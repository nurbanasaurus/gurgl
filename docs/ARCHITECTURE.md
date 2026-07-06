# Architecture

gurgl is a single Rust binary that orchestrates two external tools (a sandbox
and a capture proxy) and does the analysis itself. The design goal is that all
*judgement* (classification, the reproduction gate, diffing, allowlist shaping)
lives in pure, testable Rust, and only *mechanism* (spawning processes, reading
files) touches the OS.

## Data flow

```
                     ┌────────────── gurgl watch ──────────────┐
                     │                                          │
   gurgl.toml ──▶ ServerSpec        flightplans/default.toml ──▶ FlightPlan
                     │                                          │
                     ▼                                          ▼
             ┌─────────────┐  spawn (build_argv)      ┌──────────────────┐
             │ sandbox.rs  │─────────────────────────▶│ MCP server (child)│
             └─────────────┘  HTTPS_PROXY + lab CA     └──────────────────┘
                     │                                          │ TLS
                     ▼                                          ▼
             ┌─────────────┐  spawn (build_argv)      ┌──────────────────┐
             │  proxy.rs   │─────────────────────────▶│ mitmdump + addon │
             └─────────────┘                          └──────────────────┘
                     │  parse_flows()                          │ appends
                     ▼                                          ▼
             per-trial host sets ─────────▶ observe::aggregate  flows.jsonl
                     │  (× N trials, reproduction gate)
                     ▼
                  Snapshot ──▶ store.rs (JSON)  ──▶  diff.rs / emit.rs / share.rs
```

`share.rs` is off to the side of the capture path: `gurgl export` scrubs a stored
`Snapshot` into a shareable *shared capture* (stable hosts only, class dropped,
guardrails baked in), and `gurgl diff --against` loads someone else's - as
**untrusted input** (size-capped, control-stripped via `proxy::normalize_host`,
reproduction gate re-applied locally, URL refused, never fetched) - and feeds it
through the same `diff.rs`. It adds no network path and no new dependency.

## Why Rust + external mitmproxy

- **Single static binary** to distribute - right for a security tool people
  install and audit.
- **mitmproxy is the proven TLS-capture engine.** gurgl treats `mitmdump` as a
  subprocess and reads its output via a tiny embedded addon
  (`assets/mitm_flows.py`, `include_str!` into the binary and written to a temp
  path at runtime). No need to reimplement a MITM stack for v1.
- A pure-Rust MITM backend (`hudsucker`) that removes the mitmproxy runtime
  dependency is a roadmap item; `proxy.rs` is written so a second backend can
  slot behind the same `build_argv`/`parse_flows` shape.

## Capture mechanism (v1) and its hardening path

v1 uses **env-proxy capture**: the sandboxed child gets `HTTPS_PROXY` +
`NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE` pointing at the lab proxy and CA
(`sandbox::ProxyEnv`). Cooperating clients (Node/npm, curl, Python requests)
honor these, so their real egress is captured.

The gap: a client that *ignores* proxy env vars, or that opens raw sockets,
escapes env-proxy capture. The opt-in **forced** mode (Linux, `watch --forced` /
`capture = "forced"`) closes it: it runs the sandbox in a rootless network
namespace (`unshare` + `pasta` userspace egress) whose only route to 80/443 is a
transparent nftables `REDIRECT` to the proxy, and it drops UDP/443 so QUIC/HTTP-3
falls back to interceptable TCP. The proxy runs as the userns root and the server
as a distinct unprivileged uid, so an `nft ... meta skuid <proxy> return` rule
lets the proxy's own upstream out without looping (and the server can't read your
home). It captures IPv4; a cert-pinning client's host is still recorded (via the
TLS SNI) even though its own handshake against the lab cert fails. Env-proxy stays
the default and the only option off Linux. See `sandbox::nft_ruleset`,
`proxy::build_transparent_argv`, and `observe::forced`, and docs/THREAT-MODEL.md.

Each snapshot records a `capture_mode` (`env-proxy` or `forced`) so
`show`/`diff`/`doctor` state which mechanism was used, and a cross-mode `diff`
warns rather than reading a stronger mode's newly-seen host as drift. It is a
mechanism label, never a completeness claim.

## The reproduction gate

`observe::aggregate(trials, first_party)`:

1. Union the per-trial host sets.
2. For each host, count how many trials it appeared in.
3. `seen == N` → `Stable` (reportable). `seen < N` → `Intermittent` (treated as
   cohort/feature-gate noise; never a finding).
4. Classify each host (`model::classify`) and record the phases it was seen in.

This is what stops server-side A-B variability from producing false "drift".

## Storage

Plain JSON, one file per capture: `<store>/<server>/<version>.json`. Snapshots
are meant to be read, diffed, and committed by a human. `store.rs` orders
versions by `captured_at` so `diff` can default to the latest two.

## Capture status

`observe::run_trial` implements the full live capture: it spawns the proxy,
launches the sandboxed server wired through it, drives the MCP handshake and a
benign `tools/call` over stdio, tears everything down with drop guards (no
leaked processes), then reads flows and attributes each host to a flight-plan
phase by timestamp. Verified end-to-end against a live server contacting known
hosts. What remains is hardening (forcing *all* egress through the proxy) and
version derivation - see docs/ROADMAP.md.
