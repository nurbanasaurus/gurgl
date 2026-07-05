# CLAUDE.md - working agreement for gurgl

This file orients any Claude Code session working in this repo. Read it before
making changes.

## What gurgl is

A local-first CLI that captures the network egress of MCP servers, diffs it
across versions, and emits allowlists. Single Rust binary; shells out to
`mitmdump` and a sandbox backend (`bubblewrap`/`podman`). No backend, no
network calls of its own, no telemetry.

## Non-negotiable framing (do not "improve" these away)

These constraints are the product. They came out of a long validation process
that killed the more ambitious versions of this idea. Violating them doesn't
make gurgl better - it makes it dishonest and legally exposed.

1. **Inventory, not verification.** gurgl reports hosts it *observed under a
   flight plan*. It must never emit or imply "safe", "clean", "verified", or a
   pass/fail badge. Do not add a command, flag, or output string that certifies
   a tool. The word "clean" does not appear in user-facing output by design.
2. **Presence only, never absence.** "We saw these hosts" can never become "it
   only contacts these hosts." Every diff/allow output already carries the
   coverage caveat; keep it.
3. **The reproduction gate is load-bearing.** A host seen in some-but-not-all
   trials is `Intermittent` and must never be reported as a finding or a drift
   accusation - it's almost always server-side cohort/feature-gate noise.
   Don't add code paths that surface intermittent hosts as facts.
4. **Hosts, not payloads.** gurgl records DNS host names only. Do not add
   body/content capture. That's a different, far more fraught tool.
5. **Local-first, no telemetry.** gurgl must never phone home. No analytics, no
   "anonymous usage stats", no auto-update pings. `gurgl update` is allowed
   because it is *explicit and user-invoked* (a manual `git pull` + reinstall) -
   it must never become an automatic check, a startup ping, or a background
   fetch. The only network access on update is the git fetch the user triggered.
6. **The trusted-channel limit is acknowledged, not hidden.** gurgl cannot see
   exfiltration riding a legitimately-used host, and cannot see anything
   server-side. THREAT-MODEL.md states this plainly; keep it accurate.
7. **Publishing has separate rules.** Any feature that *publishes* observations
   naming a third party must comply with docs/PUBLISHING.md (entity + insurance,
   raw receipts, reproduction gate, coordinated disclosure, no shaming solo
   maintainers). Do not add a "publish" or "share" feature without reading it.

## Build / test / run

```sh
cargo build
cargo test                     # unit tests (model, diff, emit, sandbox, proxy, observe)
cargo clippy --all-targets     # keep it warning-clean
cargo fmt

# Works today against bundled examples (no capture backend required):
cargo run -- --config examples/gurgl.toml diff example-mcp
```

## Install layout (`~/.gurgl`)

gurgl installs into one self-contained home, `~/.gurgl` (override with
`$GURGL_HOME`): `bin/gurgl`, `gurgl.toml`, `flightplans/`, `snapshots/`,
`mitmproxy/` (the lab CA), and `env` (a sourceable PATH shim). `install.sh` does
`cargo install --root ~/.gurgl`; `gurgl init` lays down the config + the embedded
default flight plan + the store. Config discovery: `--config`, else
`./gurgl.toml`, else `~/.gurgl/gurgl.toml`, else defaults. Updating is
explicit and user-invoked only (constraint #5): `gurgl update` / `gurgl -u`
maintains a managed checkout at `~/.gurgl/src` and reinstalls from it (works even
on a `make deploy`ed box with no local `.git`); `make update` does the same from
a source clone. There is **no auto-update** - gurgl never checks or fetches on
its own.
Path helpers live in `config.rs` (`gurgl_home()`, `default_config_path()`,
`DEFAULT_FLIGHTPLAN`); don't hardcode paths elsewhere.

## Architecture map

- `model.rs` - `Host`, `Snapshot`, `HostClass`, `Reproducibility`, `classify()`.
  `HostClass::TelemetryNamed` ("telemetry?") = self-named telemetry with no
  vendor match; `needs_scrutiny()` groups it with `Unknown` everywhere findings
  are filtered - a hostname is attacker-chosen, so it must never look vetted.
- `observe.rs` - `aggregate()` (pure reproduction gate) + `capture()`/`run_trial()`
  live pipeline (spawn proxy, launch sandboxed server, drive MCP over stdio,
  attribute hosts to phases by timestamp). Implemented and verified. `Monitor`
  controls run length: `Battery` (default, N trials) or `Hold(Option<Duration>)`
  for `watch --for`/`--until-closed` (one long observation). Graceful stop: the
  `interrupt` submodule's SIGINT handler (armed for every watch; double Ctrl-C
  force-quits) plus `request_stop()`/`stop_requested()` checked at step
  boundaries, sleep/monitor ticks, and in 250ms `read_response` slices. A
  battery trial cut short is discarded (the gate compares complete runs);
  `Snapshot.trials` is the completed count. A server that EXITS mid-plan in
  battery mode is an error carrying its stderr tail, never an empty snapshot -
  "no egress observed" from a dead process would be a false observation.
  `config::SCRATCH_DIR` is guaranteed at capture time (host-side + bwrap
  `--dir`) so the starter config works out of the box.
- `diff.rs` - pure `diff(from, to) -> SnapshotDiff`.
- `emit.rs` - `allowlist(snapshot, Format)` for sandbox-runtime / opensnitch / squid.
- `store.rs` - JSON snapshots at `<store>/<server>/<version>.json`, plus two
  human-review sidecars per server: `acks.toml` (`gurgl ack` - reviewed hosts,
  worded "acknowledged" never "approved") and `baseline` (`gurgl accept` - the
  version a human reviewed; `diff --baseline`/`watch --diff` compare against it).
- `sandbox.rs` / `proxy.rs` - `build_argv()` (pure, tested) + spawn helpers.
- `flightplan.rs` - parse/fingerprint the scripted battery; `Step::args` (TOML
  table) lets a `tools/call` step pass real arguments, folded into the fingerprint.
- `discover.rs` - scan known MCP client configs (Claude Desktop/Code, Cursor,
  Windsurf, Cline) *and* every `.mcp.json` under `$HOME` for configured servers;
  `--import` appends stdio ones to `gurgl.toml`. Marks each `enabled`/`bundled`/
  `configured` from the client's own enable records (`EnabledIndex`). Read-only on
  client configs; never reads `env` values.
- `mcp.rs` - minimal MCP JSON-RPC message builders.
- `report.rs` - `Reporter` trait + `PlainReporter` (piped/`--plain`) and
  `DashboardReporter` (live ANSI dashboard, no deps, TTY-gated). Interactive:
  raw termios stdin (unix, `rawin` module) + an input thread; j/k/arrows select
  a host, enter/1-9 open a rich detail view, esc backs out, q requests the same
  clean stop as Ctrl-C (`observe::request_stop`). `watch` only.

## Conventions

- Keep pure logic (model/diff/emit/observe::aggregate) free of I/O so it stays
  unit-testable; put process/FS/network in the edge modules.
- Errors: `anyhow` in `main`/commands, plain `Result` with `.context(...)` in
  library code. User-facing errors should say what to do next.
- Exit codes are a documented contract: 0 = ok/no drift, 1 = drift
  (`diff --check`, `watch --diff`) or blocked (`doctor`), 2 = error. `run()` returns the code; don't
  add new nonzero meanings casually. `--json` outputs carry a versioned
  `schema` field (`gurgl.diff/1` ...) - breaking a schema needs a version bump.
  The drift gate (`drift_hosts` in main.rs) honors acks and never counts
  intermittent hosts (the reproduction gate applies to automation too).
- Match the existing comment density: comments state *constraints and why*, not
  what the next line does.
- Any new dependency is a supply-chain decision - this is a security tool.
  Prefer std; justify additions; keep `cargo deny` / `cargo audit` green. Direct
  deps: clap, serde, serde_json, toml, anyhow, dirs, and (unix) `libc` for the
  `watch` SIGINT handler - `libc` was already transitive via `dirs`, so it added
  no new crate. No signal-handling wrapper crates; the handler is ~5 lines.

## Next tasks (v1 polish)

The live capture (`observe::run_trial`) works. Remaining:
- **Version derivation** - DONE for servers that report it: `capture()` uses the
  MCP `initialize` response's `serverInfo.version` (precedence: config `version` >
  server-reported > `unknown`). A server that reports no version still falls back
  to `unknown`; deriving it from the installed npm/PyPI package is a further step.
- **Capture hardening** - force all egress through the proxy (network namespace
  + transparent redirect on Linux; a real least-privilege Seatbelt profile on
  macOS) instead of relying on the client honoring `HTTPS_PROXY`. The sandbox is
  functional but explicitly not a boundary yet (docs/THREAT-MODEL.md).
- **Capture fidelity notes** - per-target flags for known proxy-fingerprinting.
