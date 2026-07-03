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
- `observe.rs` - `aggregate()` (pure reproduction gate) + `capture()`/`run_trial()`
  live pipeline (spawn proxy, launch sandboxed server, drive MCP over stdio,
  attribute hosts to phases by timestamp). Implemented and verified. `Monitor`
  controls run length: `Battery` (default, N trials) or `Hold(Option<Duration>)`
  for `watch --for`/`--until-closed` (one long observation; Ctrl-C via a SIGINT
  handler in the `interrupt` submodule, unix-only, using `libc`).
- `diff.rs` - pure `diff(from, to) -> SnapshotDiff`.
- `emit.rs` - `allowlist(snapshot, Format)` for sandbox-runtime / opensnitch / squid.
- `store.rs` - JSON snapshots at `<store>/<server>/<version>.json`.
- `sandbox.rs` / `proxy.rs` - `build_argv()` (pure, tested) + spawn helpers.
- `flightplan.rs` - parse/fingerprint the scripted battery.
- `discover.rs` - scan known MCP client configs (Claude Desktop/Code, Cursor,
  Windsurf, Cline) *and* every `.mcp.json` under `$HOME` for configured servers;
  `--import` appends stdio ones to `gurgl.toml`. Marks each `enabled`/`bundled`/
  `configured` from the client's own enable records (`EnabledIndex`). Read-only on
  client configs; never reads `env` values.
- `mcp.rs` - minimal MCP JSON-RPC message builders.
- `report.rs` - `Reporter` trait + `PlainReporter` (piped/`--plain`) and
  `DashboardReporter` (live ANSI dashboard, no deps, TTY-gated). `watch` only.

## Conventions

- Keep pure logic (model/diff/emit/observe::aggregate) free of I/O so it stays
  unit-testable; put process/FS/network in the edge modules.
- Errors: `anyhow` in `main`/commands, plain `Result` with `.context(...)` in
  library code. User-facing errors should say what to do next.
- Match the existing comment density: comments state *constraints and why*, not
  what the next line does.
- Any new dependency is a supply-chain decision - this is a security tool.
  Prefer std; justify additions; keep `cargo deny` / `cargo audit` green. Direct
  deps: clap, serde, serde_json, toml, anyhow, dirs, and (unix) `libc` for the
  `watch` SIGINT handler - `libc` was already transitive via `dirs`, so it added
  no new crate. No signal-handling wrapper crates; the handler is ~5 lines.

## Next tasks (v1 polish)

The live capture (`observe::run_trial`) works. Remaining:
- **Version derivation** - resolve the actually-installed version of an npm/PyPI
  MCP server instead of the `unknown` label / config value.
- **Capture hardening** - force all egress through the proxy (network namespace
  + transparent redirect on Linux; a real least-privilege Seatbelt profile on
  macOS) instead of relying on the client honoring `HTTPS_PROXY`. The sandbox is
  functional but explicitly not a boundary yet (docs/THREAT-MODEL.md).
- **Capture fidelity notes** - per-target flags for known proxy-fingerprinting.
