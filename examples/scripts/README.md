# gurgl example scripts

Ten runnable scripts that show off what gurgl does, from "prove the idea in 30
seconds" to "watch real egress stream in live." They are plain, portable bash
(Linux and macOS; nothing newer than macOS's stock bash 3.2 is required) and
share one small helper library, [`lib/common.sh`](lib/common.sh).

Every script:

- finds gurgl automatically - `$GURGL_BIN`, then the repo's own
  `target/{release,debug}` build, then `gurgl` on your `PATH`, then `~/.gurgl/bin`
  - so they exercise the source they ship with, and still work from a global
  install if you kept no checkout. Set `GURGL_BIN=$(command -v gurgl)` to force
  your installed binary instead of the repo build;
- sends narration to **stderr** and real output (allowlists, CSV, JSON) to
  **stdout**, so you can pipe the useful half cleanly;
- keeps gurgl's framing honest: presence, never a "clean" verdict.

## Run them

```sh
cd examples/scripts
./01-quickstart-demo.sh
```

Six of the ten run **immediately with no capture backend** because they read the
bundled example snapshots. Four need the capture stack (mitmproxy + a sandbox)
and preflight it with `gurgl doctor`, telling you exactly what to fix if a
capture here would be blocked.

| # | Script | Needs a backend? | What it shows |
|---|--------|:---:|---------------|
| 01 | `01-quickstart-demo.sh` | no | The whole loop on demo data: `demo` -> `list` -> `show` -> `diff` -> `explain` -> `allow`. |
| 02 | `02-vet-before-adopt.sh` | **yes** | Learn a server's footprint in a throwaway sandbox *before* you adopt it (`--npx <pkg>` vets a fresh package in a disposable config). |
| 03 | `03-weekly-drift-audit.sh` | **yes** | The core routine as a cron/systemd/launchd job: `watch --all --diff`, logged, with a cross-platform desktop alert on drift. `--install` prints the schedule line for your OS. |
| 04 | `04-ci-gate.sh` | no | A CI / pre-commit gate on committed snapshots (JSON only) that fails the build on new stable scrutiny hosts. |
| 05 | `05-emit-allowlists.sh` | no | Turn one capture into `sandbox-runtime`, `opensnitch`, and `squid` allowlists in one go - observe with gurgl, enforce elsewhere. |
| 06 | `06-scrutiny-report.sh` | no | A `--json` + `jq` CSV of every stable host that matched no known rule, across all servers. |
| 07 | `07-snapshot-forensics.sh` | no | "When did this host first appear?" across every captured version, with an optional `git log` timeline. |
| 08 | `08-compare-with-peer.sh` | no | `export` a scrubbed shared capture and `diff --against` a peer's - exploratory, never a pass/fail. |
| 09 | `09-scaffold-flightplan.sh` | sandbox only | Draft a per-server flight plan from the server's advertised tools (`gurgl plan`) so you exercise the tools that actually reach the network. |
| 10 | `10-live-fetch-demo.sh` | **yes** | The showpiece: watch a real fetch server's egress stream in phase by phase, redirect hops and all, in a throwaway config. |

## Environment knobs

- `GURGL_BIN=/path/to/gurgl` - use a specific binary.
- `NO_COLOR=1` - disable ANSI color.
- `GURGL_LOG_DIR=...` - where `03` writes its audit logs (default `~/.gurgl/logs`).
- `jq` is required by `02`, `04`, `06`, `07`.

## The one caveat that governs all of them

A quiet gurgl run means **no new stable hosts under this flight plan** - not
"safe," not "verified," not "clean." gurgl records host names, never payloads,
and cannot see exfiltration riding a host a tool already uses, or anything a
vendor does server-side. Read [`docs/THREAT-MODEL.md`](../../docs/THREAT-MODEL.md)
before you trust any output, and [`docs/PUBLISHING.md`](../../docs/PUBLISHING.md)
before you share a capture that names a vendor.
