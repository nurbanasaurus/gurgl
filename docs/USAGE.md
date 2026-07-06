# Using gurgl

Everything gurgl can do, with examples and expected output. New here? Install
first ([INSTALL.md](INSTALL.md)), then read this top to bottom once.

- [Mental model](#mental-model)
- [Global flags & config discovery](#global-flags--config-discovery)
- [Commands](#commands): [bare gurgl / demo](#gurgl-bare-and-gurgl-demo) · [doctor](#gurgl-doctor) · [explain](#gurgl-explain) · [init](#gurgl-init) · [discover](#gurgl-discover) · [list](#gurgl-list) · [show](#gurgl-show) · [watch](#gurgl-watch) · [diff](#gurgl-diff) · [diff --against](#gurgl-diff---against-a-shared-capture) · [allow](#gurgl-allow) · [export](#gurgl-export) · [update](#gurgl-update)
- [The config file](#the-config-file-gurgltoml)
- [Flight plans](#flight-plans)
- [Host classification](#host-classification)
- [The reproduction gate](#the-reproduction-gate)
- [Reading a snapshot](#reading-a-snapshot)

---

## Mental model

1. You list the MCP servers you run in `~/.gurgl/gurgl.toml`.
2. `gurgl watch` launches each **inside a sandbox**, wired through a local
   TLS-capture proxy, and drives it through a fixed **flight plan** (a scripted
   MCP session). It does this **N times**.
3. Every host the server contacted is recorded, classified, and marked **stable**
   (seen in every trial) or **intermittent** (not). The result is a **snapshot**
   - one JSON file per `server@version`.
4. You **diff** snapshots across versions (new hosts = the signal) and **emit**
   allowlists for an enforcement engine.

gurgl reports what it **observed**. It never certifies a tool as safe - see
[THREAT-MODEL.md](THREAT-MODEL.md).

---

## Global flags & config discovery

| Flag | Meaning |
|------|---------|
| `-c, --config <path>` | Use this config file. |
| `--store <dir>` | Override where snapshots are read/written. |
| `--plain` | Disable the live `watch` dashboard (auto-off when not a terminal). |
| `--version`, `--help` | Standard. |

**Config discovery** (when `--config` is omitted), in order:

1. `./gurgl.toml` in the current directory (project-local), else
2. `~/.gurgl/gurgl.toml` (your home install), else
3. built-in defaults (no servers configured).

---

## Commands

### `gurgl` (bare) and `gurgl demo`

Bare `gurgl` prints a git-status-style orientation: which config is in use, the
servers configured (and how many more `discover` can see on this machine), each
server's capture history and staleness, and the one next command that makes
progress from your current state.

`gurgl demo` walks an annotated example diff on data bundled into the binary -
no mitmproxy, sandbox, or Node required. It teaches the three readings that
matter: a known-vendor telemetry host, a stable unknown host (the signal), and
an intermittent host the reproduction gate deliberately keeps quiet about.

### `gurgl doctor`

A read-only readiness and fidelity report for this machine: config and PATH
state, capture backends (sandbox, mitmproxy, lab CA), whether each configured
server's launch command resolves, and - the part nothing else tells you - what a
capture HERE would include or miss, with the measured reasons (e.g. "Node 22
ignores proxy env vars, so a Node server's egress is MISSED - it can look quiet
while talking"; the macOS system-python TLS caveat). Everything is phrased as
coverage, never as a safety verdict. Ends with the one next command for your
state. Exits 1 when something would block `gurgl watch`, so setup scripts can
gate on it.

### `gurgl explain`

`gurgl explain <server> [host]` - the latest capture narrated in plain
sentences instead of a table: what gurgl actually did, each host with what it
is, when it appeared and how reproducibly, which hosts deserve attention (with
your acks woven in: "You acknowledged this host on ... : reason"), and the
honest limits attached. With a host argument it focuses on that one host. Reads
the store only - no capture backends needed.

### `gurgl init`

Creates the self-contained home: `~/.gurgl/gurgl.toml`, the default flight plan,
and the snapshot store. Idempotent - existing files are left untouched.

```console
$ gurgl init
wrote /home/you/.gurgl/gurgl.toml
wrote /home/you/.gurgl/flightplans/default.toml
store ready at /home/you/.gurgl/snapshots

next: edit /home/you/.gurgl/gurgl.toml to list the MCP servers you run, then `gurgl watch --all`.
```

### `gurgl discover`

`gurgl discover [--import]` - find the MCP servers already configured on this
machine instead of hand-listing them. It reads (never writes) the standard client
configs:

| Client | Config scanned |
|--------|----------------|
| Claude Code | `~/.claude.json` (user scope + per-project `mcpServers`) |
| Claude Desktop | macOS `~/Library/Application Support/Claude/...`, Linux `~/.config/Claude/...` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Cline (VS Code) | the `saoudrizwan.claude-dev` global storage settings |
| Codex CLI | `~/.codex/config.toml` and any project `.codex/config.toml` (TOML `[mcp_servers.*]`) |
| project / plugin | every `.mcp.json` under `$HOME` (Claude Code per-project configs, plugin-shipped servers) and `./.cursor/mcp.json` |

Not scanned: **ChatGPT**. Its MCP connectors are remote HTTPS endpoints
configured in your OpenAI account, so there is no local config file to read and no
local process to capture (the same limit as any `remote (url)` server).

```console
$ gurgl discover
found 3 MCP server(s) configured on this machine:

NAME                 STATUS     KIND   COMMAND                        SOURCE
statewright          enabled    remote https://mcp.statewright.ai     project (~/.claude/.mcp.json)
filesystem           configured stdio  npx -y @modelcontextprotocol... Claude Code (~/.claude.json)
telegram             bundled    stdio  bun run ...                    plugin (~/.claude/plugins/.../telegram/.mcp.json)
```

The `STATUS` column is read from each client's own config so you can tell what is
actually on from what merely ships on disk:

- **enabled** - positively listed as on (a project's `enabledMcpjsonServers`, or
  an `enabledPlugins` record). The only status gurgl asserts from evidence.
- **bundled** - a plugin present under a marketplace/plugin dir but not enabled.
- **configured** - present in a config, but no enable record was found for it.

`--import` appends the local `stdio` servers to `gurgl.toml` (creating it if
needed), skipping any already listed, so re-running is safe. Two limits it prints
inline rather than hiding:

- **`remote` (url) servers** are shown for inventory but not imported: gurgl
  captures local stdio subprocesses, not remote HTTP/SSE endpoints.
- **`[env]` servers** set environment variables (commonly API keys) in their
  client config. gurgl neither reads nor copies those values; such a server may
  need them present in gurgl's own environment to launch.

`gurgl discover` also runs automatically at the end of `install.sh` (listing
only), so a fresh install shows you what is watchable right away.

### `gurgl list`

Lists captured servers and their versions in the store.

```console
$ gurgl list
filesystem-mcp
  1.2.0
  1.3.0
```

### `gurgl show`

`gurgl show <server> [version]` - show the hosts observed for a version
(default: the latest captured).

```console
$ gurgl show filesystem-mcp
filesystem-mcp@1.3.0  (5 trials, flight plan default-...)
HOST                                     CLASS        REPRO        SEEN
api.github.com                           registry     stable       5/5
o1234.ingest.sentry.io                   telemetry    stable       5/5
cdn.unknown-3p.net                       unknown      stable       5/5
```

`SEEN` is trials-observed / total; `REPRO` is `stable` (every trial) or
`intermittent`.

### `gurgl watch`

`gurgl watch <server>` or `gurgl watch --all` - the capture. Launches each
server in the sandbox behind the proxy and drives the flight plan `trials` times.
**Requires** mitmproxy (`mitmdump`) and a sandbox backend; it preflights both and
stops with a clear message if one is missing.

```console
$ gurgl watch --all
capturing filesystem-mcp (5 trials)...
  trial 1/5
    observed 3 host(s)
  ...
  trial 5/5
    observed 3 host(s)
saved filesystem-mcp@1.3.0 -> /home/you/.gurgl/snapshots/filesystem-mcp/1.3.0.json
```

Each capture writes `<store>/<server>/<version>.json`. Re-running the same
version overwrites it.

The output above is the **plain** form, used when stderr is not a terminal (piped
to a file, in CI) or with `--plain`. In a terminal, `watch` instead shows a live
dashboard: a trial progress bar, per-phase timers, and hosts streaming in colored
by class. It draws on the alternate screen and restores your terminal on exit, so
scrollback is untouched; the final snapshot summary is left in place afterward.

**Interactive drill-down.** The dashboard takes single keypresses (when stdin is
a terminal): `up`/`down` or `j`/`k` move the host selection, `enter` opens the
selected host (or press `1`-`9` to jump straight to a row), `esc` backs out, and
`q` stops cleanly and saves. The detail view shows the host's class with a
one-line explanation, every phase it appeared in, which trials have seen it so
far, and when it first appeared; inside it, `up`/`down` step through the other
hosts. A footer menu lists the keys at all times.

**Stopping.** `q` and Ctrl-C both request a clean stop in every mode: the current
partial battery trial is discarded (the reproduction gate only compares complete
runs of the plan), completed trials are aggregated and saved with the completed
count, and the terminal is restored. In `--for`/`--until-closed` mode the single
observation is saved as-is. A second Ctrl-C force-quits immediately.

**Watching over time.** By default `watch` runs the `trials` battery and exits.
Two flags turn it into a live monitor instead - one long observation (the flight
plan once, then a monitoring hold), so you can watch what a server beacons at rest:

| Flag | Behaviour |
|------|-----------|
| `--for <dur>` | Monitor for a fixed time, then stop and save. `<dur>` is `30s`, `5m`, `1h`, or a bare number of seconds. |
| `--until-closed` | Monitor until you press Ctrl-C (or the server exits), then stop and save. |

```console
$ gurgl watch statewright --for 5m
$ gurgl watch statewright --until-closed      # Ctrl-C to stop
```

These force a single observation, so every host is recorded as seen `1/1`; the
reproduction gate needs the multi-trial battery, so use the default `watch` when
you intend to diff. `--until-closed` catches Ctrl-C to stop cleanly, save what it
saw, and restore the terminal (on Unix). `--for` and `--until-closed` are mutually
exclusive.

### `gurgl diff`

`gurgl diff <server>` - compare two versions (default: the two most recent). Use
`--from <v> --to <v>` to pick. **New stable hosts are the signal.**

```console
$ gurgl diff filesystem-mcp
filesystem-mcp: 1.2.0 -> 1.3.0
  unchanged hosts: 2
  new hosts:
    + o1234.ingest.sentry.io                   [telemetry]
    + cdn.unknown-3p.net                        [unknown]

  ⚠ 1 new stable UNKNOWN host(s) - worth a look:
    cdn.unknown-3p.net

note: presence only. Absence of a host is non-coverage under this flight plan,
not proof the tool won't contact it.
```

Intermittent new hosts are shown but flagged as likely cohort noise, never as a
finding.

### `gurgl diff --against` (a shared capture)

`gurgl diff <server> --against <path>` compares your latest **local** capture to
someone else's **shared capture** - a file written by `gurgl export`, a raw
snapshot, or another gurgl store directory. Use it to sanity-check your footprint
against a peer's: "am I seeing hosts nobody else did, or missing ones they saw?"

```console
$ gurgl diff fetch --against ./fetch.shared.json
comparing your capture of fetch@0.13.37 against a shared capture
  source: ./fetch.shared.json [shared capture: fetch @ 0.13.37]
  [the shared capture is one observer's presence-only sample under their own flight plan -
   NOT a vetted or known-good reference. Having more or fewer hosts than it is expected.]

  hosts YOU observed that the shared capture did not:
    + beacon.unknown-3p.net                    [unknown]

  ⚠ 1 stable host(s) here matched no known rule - worth a look. This is NOT proof
    of wrongdoing: a different version, a server-side cohort, a different flight
    plan, or your own tool-call arguments can all add hosts the shared capture lacks:
    beacon.unknown-3p.net  [unknown]

  hosts also present in the shared capture: 4 (overlap is not verification)
```

It is **exploratory, never a verdict**, and this is deliberate:

- **Exit codes are `0` (compared) or `2` (error), never `1`.** `--check` is
  refused with `--against`: a stranger's capture must never be a pass/fail gate
  (that would be the "verified/clean" badge gurgl refuses to be). Wire drift gates
  to `diff --check` / `watch --diff` against **your own** versions, not this.
- **A match is not a pass.** If you observed nothing beyond the shared capture,
  gurgl says so *and* restates that this is not a clean bill of health - a tool
  exfiltrating over a host it already contacts produces an identical set
  ([THREAT-MODEL.md](THREAT-MODEL.md)).
- **The direction is symmetric, not authoritative.** "Hosts the shared capture
  saw that you didn't" is a version / cohort / coverage / flight-plan difference,
  not "you're missing something." A **flight-plan fingerprint mismatch** is called
  out loudly, because different methods exercise different egress.

`--against` takes a **local path only** and **never fetches over the network** - a
URL is refused, not downloaded (constraint #5). A shared file is treated as
**untrusted input**: it is size-capped, every string is control-stripped (so a
hostile file can't corrupt your terminal), host classes are recomputed locally
against *your* `first_party`, and the reproduction gate is re-applied locally (a
shared file is never trusted to have been gated by its author). `--json` emits the
versioned `gurgl.diff-against/1` schema with the caveat in its `note` field.

### `gurgl allow`

`gurgl allow <server> [version] --format <fmt>` - emit an allowlist from a
snapshot, to stdout. Formats: `sandbox-runtime` (default), `opensnitch`, `squid`.

```console
$ gurgl allow filesystem-mcp --format squid
# gurgl allowlist for filesystem-mcp@1.3.0
acl gurgl_filesystem_mcp dstdomain api.github.com o1234.ingest.sentry.io cdn.unknown-3p.net
http_access allow gurgl_filesystem_mcp

$ gurgl allow filesystem-mcp --format sandbox-runtime > allow.txt
```

An allowlist reflects only what was **observed** under the flight plan - it is a
starting point to review, not a complete contract.

### `gurgl export`

`gurgl export <server> [version] [-o FILE] [--as-name NAME] [--force]` - write a
scrubbed, shareable **shared capture** of a server's observed egress, for others
to `diff --against`. JSON goes to stdout (so `gurgl export foo > foo.shared.json`
works), or to a file with `-o`; the host list and review warnings go to stderr.

```console
$ gurgl export fetch -o fetch.shared.json
shared capture of fetch @ 0.13.37 - 5 stable host(s):
    api.github.com
    example.com
    ...
review before you share (this file names a third party):
  - server label written: 'fetch' (your local label) - it may identify you; rename with --as-name.
  - a host reached via a tool-call ARGUMENT may be YOURS, not the tool's.
  - a host that reveals internal infrastructure should be removed by hand.
  - publishing named observations takes on real legal/ethical exposure ... (docs/PUBLISHING.md)
wrote fetch.shared.json
```

What the scrub does, and why:

- **Stable hosts only.** Intermittent and single-observation hosts are dropped -
  the reproduction gate is mandatory for anything you share (a single sighting is
  server-side noise, not a fact about the tool).
- **No host class.** The file carries host names, trial counts, phases, and the
  flight-plan fingerprint - **raw receipts** - but not gurgl's `first-party /
  telemetry / unknown` inference. What a host *is* is the reader's conclusion to
  draw, not the publisher's to assert (see [PUBLISHING.md](PUBLISHING.md); the
  consumer recomputes class locally against their own `first_party`).
- **Date, not timestamp.** The capture time is coarsened to `YYYY-MM-DD`.
- **Guardrails baked in.** The publishing rules are written into the file itself,
  so they travel with it to whoever receives or reposts it.

`-o` **refuses to overwrite** an existing file unless you pass `--force` (and
writes atomically, so a crash never leaves a half-written bundle). `--as-name`
renames the server in the output - use it if your local label identifies you.

Exporting a file is not itself publishing; **sharing or posting it is**, and that
is what [PUBLISHING.md](PUBLISHING.md) governs (entity + insurance, coordinated
disclosure, never punch down). A shared capture is a floor of hosts one observer
reproduced - never a ceiling, never an allowlist, never a "this tool is safe".

### `gurgl ack`

`gurgl ack <server> <host> [--note "..."]` - record that you reviewed a host, so
`diff` reports it in a quiet one-liner instead of re-alerting on every run. The
ack stores your note, the date, and the version you reviewed at, in a
human-editable sidecar (`<store>/<server>/acks.toml`) you can commit to git.

```console
$ gurgl ack example-mcp beacon.cdn.example --note "static assets for the pdf tool"
$ gurgl ack example-mcp --list
$ gurgl ack example-mcp beacon.cdn.example --remove
```

An ack means "a human looked at this and recorded why" - it is **not** an
endorsement, and gurgl still cannot see what is *sent* to an acknowledged host.
`diff --check` and `watch --diff` honor acks: acknowledged hosts do not trip the
drift gate.

### `gurgl accept`

`gurgl accept <server> [version]` - mark a reviewed capture as this server's
**baseline** (default: the latest). `gurgl diff <server> --baseline` and
`watch --diff` then compare against what you actually reviewed instead of just
the latest two versions - so drift accumulates against your last review, not
against yesterday's unreviewed capture. `--clear` removes the pointer; `list`
marks the baseline version.

### Automation: `--check`, `watch --diff`, `--json`, and exit codes

**Exit codes** (grep convention): `0` = success / no drift at the requested
threshold, `1` = drift detected, `2` = error.

**`gurgl diff <server> --check[=unknown|any]`** exits 1 when new stable hosts
were observed: `unknown` (the default) triggers only on hosts needing scrutiny
(`unknown` / `telemetry?`), `any` on every new stable host. Acks are honored.
Intermittent hosts never trip the gate - the reproduction gate applies to
automation too.

**`gurgl watch --all --diff`** is the one-shot audit: capture every server, diff
each against its accepted baseline (else its previous version), print a
per-server drift summary, and exit 1 if anything needs scrutiny. Made for cron -
see [RECIPES.md](RECIPES.md).

**`--json`** switches `list`, `show`, `diff`, and `discover` to stable,
versioned JSON on stdout (`gurgl.diff/1` etc.). The epistemic caveat travels in
a `note` field; `diff` JSON carries `needs_scrutiny` (acks already subtracted)
and `acknowledged_present` separately so scripts do not re-alert on reviewed
hosts. `diff --against` emits `gurgl.diff-against/1` (carrying
`you_saw_shared_did_not` / `shared_saw_you_did_not` and no verdict field, since
it never gates). `gurgl export` always writes JSON, so `--json` does not apply to
it.

Every snapshot also records its **capture mode** - how egress was forced through
the proxy. Today that is always `env-proxy` (only clients that honor proxy env
vars are captured; a client that opens raw sockets or pins certs escapes it); a
future `forced` mode will route *all* TCP egress through the proxy. It is a
statement about the capture *mechanism*, never a safety or completeness claim.
`show` prints it in the header, `gurgl.show/1` carries it inside `snapshot`, and
`gurgl.diff/1` adds `from_capture_mode` / `to_capture_mode` /
`capture_mode_mismatch` (additive fields - the schema tag stays `/1`). A
`capture_mode_mismatch` means the two captures used different mechanisms, so a
"new" host may just be one the weaker mode missed rather than new egress; `diff`
flags it in text like a flight-plan mismatch. `gurgl doctor` reports which mode is
achievable on the machine and why.

```sh
gurgl --json diff my-server | jq -r '.needs_scrutiny[]'
```

### `gurgl update`

`gurgl update` (or `gurgl -u` / `gurgl --update`) - update gurgl from the public
repo and reinstall. It runs **only when you invoke it**; gurgl never checks for,
pings about, or downloads updates on its own (constraint #5). The only network
access is the git fetch you just asked for.

```console
$ gurgl update
>> updating gurgl source in /home/you/.gurgl/src ...
>> building + installing the update ...
gurgl is up to date. Check `gurgl --version`.
```

It maintains a managed checkout at `~/.gurgl/src` and reinstalls from it, so it
works the same on any machine - including one set up with `make deploy`, which has
no git checkout of its own to pull. Requires `git` and a compiler toolchain (the
installer bootstraps Rust if it is missing). If you work from a source clone,
`make update` does the same thing from that clone.

---

## The config file (`gurgl.toml`)

```toml
# Where captures are stored. Relative paths resolve against THIS file's
# directory. Default: ~/.gurgl/snapshots.
# store = "snapshots"

# Sandbox backend. Default is OS-aware: "bubblewrap" on Linux, "sandbox-exec"
# (Seatbelt) on macOS. Set "podman" to use Podman instead.
# sandbox = "bubblewrap"

# The capture proxy binary. A bare name is looked up on PATH; an absolute path
# is used as-is.
mitmdump = "mitmdump"

# The flight plan gurgl drives against each server (relative to this file).
flightplan = "flightplans/default.toml"

# Trials per capture. More trials = a stronger reproduction gate (less
# server-side cohort/feature-gate noise leaking through as "drift").
trials = 5

# --- the servers you watch ------------------------------------------------
[[servers]]
name = "filesystem-mcp"                    # logical name (used for storage + CLI)
command = "npx"                            # launched INSIDE the sandbox
args = ["-y", "@modelcontextprotocol/server-filesystem", "/tmp/scratch"]
version = "1.3.0"                          # optional; else labeled "unknown"
first_party = ["vendor.com"]               # domains you EXPECT - classified first-party
```

| Field | Required | Notes |
|-------|----------|-------|
| `name` | yes | Storage + CLI identity. |
| `command` | yes | Executable run inside the sandbox (`npx`, `python3`, `node`, ...). |
| `args` | no | Arguments to `command`. |
| `version` | no | Explicit label; absent → the server's self-reported version from its MCP `initialize` response, else `unknown`. Distinct versions are distinct snapshots, which is what makes `diff` work. |
| `first_party` | no | Expected domains, so gurgl can class them as first-party. |
| `flightplan` | no | Per-server flight plan path, overriding the config-level default. Use for a server whose battery needs its own tool + args. |

### Backends

| `sandbox` | Requires | Platform |
|-----------|----------|----------|
| `bubblewrap` (Linux default) | `bwrap` | Linux |
| `sandbox-exec` (macOS default) | `sandbox-exec` | macOS |
| `podman` | `podman` | Linux (macOS via VM) |

> The sandbox today provides isolation and the env-proxy wiring for capture; it
> is **not yet a hardened security boundary** ([THREAT-MODEL.md](THREAT-MODEL.md),
> [ROADMAP.md](ROADMAP.md)).

---

## Flight plans

A flight plan is the fixed, ordered MCP session gurgl runs so egress is exercised
the same way every time. It is fingerprinted into each snapshot - change the plan
and past snapshots are no longer directly comparable.

```toml
name = "default"

[[steps]]
phase = "startup"        # a label; hosts contacted here are attributed to it
action = "initialize"    # MCP initialize handshake

[[steps]]
phase = "enumerate"
action = "tools/list"

[[steps]]
phase = "tool-call"
action = "tools/call"    # gurgl auto-picks the first benign, read-only-looking tool
                         # (never a delete/write/send/exec-shaped one) and calls it
                         # with no arguments. Pin one with `tool = "..."`, and pass
                         # real input with `args = { ... }` (see below).

[[steps]]
phase = "idle"
action = "sleep"
seconds = 8              # catch background beacons / deferred telemetry
```

Supported `action`s: `initialize`, `tools/list`, `tools/call`, `sleep`.
`gurgl init` writes this default to `~/.gurgl/flightplans/default.toml`.

**Exercising a tool with real input.** Many tools only reach the network when
given arguments (a `fetch` tool needs a URL, a `search` tool needs a query), so a
call with empty `{}` shows only the server's startup egress. Name the tool and
pass `args` (a TOML table sent as the tool's JSON arguments):

```toml
[[steps]]
phase = "tool-call"
action = "tools/call"
tool = "fetch"
args = { url = "https://example.com" }
```

Keep the tool read-only. `args` is part of the flight-plan fingerprint, so
changing it makes past snapshots no longer directly comparable (by design: a
different call is a different method). Note this only surfaces more hosts if the
tool actually makes network calls - a purely local tool (e.g. filesystem reads)
has no egress to reveal regardless of its arguments.

Because a tool-specific plan only fits one server, set it per server rather than
globally: give that `[[servers]]` entry its own `flightplan = "flightplans/..."`
and every other server keeps the default battery. `gurgl watch --all` uses each
server's own plan.

---

## Host classification

Every observed host is put in one class, used to make diffs readable:

| Class | Meaning |
|-------|---------|
| **first-party** | Matches a `first_party` domain you declared for the server. |
| **telemetry** | Matches a known analytics/crash-reporting vendor domain. |
| **telemetry?** | Merely NAMES itself telemetry/analytics (`telemetry.*` / `analytics.*`) but matches no known vendor. Anyone can pick a hostname, so this is **not** vetted - scrutinize it like `unknown`. |
| **registry** | Package registries / code hosts (npm, PyPI, GitHub, ...). |
| **unknown** | Everything else - **the class to scrutinize**, especially when new. |

A **new stable `unknown`** (or `telemetry?`) host after an update is the loudest
thing gurgl can tell you, and `diff` flags exactly those.

---

## The reproduction gate

MCP servers legitimately vary run to run (A/B cohorts, feature gates, CDN
rotation). To avoid crying "drift" at noise, gurgl runs `trials` captures and:

- a host in **every** trial → **stable** (reportable),
- a host in **some** trials → **intermittent** (shown, but never a finding).

Raise `trials` for noisier servers. This gate is load-bearing - see
[ARCHITECTURE.md](ARCHITECTURE.md#the-reproduction-gate).

---

## Reading a snapshot

Snapshots are plain JSON you own - read, diff, and commit them:

```jsonc
// ~/.gurgl/snapshots/filesystem-mcp/1.3.0.json
{
  "server": "filesystem-mcp",
  "version": "1.3.0",
  "captured_at": 1751500000,
  "trials": 5,
  "flightplan": "default-a1b2c3...",   // fingerprint tying this to its method
  "gurgl_version": "0.1.0",
  "hosts": [
    { "name": "cdn.unknown-3p.net", "class": "unknown",
      "reproducibility": "stable", "seen_in_trials": 5,
      "phases": ["tool-call"] }
  ]
}
```
