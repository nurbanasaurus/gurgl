# Using gurgl

Everything gurgl can do, with examples and expected output. New here? Install
first ([INSTALL.md](INSTALL.md)), then read this top to bottom once.

- [Mental model](#mental-model)
- [Global flags & config discovery](#global-flags--config-discovery)
- [Commands](#commands): [init](#gurgl-init) · [list](#gurgl-list) · [show](#gurgl-show) · [watch](#gurgl-watch) · [diff](#gurgl-diff) · [allow](#gurgl-allow)
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
| Claude Desktop | macOS `~/Library/Application Support/Claude/…`, Linux `~/.config/Claude/…` |
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
telemetry.vendor.com                     telemetry    stable       5/5
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
    + telemetry.vendor.com                     [telemetry]
    + cdn.unknown-3p.net                        [unknown]

  ⚠ 1 new stable UNKNOWN host(s) - worth a look:
    cdn.unknown-3p.net

note: presence only. Absence of a host is non-coverage under this flight plan,
not proof the tool won't contact it.
```

Intermittent new hosts are shown but flagged as likely cohort noise, never as a
finding.

### `gurgl allow`

`gurgl allow <server> [version] --format <fmt>` - emit an allowlist from a
snapshot, to stdout. Formats: `sandbox-runtime` (default), `opensnitch`, `squid`.

```console
$ gurgl allow filesystem-mcp --format squid
# gurgl allowlist for filesystem-mcp@1.3.0
acl gurgl_filesystem_mcp dstdomain api.github.com telemetry.vendor.com cdn.unknown-3p.net
http_access allow gurgl_filesystem_mcp

$ gurgl allow filesystem-mcp --format sandbox-runtime > allow.txt
```

An allowlist reflects only what was **observed** under the flight plan - it is a
starting point to review, not a complete contract.

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
| `version` | no | Explicit label; absent → `unknown`. |
| `first_party` | no | Expected domains, so gurgl can class them as first-party. |

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
                         # (never a delete/write/send/exec-shaped one). Pin one with `tool = "..."`.

[[steps]]
phase = "idle"
action = "sleep"
seconds = 8              # catch background beacons / deferred telemetry
```

Supported `action`s: `initialize`, `tools/list`, `tools/call`, `sleep`.
`gurgl init` writes this default to `~/.gurgl/flightplans/default.toml`.

---

## Host classification

Every observed host is put in one class, used to make diffs readable:

| Class | Meaning |
|-------|---------|
| **first-party** | Matches a `first_party` domain you declared for the server. |
| **telemetry** | Known analytics/telemetry endpoints. |
| **registry** | Package registries / code hosts (npm, PyPI, GitHub, ...). |
| **unknown** | Everything else - **the class to scrutinize**, especially when new. |

A **new stable `unknown`** host after an update is the loudest thing gurgl can
tell you.

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
