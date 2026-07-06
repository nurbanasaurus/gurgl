# gurgl

**Local-first egress hygiene for the MCP servers you run.**

[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![build](https://img.shields.io/badge/build-cargo-orange.svg)](#install)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey.svg)](docs/INSTALL.md)

gurgl captures what an MCP server contacts on the network, diffs that across
versions, and emits least-privilege allowlists you can enforce with tools you
already run. It exists to answer one question you can't easily answer today:

> **When I install or update an MCP server, does it start talking to somewhere new?**

It runs entirely on your machine. No backend, no account, no telemetry - gurgl
makes **no network calls of its own**, and nothing it observes ever leaves your box.

---

## Contents

- [What gurgl is - and isn't](#what-gurgl-is--and-is-deliberately-not)
- [How it works](#how-it-works-30-seconds)
- [Install](#install) · [full per-OS guide →](docs/INSTALL.md)
- [Try it now (no backend)](#try-it-now-no-capture-backend-needed)
- [A real capture](#a-real-capture)
- [Where things live: `~/.gurgl`](#where-things-live-gurgl)
- [Updating](#updating)
- [Command reference](#command-reference) · [full usage guide →](docs/USAGE.md)
- [Using gurgl effectively](#using-gurgl-effectively)
- [What gurgl cannot do](#what-gurgl-cannot-do-read-this)

## What gurgl is - and is deliberately not

gurgl is an **egress inventory + drift** tool. It tells you, reproducibly:

- the set of hosts a `server@version` was observed contacting under a fixed
  *flight plan*, each classified (**first-party / telemetry / registry / unknown**);
- what **changed** between two versions - **new hosts are the signal**;
- an **allowlist** for [Anthropic sandbox-runtime], [OpenSnitch], or a squid proxy.

gurgl is **not** a verifier, scanner, or safety certifier. It never tells you a
tool is "safe," "clean," or "verified" - it can't, and pretending otherwise
would be dishonest. Specifically it **cannot**:

- see *what* is sent - it records host names, never payloads;
- catch exfiltration riding a host the tool already legitimately uses (a
  malicious server that BCCs your data out *through the real vendor API* - the
  [postmark-mcp] pattern - looks identical to normal use);
- see anything a vendor does **server-side** (retention, training, resale);
- prove a tool *won't* contact a host it simply didn't reach under the flight plan.

Those limits are the whole reason gurgl is scoped the way it is. Read
**[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** before you trust any output.

**Why it's still worth running:** most real-world MCP nastiness isn't subtle
in-band exfiltration - it's a package that, after an update, simply starts
beaconing to a **new** host it never used before. That is exactly what a
version-over-version egress diff surfaces, and nobody is doing it for the long
tail of npm/PyPI-published MCP servers you actually install.

## How it works (30 seconds)

```
  gurgl.toml ─▶ server spec        flight plan ─▶ scripted MCP battery
       │                                │
       ▼                                ▼
  launch the server INSIDE a sandbox, wired through a local TLS-capture proxy
  (mitmdump) with a lab CA, then drive it: initialize → tools/list → a benign
  tool call → idle.
       │
       ▼
  record every host it contacted, attributed to the phase it happened in,
  repeated N times. A host counts as STABLE only if seen in every trial
  (the reproduction gate rejects server-side cohort/feature-gate noise).
       │
       ▼
  a JSON snapshot you own  ─▶  diff two versions  ─▶  emit an allowlist
```

Full design: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Install

gurgl installs into a single self-contained directory, **`~/.gurgl`** (binary,
config, flight plans, snapshots, and lab CA all under one place you can inspect
or `rm -rf`).

**One-liner (Linux or macOS):**

```sh
git clone https://github.com/nurbanasaurus/gurgl
cd gurgl && ./install.sh
. ~/.gurgl/env        # add ~/.gurgl/bin to PATH (add this line to your shell profile)
```

`install.sh` does everything: installs Rust if it's missing, builds gurgl, and
**installs the two runtime deps** that only `gurgl watch` needs (a sandbox
backend and mitmproxy). It picks the right method per OS:

| OS | sandbox backend | capture proxy |
|----|-----------------|---------------|
| **macOS** | `sandbox-exec` (built in) | Homebrew, else a self-contained venv |
| **Debian/Ubuntu** | `bubblewrap` (apt) | pipx, else a self-contained venv |
| **Fedora** | `bubblewrap` (dnf) | pipx, else a self-contained venv |
| **Arch** | `bubblewrap` (pacman) | pipx, else a self-contained venv |

Sandbox packages use your package manager (needs `sudo`); mitmproxy prefers a
user-space install (Homebrew/pipx) and otherwise drops into a dedicated venv
under `~/.gurgl` with `mitmdump` symlinked onto your PATH. Skip the dep step with
`./install.sh --no-deps`. `list` / `show` / `diff` / `allow` need neither dep,
only `watch` does.

Copy-paste blocks for each OS, PATH setup, and uninstall are in
**[docs/INSTALL.md](docs/INSTALL.md)**.

## Try it now (no capture backend needed)

The pure logic works immediately against bundled example snapshots:

```sh
gurgl --config examples/gurgl.toml list
gurgl --config examples/gurgl.toml diff example-mcp
gurgl --config examples/gurgl.toml allow example-mcp --format squid
```

Or run the guided tour that stitches those together, plus nine more worked
examples (vet-before-adopt, a cron drift audit, a CI gate, allowlist emission,
a live capture) in **[examples/scripts/](examples/scripts/)** - portable bash
for Linux and macOS:

```sh
examples/scripts/01-quickstart-demo.sh      # the whole loop on demo data, no backend
```

The `diff` demonstrates the core signal - two new **stable** hosts between 1.2.0
and 1.3.0 (one telemetry, one **unknown**), plus an intermittent host the
reproduction gate correctly refuses to report as a finding:

```
example-mcp: 1.2.0 -> 1.3.0
  unchanged hosts: 2
  new hosts:
    + telemetry.example-vendor.com             [telemetry]
    + cdn.unknown-3p.net                        [unknown]

  ⚠ 1 new stable UNKNOWN host(s) - worth a look:
    cdn.unknown-3p.net
```

## A real capture

```sh
gurgl init                 # writes ~/.gurgl/gurgl.toml + the default flight plan
gurgl discover --import    # find the MCP servers already on this machine, add them
gurgl watch --all          # capture each, N trials, behind the proxy
gurgl show <server>        # the hosts it contacted, by class + reproducibility
gurgl diff <server>        # compare the two most recent versions
gurgl allow <server> --format sandbox-runtime > allow.txt
```

Prefer to list servers yourself? Edit `~/.gurgl/gurgl.toml` by hand instead of
`discover --import`; the format is in [docs/USAGE.md](docs/USAGE.md).

`gurgl show` after a capture looks like this (a real run against a server that
fetches two hosts at startup and one on the tool call):

```
pingtest@unknown  (2 trials, flight plan default-...)
HOST                                     CLASS        REPRO        SEEN
api.github.com                           registry     stable       2/2
example.com                              first-party  stable       2/2
example.org                              unknown      stable       2/2
```

### Finding your servers: `gurgl discover`

You do not have to hand-list servers. `gurgl discover` scans the standard MCP
client configs on this machine - Claude Desktop, Claude Code (`~/.claude.json`),
Cursor, Windsurf, Cline, and Codex (`~/.codex/config.toml`) - plus every
project-scoped `.mcp.json` and `.codex/config.toml` under your home, then shows
what it finds:

```
found 3 MCP server(s) configured on this machine:

NAME                 STATUS     KIND   COMMAND                        SOURCE
statewright          enabled    remote https://mcp.statewright.ai     project (~/.claude/.mcp.json)
filesystem           configured stdio  npx -y @modelcontextprotocol... Claude Code (~/.claude.json)
telegram             bundled    stdio  bun run ...                    plugin (~/.claude/plugins/.../telegram/.mcp.json)
```

The `STATUS` column tells you what is actually on, read from each client's own
config:

- **enabled** - positively listed as on (in `enabledMcpjsonServers`, or an
  `enabledPlugins` record). This is the only status gurgl asserts from evidence.
- **bundled** - a plugin that ships with a marketplace but is not enabled.
  Present on disk, not something you turned on.
- **configured** - present in a config, but gurgl found no enable record for it.

`--import` appends the local `stdio` servers to your `gurgl.toml` so `gurgl watch`
can capture them. It is safe to re-run (it skips servers already listed). Two
honest limits it calls out inline: `remote` (url) servers are inventory only -
gurgl watches local subprocesses, not remote HTTP/SSE endpoints - and `[env]`
servers set their own environment (often API keys), which gurgl does not copy.

**Not covered: ChatGPT.** ChatGPT's MCP support (Developer Mode) is remote-only:
its connectors are HTTPS endpoints configured in your OpenAI account, not a local
config on your machine, and not a local process. There is nothing on disk to
discover and nothing local to sandbox, so ChatGPT is outside gurgl's model for
the same reason `remote (url)` servers are listed but never captured.

### Live dashboard

Run in a terminal, `gurgl watch` shows a live, colored dashboard: a trial
progress bar, a per-phase timer and timeline, and hosts streaming in colored by
class as they are contacted. Piped or non-interactive output stays plain, so logs
and scripts are unaffected; force plain anywhere with `--plain`. It adds no
dependencies (plain ANSI on the alternate screen) and restores your terminal when
it finishes.

The dashboard is interactive. Move the selection through the host list and open
any host for rich context: what its class means, every phase it appeared in, how
many trials have seen it so far, and when it first showed up.

| Key | Action |
|-----|--------|
| `up`/`down` or `k`/`j` | Move the host selection |
| `enter` (or `1`-`9` to jump) | Open the selected host's detail view |
| `esc` (or `h`/`0`) | Back to the overview |
| `q` | Stop cleanly and save what completed (same as Ctrl-C) |

`q` and Ctrl-C both stop gracefully in every mode: a partial battery trial is
discarded (the reproduction gate only compares complete runs), completed trials
are saved, and the terminal is restored. Press Ctrl-C twice to force-quit.

### Watching over time

By default `gurgl watch` runs the repeated-trial battery and exits. To sit and
watch a server instead:

```sh
gurgl watch <server> --for 5m         # run once, then monitor for 5 minutes
gurgl watch <server> --until-closed   # monitor until you press Ctrl-C
```

Both run one long observation (the flight plan once, then a live monitoring hold)
rather than the battery, so you can see what a server beacons at rest. `--for`
accepts `30s`, `5m`, `1h` (a bare number is seconds). `--until-closed` stops
cleanly on Ctrl-C and still saves what it captured. Because these are a single
observation, everything is recorded as seen 1/1 - use the default battery when
you want the reproduction gate.

For a live demo with real egress, see
[flightplans/fetch-demo.toml](flightplans/fetch-demo.toml): pair it with a
no-key fetch MCP server and watch hosts stream in phase by phase, including
redirect hops the plan never named.

### Comparing notes: `gurgl export` and `diff --against`

You can share a capture and compare against someone else's. `gurgl export`
writes a **shared capture** - a scrubbed, shareable file of the *stable* hosts
you observed:

```sh
gurgl export fetch -o fetch.shared.json     # stable hosts only; JSON to a file (or stdout)
gurgl diff fetch --against fetch.shared.json # compare your latest capture to it
```

The export deliberately carries only raw receipts - host names, trial counts,
phases, the flight-plan fingerprint - and **drops gurgl's per-host class**, since
what a host *is* is the reader's call to make, not the publisher's to assert. It
bakes the [docs/PUBLISHING.md](docs/PUBLISHING.md) guardrails into the file so
they travel with it.

`diff --against` is **exploratory, never a verdict**. A shared capture is one
observer's presence-only sample under *their* flight plan - not a verified or
known-good reference. Matching it is **not** a pass (a tool exfiltrating over a
host it already contacts produces an identical set), and having more or fewer
hosts than it is expected, not proof of anything. It takes a **local path only**
- a file, a raw snapshot, or another gurgl store dir - and never fetches over the
network (a URL is refused, not downloaded). A shared file is treated as untrusted
input: size-capped, control-stripped, and re-checked against the reproduction
gate locally.

## Where things live: `~/.gurgl`

```
~/.gurgl/
├── bin/gurgl              the binary
├── env                   `source` it to put ~/.gurgl/bin on PATH
├── gurgl.toml            your config          (gurgl init)
├── flightplans/
│   └── default.toml      the scripted battery (gurgl init)
├── snapshots/            captured egress, one JSON per server@version - yours to diff & commit
│   └── <server>/<version>.json
└── mitmproxy/            the lab CA, generated on first `watch`
```

Override the location with `$GURGL_HOME`. Uninstall is `rm -rf ~/.gurgl`.

## Updating

gurgl updates **only when you ask it to**. It never checks for, pings about, or
downloads updates on its own - a security tool that makes no network calls of its
own shouldn't phone home for updates either (constraint #5 in
[CLAUDE.md](CLAUDE.md)). When you run the command below, the only network access
is the git fetch you just triggered.

```sh
gurgl update      # or: gurgl -u  /  gurgl --update
```

This pulls the latest source into a managed checkout at `~/.gurgl/src`, rebuilds,
and reinstalls into `~/.gurgl`. It works the same on any machine, including one
set up with `make deploy` (which has no local git checkout of its own). Requires
`git` and a compiler toolchain (the installer bootstraps Rust if missing).

Working from a source clone instead? `make update` (git pull + reinstall) and
`make deploy HOST=my-mac` (push to a remote over SSH/Tailscale) still work.

## Command reference

| Command | What it does |
|---------|--------------|
| `gurgl` (bare) | Orientation: config/server/capture status and the one next command. |
| `gurgl demo` | Annotated example diff on bundled data - no deps needed. |
| `gurgl doctor` | Readiness + capture-fidelity report for this machine; exits 1 if `watch` would be blocked. |
| `gurgl explain <server> [host]` | The latest capture narrated in plain language, acks woven in. |
| `gurgl init` | Create `~/.gurgl` (config, default flight plan, store). |
| `gurgl discover [--import]` | Find MCP servers on this machine (with enabled/bundled status); `--import` adds the stdio ones to `gurgl.toml`. |
| `gurgl list` | List captured servers and versions. |
| `gurgl show <server> [version]` | Show observed hosts for a version (default: latest). |
| `gurgl watch [<server>] [--all] [--for <dur>] [--until-closed] [--diff] [--allow-overwrite] [--forced]` | Capture egress behind the proxy (needs mitmproxy + sandbox). `--diff` audits each capture against its baseline and exits 1 on drift. Refuses (exit 1) to overwrite a same-version snapshot whose stable host set changed unless `--allow-overwrite`. `--forced` routes ALL TCP egress through the proxy (netns + transparent redirect; Linux + bubblewrap, needs pasta/nftables/uidmap) so a proxy-ignoring client is captured too. |
| `gurgl plan <server> [-o file] [--force]` | Scaffold a DRAFT flight plan from the server's advertised tools (launches it once, no capture). One read-only-looking `tools/call` step per tool with `REPLACE_ME` placeholders; gurgl never runs the draft. Review it, then wire it up via the server's `flightplan` key. |
| `gurgl diff <server> [--from --to] [--baseline] [--check[=any]]` | Diff egress between versions. `--check` exits 1 on new stable scrutiny hosts (CI/cron gates). |
| `gurgl diff <server> --against <path>` | Compare your capture to someone else's *shared capture* (a file or another store dir). Exploratory, never a pass/fail; local path only. |
| `gurgl ack <server> <host> [--note ...]` | Record that you reviewed a host so diff reports it quietly (also `--list`, `--remove`). |
| `gurgl accept <server> [version]` | Mark a reviewed capture as the baseline for `--baseline` / `watch --diff`. |
| `gurgl allow <server> [--format ...]` | Emit an allowlist (`sandbox-runtime` / `opensnitch` / `squid`). |
| `gurgl export <server> [version] [-o file] [--as-name n] [--force]` | Write a scrubbed, shareable *shared capture* (stable hosts only, no verdict) for others to `diff --against`. Read [docs/PUBLISHING.md](docs/PUBLISHING.md) first. |
| `gurgl update` (`-u`, `--update`) | Pull the latest source and reinstall. Runs only when invoked; no auto-update. |

Global flags: `--config <path>` (else `./gurgl.toml`, else `~/.gurgl/gurgl.toml`),
`--store <dir>`, `--plain` (disable the live dashboard), `--json` (stable,
versioned JSON from `list`/`show`/`diff`/`discover`, for jq and scripts).

**Exit codes** are a contract: `0` = no drift at the requested threshold, `1` =
drift detected (`diff --check`, `watch --diff`), `2` = error - so a cron line or
CI step can gate on gurgl directly. (`diff --against` is the deliberate exception:
it is exploratory and returns only `0` = compared or `2` = error, never `1` - a
stranger's capture must never be a pass/fail oracle.) Copy-paste automation (cron, systemd,
launchd, CI, jq) lives in **[docs/RECIPES.md](docs/RECIPES.md)**. Every flag,
the config schema, and flight plans are documented in
**[docs/USAGE.md](docs/USAGE.md)**.

## Using gurgl effectively

gurgl is an egress inventory with a memory. Its value compounds with routine,
not one-off runs:

**1. Vet before you adopt.** Before adding any MCP server to Claude Code,
Cursor, or another client, run it through gurgl first: `gurgl watch <name>`.
You learn its network footprint before it touches your real environment. A
filesystem tool that talks to one host is boring - that is the point. A
"markdown converter" contacting six unknowns is a decision you now get to make
consciously.

**2. Gate upgrades with diff.** The core loop. Baseline every server you use
(`gurgl accept <server>` once reviewed), then after any update:

```sh
gurgl watch --all --diff        # captures, compares to your baselines, exits 1 on drift
```

A new **stable** unknown host after a version bump is exactly the
[postmark-mcp] pattern - a package that turns malicious in a patch release. This
is the one attack class an egress diff catches almost for free. Put that one
command in a weekly cron ([docs/RECIPES.md](docs/RECIPES.md)) and review with
`gurgl diff <server>` when it exits 1; `gurgl ack` hosts you have reviewed so
they never re-alert, and `gurgl accept` the capture when you are done.

**3. Commit your snapshots.** They are plain JSON receipts in
`~/.gurgl/snapshots/`. Keep them in a git repo and you have a timestamped,
diffable history of what your tools contacted - cheap forensics when you need to
answer "when did this host first appear?"

**4. Feed enforcement.** `gurgl allow` turns observation into policy - see below.

### What it works with

gurgl deliberately only observes. It pairs with tools that decide or block, and
the `gurgl allow` formats target them directly:

| Tool | Relationship |
|------|--------------|
| [OpenSnitch] (Linux), Little Snitch / LuLu (macOS) | Per-app firewalls that ask "allow this connection?" at runtime. gurgl answers the question they cannot: what does this tool *normally* contact? `gurgl allow <server> --format opensnitch` turns a clean baseline into rules, so the firewall only prompts on genuine anomalies. |
| [Anthropic sandbox-runtime] | Enforces a network allowlist on the running agent. `gurgl allow --format sandbox-runtime` generates the domain list from observed behavior instead of guesswork. Observe with gurgl, enforce with the sandbox - the strongest combo. |
| Squid or another egress proxy | The same idea at a network chokepoint: `--format squid` emits the ACL. |
| mcp-scan (Invariant Labs) and other static scanners | An orthogonal axis. They inspect tool *descriptions and prompts* (tool poisoning, injection); gurgl inspects *runtime network behavior*. A server can pass one and fail the other - run both when vetting. |
| Socket.dev, npm audit, dependency scanners | Supply-chain metadata: who published, what changed in the package. gurgl adds the behavioral half - what the code actually does on the wire. |

The layering in one line: **scanners judge the code, gurgl witnesses the
behavior, firewalls and sandboxes enforce the boundary.** gurgl is the middle
layer that makes the enforcement rules evidence-based instead of guesswork.

## What gurgl cannot do (read this)

gurgl reports **presence, never absence**, and only for **cooperating clients**.
v1 capture wires the sandboxed child to the proxy via `HTTPS_PROXY` + a lab CA;
a client that ignores proxy env vars or opens raw sockets escapes capture (the
tracked hardening step is a network namespace + transparent redirect). The
sandbox is **functional but not yet a security boundary**. See
**[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** and **[docs/ROADMAP.md](docs/ROADMAP.md)**.

## Documentation

| Doc | What |
|-----|------|
| [docs/INSTALL.md](docs/INSTALL.md) | Per-OS install, PATH, remote deploy, uninstall |
| [docs/USAGE.md](docs/USAGE.md) | Every command + the config & flight-plan reference |
| [docs/RECIPES.md](docs/RECIPES.md) | Cron/systemd/launchd audits, CI gates, jq one-liners |
| [examples/scripts/](examples/scripts/) | Ten runnable demo scripts (Linux/macOS): quickstart, vet, drift audit, CI gate, allowlists, forensics, live capture |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How capture, the reproduction gate, and storage work |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What gurgl can and cannot see - read before trusting output |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Scope, kill criteria, the deliberate ceiling |
| [docs/PUBLISHING.md](docs/PUBLISHING.md) | Guardrails if you ever publish observations naming a vendor |
| [docs/SPEC.md](docs/SPEC.md) | The v1 specification |

## Publishing note

gurgl is a personal tool first. If you ever publish observations that **name a
vendor**, don't do it casually - read **[docs/PUBLISHING.md](docs/PUBLISHING.md)**
first. There are real legal and ethical guardrails (entity + insurance, raw
receipts only, reproduction gate, coordinated disclosure, never shame solo
maintainers). They are not optional.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

[Anthropic sandbox-runtime]: https://github.com/anthropic-experimental/sandbox-runtime
[OpenSnitch]: https://github.com/evilsocket/opensnitch
[postmark-mcp]: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/
