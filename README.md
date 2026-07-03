# gurgl

**Local-first egress hygiene for the MCP servers you run.**

[![license](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![build](https://img.shields.io/badge/build-cargo-orange.svg)](#install)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS-lightgrey.svg)](docs/INSTALL.md)

gurgl captures what an MCP server contacts on the network, diffs that across
versions, and emits least-privilege allowlists you can enforce with tools you
already run. It exists to answer one question you can't easily answer today:

> **When I install or update an MCP server, does it start talking to somewhere new?**

It runs entirely on your machine. No backend, no account, no telemetry — gurgl
makes **no network calls of its own**, and nothing it observes ever leaves your box.

---

## Contents

- [What gurgl is — and isn't](#what-gurgl-is--and-is-deliberately-not)
- [How it works](#how-it-works-30-seconds)
- [Install](#install) · [full per-OS guide →](docs/INSTALL.md)
- [Try it now (no backend)](#try-it-now-no-capture-backend-needed)
- [A real capture](#a-real-capture)
- [Where things live: `~/.gurgl`](#where-things-live-gurgl)
- [Updating](#updating)
- [Command reference](#command-reference) · [full usage guide →](docs/USAGE.md)
- [What gurgl cannot do](#what-gurgl-cannot-do-read-this)

## What gurgl is — and is deliberately not

gurgl is an **egress inventory + drift** tool. It tells you, reproducibly:

- the set of hosts a `server@version` was observed contacting under a fixed
  *flight plan*, each classified (**first-party / telemetry / registry / unknown**);
- what **changed** between two versions — **new hosts are the signal**;
- an **allowlist** for [Anthropic sandbox-runtime], [OpenSnitch], or a squid proxy.

gurgl is **not** a verifier, scanner, or safety certifier. It never tells you a
tool is "safe," "clean," or "verified" — it can't, and pretending otherwise
would be dishonest. Specifically it **cannot**:

- see *what* is sent — it records host names, never payloads;
- catch exfiltration riding a host the tool already legitimately uses (a
  malicious server that BCCs your data out *through the real vendor API* — the
  [postmark-mcp] pattern — looks identical to normal use);
- see anything a vendor does **server-side** (retention, training, resale);
- prove a tool *won't* contact a host it simply didn't reach under the flight plan.

Those limits are the whole reason gurgl is scoped the way it is. Read
**[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** before you trust any output.

**Why it's still worth running:** most real-world MCP nastiness isn't subtle
in-band exfiltration — it's a package that, after an update, simply starts
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

`install.sh` installs Rust if it's missing, builds gurgl, and reports the two
runtime deps that only `gurgl watch` needs. Install those per your OS:

| OS | sandbox backend | capture proxy |
|----|-----------------|---------------|
| **macOS** | `sandbox-exec` (built in) | `brew install mitmproxy` |
| **Debian/Ubuntu** | `sudo apt install bubblewrap` | `pipx install mitmproxy` |
| **Fedora** | `sudo dnf install bubblewrap` | `pipx install mitmproxy` |
| **Arch** | `sudo pacman -S bubblewrap` | `pacman -S mitmproxy` |

> `list` / `show` / `diff` / `allow` need **neither** — only `watch` (capture) does.

Copy-paste blocks for each OS, PATH setup, and uninstall are in
**[docs/INSTALL.md](docs/INSTALL.md)**.

## Try it now (no capture backend needed)

The pure logic works immediately against bundled example snapshots:

```sh
gurgl --config examples/gurgl.toml list
gurgl --config examples/gurgl.toml diff example-mcp
gurgl --config examples/gurgl.toml allow example-mcp --format squid
```

The `diff` demonstrates the core signal — two new **stable** hosts between 1.2.0
and 1.3.0 (one telemetry, one **unknown**), plus an intermittent host the
reproduction gate correctly refuses to report as a finding:

```
example-mcp: 1.2.0 -> 1.3.0
  unchanged hosts: 2
  new hosts:
    + telemetry.example-vendor.com             [telemetry]
    + cdn.unknown-3p.net                        [unknown]

  ⚠ 1 new stable UNKNOWN host(s) — worth a look:
    cdn.unknown-3p.net
```

## A real capture

```sh
gurgl init                 # writes ~/.gurgl/gurgl.toml + the default flight plan
$EDITOR ~/.gurgl/gurgl.toml # list the MCP servers you actually run
gurgl watch --all          # capture each, N trials, behind the proxy
gurgl show <server>        # the hosts it contacted, by class + reproducibility
gurgl diff <server>        # compare the two most recent versions
gurgl allow <server> --format sandbox-runtime > allow.txt
```

`gurgl show` after a capture looks like this (a real run against a server that
fetches two hosts at startup and one on the tool call):

```
pingtest@unknown  (2 trials, flight plan default-…)
HOST                                     CLASS        REPRO        SEEN
api.github.com                           registry     stable       2/2
example.com                              first-party  stable       2/2
example.org                              unknown      stable       2/2
```

## Where things live: `~/.gurgl`

```
~/.gurgl/
├── bin/gurgl              the binary
├── env                   `source` it to put ~/.gurgl/bin on PATH
├── gurgl.toml            your config          (gurgl init)
├── flightplans/
│   └── default.toml      the scripted battery (gurgl init)
├── snapshots/            captured egress, one JSON per server@version — yours to diff & commit
│   └── <server>/<version>.json
└── mitmproxy/            the lab CA, generated on first `watch`
```

Override the location with `$GURGL_HOME`. Uninstall is `rm -rf ~/.gurgl`.

## Updating

gurgl **never self-updates** — a security tool that makes no network calls of
its own shouldn't phone home for updates either (see constraint #5 in
[CLAUDE.md](CLAUDE.md)). Updating is explicit: pull the source and reinstall.

```sh
cd gurgl && make update      # git pull --ff-only && ./install.sh
```

To update a remote machine you deploy to (e.g. over Tailscale/SSH):

```sh
make deploy HOST=my-mac      # rsync latest source, rebuild + reinstall natively there
```

## Command reference

| Command | What it does |
|---------|--------------|
| `gurgl init` | Create `~/.gurgl` (config, default flight plan, store). |
| `gurgl list` | List captured servers and versions. |
| `gurgl show <server> [version]` | Show observed hosts for a version (default: latest). |
| `gurgl watch [<server>] [--all]` | Capture egress behind the proxy (needs mitmproxy + sandbox). |
| `gurgl diff <server> [--from --to]` | Diff egress between two versions (default: latest two). |
| `gurgl allow <server> [--format …]` | Emit an allowlist (`sandbox-runtime` / `opensnitch` / `squid`). |

Global flags: `--config <path>` (else `./gurgl.toml`, else `~/.gurgl/gurgl.toml`),
`--store <dir>`. Every flag, the config schema, and flight plans are documented
in **[docs/USAGE.md](docs/USAGE.md)**.

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
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How capture, the reproduction gate, and storage work |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | What gurgl can and cannot see — read before trusting output |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Scope, kill criteria, the deliberate ceiling |
| [docs/PUBLISHING.md](docs/PUBLISHING.md) | Guardrails if you ever publish observations naming a vendor |
| [docs/SPEC.md](docs/SPEC.md) | The v1 specification |

## Publishing note

gurgl is a personal tool first. If you ever publish observations that **name a
vendor**, don't do it casually — read **[docs/PUBLISHING.md](docs/PUBLISHING.md)**
first. There are real legal and ethical guardrails (entity + insurance, raw
receipts only, reproduction gate, coordinated disclosure, never shame solo
maintainers). They are not optional.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

[Anthropic sandbox-runtime]: https://github.com/anthropic-experimental/sandbox-runtime
[OpenSnitch]: https://github.com/evilsocket/opensnitch
[postmark-mcp]: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/
