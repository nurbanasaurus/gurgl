# gurgl - specification

## One sentence

A local-first CLI that measures what the MCP servers you run contact on the
network, diffs it across versions, and emits allowlists - so you notice when an
install or update starts talking somewhere new.

## The one thing it does

For each MCP server you run: capture its egress reproducibly under a fixed flight
plan, store it per version, and answer *"what changed?"* - with the new-host
diff as the primary signal and a generated allowlist as the primary action.

## Users

You (a security engineer running MCP servers on Linux) are user #1. The tool is
useful with an audience of exactly one; any publication is a byproduct of your
own dogfooding, never the reason it exists.

## Requirements

- **Local-first.** No backend, no account, no telemetry. Nothing observed leaves
  the machine.
- **Reproducible.** N trials per capture, fixed flight plan committed to the
  repo, method fingerprint stored with each snapshot.
- **Honest.** Inventory + drift, never verification. No "safe/clean/verified".
  Presence-only lower bounds. The reproduction gate suppresses cohort noise.
- **Rides incumbents.** Emits allowlists for enforcement engines you already run
  (sandbox-runtime, OpenSnitch, squid); it does not enforce or block itself.
- **Single binary.** Rust; external `mitmdump` + sandbox backend as runtime deps.

## Scope

**In:** MCP servers (npm/PyPI/container) and MCP-speaking CLIs you configure;
host-name egress; version diffing; allowlist generation; local storage; **local**
export/compare of a scrubbed *shared capture* (`gurgl export` / `diff --against`,
a local file exchanged out-of-band - not a hosted service).

**Out (v1):** payload inspection; GUI IDEs (ToS/automation risk); a live public
index or hosted catalog; fetching a shared capture over the network (it is
PATH-only, by design); a paid feed; any "verify vendor claims / is-my-code-safe"
certification; treating agreement with a shared capture as a pass; blocking/enforcement.

## Commands

| Command | Does |
|---------|------|
| `gurgl init` | write `gurgl.toml`, create the store |
| `gurgl watch <server> \| --all` | capture egress (N trials) and store it |
| `gurgl plan <server>` | scaffold a DRAFT flight plan from the server's tools (never run) |
| `gurgl list` | list captured servers/versions |
| `gurgl show <server> [version]` | print observed hosts |
| `gurgl diff <server> [--from --to]` | diff two versions (default: latest two) |
| `gurgl allow <server> [version] --format ...` | emit an allowlist |

## Success criteria

- You run it on every MCP install/update and it takes < a couple of minutes.
- A new stable unknown host in a diff makes you look before you keep using the
  update.
- The generated allowlist meaningfully tightens what that server can reach.

## Explicit non-goals

Detecting in-band exfiltration; seeing server-side behavior; certifying safety;
being comprehensive across the whole MCP universe; becoming a SaaS. See
docs/THREAT-MODEL.md and docs/ROADMAP.md for why each is out.
