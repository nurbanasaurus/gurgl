# gurgl documentation

Local-first egress hygiene for the MCP servers you run. Start at the
[project README](../README.md) for the overview, then dive in here.

## Getting started

- **[INSTALL.md](INSTALL.md)** — install on Linux or macOS, per-OS backend
  setup, remote deploy, updating, uninstall.
- **[USAGE.md](USAGE.md)** — every command with examples, the `gurgl.toml`
  schema, flight plans, and how to read a snapshot.

## Understanding it

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — how capture, the reproduction gate,
  phase attribution, and storage work.
- **[THREAT-MODEL.md](THREAT-MODEL.md)** — what gurgl can and, crucially,
  **cannot** see. Read this before you trust any output.
- **[SPEC.md](SPEC.md)** — the v1 specification.

## Direction & guardrails

- **[ROADMAP.md](ROADMAP.md)** — scope, kill criteria, and the deliberate
  ceiling (gurgl is a respected local tool, not a venture).
- **[PUBLISHING.md](PUBLISHING.md)** — the legal and ethical guardrails that
  apply *if* you ever publish observations naming a third party.

## The short version

| I want to… | Go to |
|------------|-------|
| Get it running | [INSTALL.md](INSTALL.md) |
| Learn the commands | [USAGE.md](USAGE.md) |
| Know what it can't catch | [THREAT-MODEL.md](THREAT-MODEL.md) |
| Understand the internals | [ARCHITECTURE.md](ARCHITECTURE.md) |
| Contribute a capability | [ROADMAP.md](ROADMAP.md) |

## Working agreement

If you're editing gurgl (human or AI), read **[../CLAUDE.md](../CLAUDE.md)** — it
encodes the non-negotiable framing (inventory-not-verifier, presence-not-absence,
the reproduction gate, hosts-not-payloads, no telemetry) that the whole tool
depends on.
