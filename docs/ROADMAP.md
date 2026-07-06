# Roadmap

gurgl is intentionally small. The roadmap is about *finishing v1 well* and
staying inside the honest scope, not about growing into a platform. The ceiling
is deliberate (see the note at the end).

## v1 - the personal tool (in progress)

**Goal:** you get daily value on your own machine, every time you install or
update an MCP server.

- [x] Core model, host classification, storage.
- [x] Reproduction gate (`observe::aggregate`).
- [x] Version-over-version diff.
- [x] Allowlist emit (sandbox-runtime / OpenSnitch / squid).
- [x] Sandbox + proxy command construction (bubblewrap default, podman, Seatbelt).
- [x] Embedded mitmproxy addon + flow parsing.
- [x] **Live capture** (`observe::run_trial`) - spawn proxy, launch sandboxed
      server through it, drive MCP over stdio, attribute hosts to phases by
      timestamp. Verified end-to-end against a live server.
- [ ] Version derivation (resolve the actual installed version of an npm/PyPI
      MCP server instead of the config label).
- [x] `watch` ergonomics: live dashboard, timing, partial-capture handling.
- [x] **Local sharing primitives** (`gurgl export` + `gurgl diff --against`):
      scrub a capture into a shareable *shared capture* (stable hosts only, class
      dropped, guardrails baked in-band), and compare your capture to someone
      else's local file/store dir. Exploratory only, never a pass/fail; local
      path only, never a network fetch. These are the personal-tool foundation
      the v2 catalog would build on - the file format and the consume path exist,
      the *distribution* deliberately does not.

## v1.1 - capture hardening

- [ ] Network-namespace + transparent redirect so *all* egress is forced
      through the proxy (not just proxy-env-honoring clients); block UDP/443.
- [ ] Per-target fidelity notes (known proxy-fingerprinting / pinning).
- [ ] Pure-Rust MITM backend (`hudsucker`) as an alternative to mitmdump.

## v2 - the community catalog (only as exhaust, only with guardrails)

If and only if the personal tool is genuinely useful and you're already running
it, a *static* community catalog of observed host sets per MCP-server@version
can be published as a byproduct. This is gated on **docs/PUBLISHING.md** in full
(entity + insurance, raw receipts, reproduction gate, coordinated disclosure,
never shaming solo maintainers). It is not a live index, not a paid feed, not a
"verified/safe" ranking.

The **local** half already exists: `gurgl export` produces the scrubbed,
guardrail-carrying artifact and `gurgl diff --against` consumes one. What is
deliberately *not* built is any distribution of them - and the constraints on
that stay hard: PATH-only consumption forever (no default/well-known catalog URL,
no "check for a newer capture", no auto-sync endpoint), or it becomes the
phone-home the whole tool refuses to be.

- [ ] Signed, versioned static dataset format (bundling many exported captures).
- [ ] Contribution flow for community-run flight plans.
- [ ] Event-triggered writeups (only when materially newsworthy).

## Kill criteria (decide before you're attached)

Stop or downscope if:

- **(a)** Vendors ship signed, accurate, independently-verifiable egress
  manifests and keep them green → the verification value collapses to
  spot-checking; wind down to a personal tool.
- **(b)** A better-resourced *independent* observer (academic lab, an
  Exodus-style nonprofit, a funded firewall vendor already publishing observed
  egress) commits to continuous coverage → contribute to theirs instead of
  running parallel infrastructure.
- **(c)** After ~6 months, the tool isn't earning its keep for *you* and there
  are no outside contributors → it's a personal utility plus a couple of good
  writeups. That's a fine outcome; stop calling it a product.

## The deliberate ceiling

gurgl is a respected local tool + reputation asset, not a venture. It clears
"one thing done well", "daily personal benefit", and "grows into something with
meaning". It does **not** claim a defensible moat, and that's an accepted,
eyes-open trade - see the project notes that led here. Build the small true
thing; let it earn the right to become more.
