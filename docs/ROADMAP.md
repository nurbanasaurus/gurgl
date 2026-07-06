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
- [~] Version derivation - the `serverInfo.version` path is done; deriving from
      the actually-installed npm/PyPI package (so an attacker-chosen version
      string is no longer the storage key) is **item 2 of the v1.1 plan below**.
- [x] `watch` ergonomics: live dashboard, timing, partial-capture handling.
- [x] **Local sharing primitives** (`gurgl export` + `gurgl diff --against`):
      scrub a capture into a shareable *shared capture* (stable hosts only, class
      dropped, guardrails baked in-band), and compare your capture to someone
      else's local file/store dir. Exploratory only, never a pass/fail; local
      path only, never a network fetch. These are the personal-tool foundation
      the v2 catalog would build on - the file format and the consume path exist,
      the *distribution* deliberately does not.

## v1.1 - the "pursue now" plan (sequenced)

Five items survived the July-2026 market re-scoping as *pursue now*; the rest
were deferred or refused (list at the end of this section). They are **sequenced,
not parallel**. Two of them fix honesty foundations - what a capture *covers*
(item 1) and what version label it is *stored under* (item 2) - and the three
authoring / machine-surface items are only worth as much as the captures beneath
them, so they land behind the foundations. Effort tags are S/M/L/XL. None adds a
network path or an HTTP-client crate; each carries its constraint check against
CLAUDE.md's non-negotiables.

Source-grounded scope for all five lives in the working notes; what follows is
the plan of record.

### 1. Forced-capture backend: netns + transparent redirect (the unanimous #1)

**Status: SHIPPED (both slices, Linux) and live-verified.** Slice 1a
(capture_mode labeling) plus slice 1b (the forced backend) are done. The design
was spike-validated on the Pop!_OS box before any gurgl code was written (rootless
multi-uid userns + pasta egress + `nft inet` OUTPUT REDIRECT with the launcher-uid
exclusion + transparent mitmdump; bwrap-in-netns preserves the uid distinction;
the SNI is captured even when a cert-pinning client rejects the lab CA). The
load-bearing test passed live: a proxy-ignoring MCP server (`urllib` with
`ProxyHandler({})`) is captured (`example.com`, stable) under `--forced` and
observed 0 hosts under env-proxy. What actually shipped vs. the plan below: the
opt-in is a `capture = "forced"` config key + `watch --forced` flag (not a new
`SandboxKind`); the netns is made IPv4-only because the v6 REDIRECT target
(`[::1]:port`) does not carry the original destination reliably (documented
coverage limit); `uidmap`/`newuidmap` is required (the second uid the exclusion
needs); the addon gained a `tls_clienthello` SNI hook. macOS Seatbelt hardening
is still open. The rest of this item is kept as the original design record.

**Goal.** An additive Linux capture strategy that forces *all* child TCP egress
through mitmdump - not just clients that honor `HTTPS_PROXY` - blocks UDP/443 so
QUIC clients fall back to interceptable TCP, and stamps every `Snapshot` with how
it was captured (`forced` vs `env-proxy`) so `show`/`diff`/`doctor` stop implying
more coverage than they have. This closes the one gap ARCHITECTURE.md already
names: a client that ignores proxy env or opens raw sockets escapes capture today.

**Land it in two slices** (this is the honest sizing - the item is two very
different sizes of work bolted together):

- **1a. `capture_mode` labeling (M) - ship first, hardcoded to `env-proxy`.**
  `model.rs`: `enum CaptureMode { EnvProxy, Forced }` (kebab-case, `Display`,
  `Default = EnvProxy`) plus `#[serde(default)] capture_mode` on `Snapshot`, so
  every old snapshot on disk deserializes as `env-proxy` and *never* as `forced`
  (defaulting an unlabeled capture to `forced` would be a false coverage claim).
  `main.rs`: `doctor` gains a forced-capture-feasibility probe (kernel version,
  `nft` on PATH, pasta/slirp4netns on PATH, and whether unprivileged userns is
  AppArmor-restricted a la Ubuntu 24.04), reported as coverage prose, never a
  pass/fail badge; `show` prints the mode; `diff` adds both modes to the JSON and
  **warns when they differ** (an `env-proxy` -> `forced` diff surfaces phantom
  "new" hosts that were always there but previously unseen - it must be flagged
  like the existing `flightplan_mismatch`, or it reads as drift). This slice is
  safe, testable without root, and delivers the honest-labeling win on its own.

- **1b. The forced backend itself (XL) - spike-gated.** `sandbox.rs`:
  `build_bwrap_forced_argv` that does `--unshare-net`, brings up `lo`, and execs
  an in-netns setup-then-server sequence; a pure, unit-testable
  `nft_ruleset(mitm_uid, tproxy_port)` string builder (REDIRECT tcp 80/443 while
  excluding the mitmdump owner uid; `drop` udp/443). `observe.rs`: a
  `spawn_netns_egress` wrapper around pasta/slirp4netns for rootless upstream
  connectivity. `proxy.rs`: `--mode transparent`. `config.rs`: an **opt-in**
  `SandboxKind` (or `capture=` key) - never the silent Linux default, so a host
  that can't do netns keeps working on `env-proxy`.

**Privilege model (the crux, resolved).** `unshare -rn` makes the child the owner
of a new user + net namespace; per `user_namespaces(7)` the owner holds
`CAP_NET_ADMIN` over namespaces it owns, so nft rules on the child's *own* netns
need **no host root**. But `--unshare-net` leaves that netns with a loopback-only
route and no path to the internet - mitmdump inside it has nowhere to send
upstream traffic. The rootless fix is pasta/slirp4netns (a userspace TCP/IP
stack, the modern podman-5 egress path), a **new external binary** (a
supply-chain decision, but consistent with the existing external mitmdump/bwrap
model - not a Rust crate). The veth-pair alternative needs host `CAP_NET_ADMIN` =
root and is rejected. **Spike before any gurgl code:** on a scratch box, prove
`unshare -rn` + pasta + in-netns nft REDIRECT + in-netns mitmdump transparent
captures a raw-socket client. If the spike fails, fall back to mitmproxy's eBPF
`--mode local` and **disclose the sudo requirement in `doctor`** rather than hide
it - never write gurgl code against an unproven design.

**Schema / back-compat.** `capture_mode` via `#[serde(default)]` - no store
migration, no version-dir change; `gurgl.show/1` and `gurgl.diff/1` gain additive
fields (a `capture_mode_mismatch` bool alongside `flightplan_mismatch`), so no
schema bump.

**Load-bearing test.** Run a client that ignores `HTTPS_PROXY`
(`curl --noproxy '*'` or a raw-socket Python) under the forced backend and assert
its host lands in `flows.jsonl`, where `env-proxy` captures nothing for it. That
single live test is the only evidence "forced" is not a lie. Plus: an HTTP/3
client seen on TCP after the udp/443 drop (noting any hard-fail client), and
`doctor` reporting correct availability on both a capable box and an
AppArmor-restricted one.

**Constraint check.** #1/#2: `forced` is a stronger *mechanism*, never a
completeness claim - every string says "all TCP egress was routed through the
proxy", never safe/clean/complete/verified; presence-only notes stay. #3: the
reproduction gate is untouched; a cross-mode diff must warn so a mode change is
never misread as drift. #5: all new work is local process orchestration
(nft/pasta/mitmdump/netns) - zero gurgl-initiated network calls; pasta carries
only the *observed server's* egress. #6: forced still cannot see trusted-channel
or server-side exfil, and the fidelity docs restate that.

**Effort:** M (1a) + XL (1b, spike-gated). **Depends on:** nothing; but 1a ships
independently so the labeling value survives even if the netns spike stalls.

### 2. Version from the installed package + rug-pull guard - L

**Status: shipped.** Both halves are done and live-verified - derivation from the
installed package (`pkgver`, sandbox HOME now a host bind) and the rug-pull guard
(`diff::same_label_conflict`; `watch` refuses a stable-set-changing same-version
overwrite, exit 1, `--allow-overwrite` to bypass).

**Goal.** Label a capture with the version the package manager *actually resolved
and installed* inside the sandbox (read from local files only - `package.json`
for node, `*.dist-info` for python), demoting the MCP `initialize`
`serverInfo.version` to a display-only `reported_version`. New precedence:
config `version` > derived-from-installed-package > server-reported > `unknown`.
A package that self-reports `9.9.9` while installing as `1.2.0` becomes visibly
discrepant instead of silently trusted as the storage key. And on save, when a
snapshot already exists for the same `server@version` under the same flight-plan
fingerprint but with a **different stable host set** (both sides `trials >= 2`),
gurgl refuses to silently overwrite - it prints the stable-host delta, prompts on
a TTY (default No), refuses non-interactively unless `--allow-overwrite` is
passed, and keeps the prior snapshot. A silent same-version overwrite is exactly
what a re-released ("rug-pulled") package looks like.

**Files.** New pure `pkgver.rs` (`package_from_args` parses launcher argv for
npx/uvx/pipx/bunx; `installed_version` does a bounded, size-capped local walk of
the resolved package tree - no registry query). `observe.rs`: per-trial scratch
`home/` bound host-side so the install cache is readable; a pure
`resolve_version(config, installed, reported)` precedence fn; bail if two
completed trials derive *different* installed versions (a mid-battery re-release
would mix two codebases under one label, breaking the gate premise). `diff.rs`:
pure `same_label_conflict` (stable sets only, `trials >= 2` both sides, same
fingerprint). `model.rs`: `reported_version` + `version_source`, both
`serde(default, skip_serializing_if = None)`. `sandbox.rs`: thread a sandbox-home
mount through all three backends. `main.rs`: the save-site conflict guard + a
`confirm_overwrite` TTY prompt. `cli.rs`: `--allow-overwrite`.
`docs/THREAT-MODEL.md`: the honest residual - the derived version is read from
files written *inside* the sandbox, so it beats a lying `serverInfo` but is not
tamper-proof against a hostile postinstall; state it, do not hide it (#6).

**Schema / back-compat.** Two optional `serde(default)` snapshot fields; old
snapshots load as `None`, old binaries reading new snapshots are unaffected. New
`--allow-overwrite` flag; `watch` gains a documented exit-1 case (same-version
capture refused because the stable set changed) reusing the existing "1 = drift"
meaning, not a new code.

**Load-bearing test.** Live rug-pull drill: `watch` a real npx server, confirm
the snapshot lands under the npm-resolved version with `version_source =
installed-package`; then hand-edit the stored snapshot's stable hosts and re-watch
the same version to observe the loud delta print, the y/N prompt, exit 1 when
piped, and the prior file surviving. Repeat once for a uvx server.

**Constraint check.** #5: exclusively local file reads under gurgl's own scratch
home - no `npm view`, no registry query, no network path. #3: the conflict
compares *stable* sets only and only when both ran the gate; intermittent/observed
deltas can never trigger it. #1/#2: all wording is observational ("stable host
set changed under the same version label"), never "tampered"/"malicious". Zero new
crates (serde_json parses `package.json`; `METADATA` is a std line scan).

**Effort:** L. **Depends on:** nothing. Can land alongside slice 1a.

### 3. `gurgl plan <server>` - flight-plan scaffolding - L

**Status: shipped.** `plan.rs` (pure render) + `observe::enumerate_tools`
(no-proxy sandboxed launch) + the `build_argv(Option<&ProxyEnv>)` refactor, all
live-verified. Note: the no-proxy launch binds the resolved `/etc/resolv.conf` so
DNS works without the proxy (the capture path routes DNS through the proxy).

**Goal.** A new subcommand launches the configured server *once* in the sandbox
(no proxy, no capture), drives `initialize` -> `tools/list` over stdio, and writes
a **draft** flight plan to `flightplans/<server>.toml` for human review - one
`tools/call` step per tool that looks read-only under the existing name heuristic,
with placeholder args derived from each tool's `inputSchema` (`REPLACE_ME` for
strings, `0` for numbers, etc.). gurgl **never runs the draft and never fuzzes
args**; a hand-written header states the reproduction-gate implication (a new or
edited plan is a new method with a new fingerprint, so its snapshots are not
comparable to default-plan ones).

**Files.** New pure `plan.rs` (`render_draft_plan` hand-emits commented TOML -
`toml::to_string` drops comments, so it is hand-rendered and guarded by a
round-trip `FlightPlan::load` test). `observe.rs`: `enumerate_tools` (sandboxed,
no-proxy stdio handshake reusing the existing private machinery) and
`tool_looks_unsafe` extracted from `pick_benign_tool` so the SAFE/UNSAFE list is
single-sourced. `sandbox.rs`: `build_argv` gains `env: Option<&ProxyEnv>` - when
`Some` it is byte-identical to today; when `None` it skips the CA bind and proxy
env for the no-capture launch. `cli.rs` + `main.rs`: the `Plan` subcommand and
`cmd_plan` (write via `write_atomic`, refuse overwrite without `--force`, print
the exact `flightplan = "..."` wire-up line and the review caveats).

**Risk to flag.** The `build_argv` -> `Option<&ProxyEnv>` refactor touches the
load-bearing capture path via its one `run_trial` call site; a silent env/argv
regression there would blind captures. Mitigation: keep `run_trial`'s own spawn
untouched, add a unit test asserting the `Some`-argv is byte-identical to today's.
**Note the coupling with item 1b:** both this item and the forced backend edit
`sandbox::build_argv`'s signature. Land them in sequence (this after 1b, or
rebase whichever lands second) so the signature churns once.

**Constraint check.** #1: the read-only filter and every generated comment say
"read-only-looking (heuristic, review before running)", never safe/clean/verified
- enforced by a test asserting those substrings are absent. #3: the header warns a
new plan is a new fingerprint. #5: gurgl makes no network call of its own; it only
launches the target (whose egress is disclosed, not captured or fetched) and never
fetches schemas. Never-auto-execute / never-auto-fuzz: inert `REPLACE_ME`
placeholders written to disk only. Zero new deps.

**Effort:** L. **Depends on:** sequences behind capture maturity (a generated plan
is only worth capturing under once forced capture makes the snapshots trustworthy)
and shares the `build_argv` signature with 1b.

### 4. NDJSON drift events (`gurgl.event/1`) - M

**Goal.** `gurgl diff <server> --events <FILE|->` and `watch --diff --events
<FILE>` additionally emit one compact JSON line per drifting host (schema
`gurgl.event/1`, kind `new-stable-scrutiny-host`) so a user's own log shipper
(vector/filebeat/promtail) can tail it. The event set is *exactly* the existing
gate set `drift_hosts(...)` - stable + needs-scrutiny + not acked - pinned equal
by a unit test, so intermittent/observed hosts can never produce an event and
removed hosts produce nothing. Events are purely additional: the human report, the
`gurgl.diff/1` object, and the 0/1/2 exit contract are untouched.

**Files.** New pure I/O-free `event.rs` (`DriftEvent`, `SCHEMA`, `drift_events`,
`to_ndjson_line`). `cli.rs`: `--events` on `Diff` and `Watch`, added to the
`--against` `conflicts_with_all` list (a stranger's capture must never feed a
drift log). `main.rs`: `append_events` (append-only NDJSON, `O_APPEND`, one
`write_all` per full line; a **URL-shaped path is refused** before any open,
mirroring `share.rs`'s never-fetch stance); a failed write to a file the user
asked for is exit 2. `docs/USAGE.md`: document the schema next to `gurgl.diff/1`,
the additive-only rule, and the no-network-sink stance (no syslog, no CEF, no
URL - bring your own shipper). Plus a drive-by: fix the `Snapshot.flightplan`
doc comment (it says "name" but stores the fingerprint).

**Schema.** New versioned `gurgl.event/1`, locked by an exact-serialization test;
additive fields stay `/1`, rename/removal needs `/2`. No snapshot/config/store
changes. `gurgl.diff/1` is deliberately *not* extended (phases are looked up from
the to-snapshot inside `event.rs`).

**Load-bearing test.** Against the bundled examples (no capture backend needed):
`diff example-mcp --check --events /tmp/ev.ndjson` must exit 1 and append exactly
one line (the one stable Unknown host; the intermittent host absent - that
absence is the proof the gate holds); run twice -> two lines (append, not
overwrite); `ack` the host -> zero new lines, exit 0; a URL path and
`--against ... --events` and `--json --events -` each refused.

**Constraint check.** #1/#2: one observational kind, no verdict/severity field,
per-line `note` carries the caveat; only additions emit, removed hosts emit
nothing, zero events is documented as non-coverage not cleanliness. #3: the
builder consumes the exact gate set, pinned equal by test. #5: sinks are stdout or
a local file, period - no socket, URL-shaped paths refused. Zero new deps (date
coarsening reuses `share::date_from_epoch`).

**Effort:** M. **Depends on:** lands after 1a so the machine surface can carry
`capture_mode` context; shares `cmd_watch`/`cmd_diff` drift code with item 5, so
land this before 5.

### 5. Agent-native machine surface (`--json` gaps + `AGENTS.md` + `SKILL.md`) - L

**Goal.** Every command either emits a versioned, note-carrying JSON schema under
`--json` or refuses loudly - never silently prints prose to a machine. Close the
gaps: `gurgl.explain/1`, `gurgl.doctor/1`, `gurgl.ack-list/1`, and a
`gurgl.capture/1` end-of-`watch` summary. `allow` stays deliberately text-only
(its output *is* the machine format for an enforcement engine; the opensnitch
variant is already JSON) and **errors** under `--json` instead of masquerading;
`ack` add/remove and `discover --import` likewise refuse under `--json` (mutations
are human decisions). Ship `docs/AGENTS.md` (the exit-code contract, the `--json`
schema table, the vet-before-install loop, and the hard vocabulary rule: a quiet
result is "no new stable hosts observed under this flight plan", never
safe/clean/verified/passed) and an in-repo `skills/gurgl/SKILL.md` a Claude-Code
harness can copy into `~/.claude/skills/`, with the forbidden vocabulary and the
never-auto-ack / never-auto-accept / read-PUBLISHING-before-export rules baked in.

**Files.** `main.rs`: `--json` branches for `explain`/`doctor`/`ack --list`/
`watch`, refactoring `doctor`'s ad-hoc closures into a `Vec<DoctorCheck>` and
`watch`'s `drift_lines: Vec<String>` into structured per-server records - both
rendered to text (byte-identical to today) *or* JSON from the same structs, so
they can't drift apart. `cli.rs`: update the `--json` coverage doc + the refusal
rule. New `docs/AGENTS.md`, `skills/gurgl/SKILL.md`, a `docs/RECIPES.md`
agent-harness gate section, and `tests/json_surface.rs` (every read command's
`--json` parses and carries `schema` + `note`; `allow`/`ack`-mutation under
`--json` exit 2 with empty stdout).

**Risk to flag.** The `cmd_watch` refactor is the one place this touches live-
capture control flow (Ctrl-C partial batches, the zero-captures bail, the
dashboard). Mitigation: force `Mode::Plain` under `--json`, emit the JSON object
only at the two `Ok` returns (exit 0/1) never on bail, keep exit-code logic
untouched, golden-diff the text output before/after, and live-test Ctrl-C
mid-battery in both modes.

**Schema.** Four additive versioned schemas, each carrying the epistemic caveat in
`note`; no existing schema changes shape. The deliberate behavior change is that
`--json` with `allow`/`ack`-mutation becomes a loud exit-2 refusal instead of
silently printing non-JSON - anyone wrapping gurgl with a blanket `--json` sees
the error. Zero new deps.

**Constraint check.** #1/#2: every schema's `note` carries the presence-only
caveat; `doctor` statuses are machine-readiness coverage, never tool-safety
verdicts; `AGENTS.md`/`SKILL.md` hard-code the forbidden vocabulary with approved
phrasing to quote. #3: `gurgl.capture/1` drift comes from the existing
`drift_hosts` (excludes intermittent, honors acks); `explain` serializes
reproducibility with the "not a finding" story. #5: pure docs + JSON rendering, no
network surface; the skill forbids the agent fetching anything on gurgl's behalf.
Publishing (#7): `SKILL.md` requires the human to read `docs/PUBLISHING.md` before
any export that names a third party.

**Effort:** L. **Depends on:** lands last - `AGENTS.md`'s schema table documents
`gurgl.event/1` (item 4) and the finished command surface (items 1-3), so it
should describe an already-shipped surface.

### Why this order

Capture fidelity (1) and the version label (2) are the two honesty foundations:
until forced capture lands, a quiet capture is soft for any client that ignores
proxy env, and until the version comes from the installed package, the storage key
is attacker-chosen. Everything else *reports on* captures, so it is worth exactly
as much as those foundations. `plan` (3) generates something you then capture
under, so it sequences behind capture maturity and shares `build_argv` with 1b.
The machine surface splits: NDJSON events (4) before the agent-native umbrella (5)
because `AGENTS.md`'s schema table must document an already-shipped
`gurgl.event/1`, and both edit the same `cmd_watch`/`cmd_diff` drift code. Slice
1a is carved out precisely so the honest-labeling win ships even if the XL netns
spike stalls.

### What we deliberately did NOT pursue now

**Deferred** (real, but not now - revisit when the five above have landed and
earned it): a real least-privilege macOS Seatbelt profile; broader MCP-client
discovery; capture-in-CI; new emit targets; a read-only `gurgl mcp` server;
generalizing the harness beyond MCP; the pure-Rust `hudsucker` MITM backend (still
a v2 catalog note - it removes the mitmdump runtime dep but changes nothing about
what gurgl observes).

**Refused** (categorical, not a backlog): a live session monitor; any hosted gurgl
endpoint; enterprise SaaS, central management, or "compliance attestation". These
violate the non-negotiables (#1, #5) and the deliberate ceiling below, and no
market pressure changes that.

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
