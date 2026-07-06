# Threat model - what gurgl can and cannot see

Read this before trusting any gurgl output. The limits below are not bugs to be
fixed later; they are properties of observing egress at the network layer, and
they define the honest scope of the tool.

## What gurgl observes

- The **DNS host names** an MCP server contacts, captured by routing its TLS
  through a local proxy (`mitmdump`) whose lab CA the sandboxed server trusts.
- Aggregated over **N repeated trials** under a fixed **flight plan**, so
  server-side cohort/feature-gate variability can be separated from stable
  behavior (the *reproduction gate*).

That's it. Host names, reproducibly, under a scripted workload.

## What gurgl catches well

- **New-host drift on update.** A server that was benign at v1.2 and, at v1.3,
  begins contacting a host it never used before. This is the common shape of
  real MCP supply-chain abuse (rug pulls, injected postinstall beacons), and a
  version diff surfaces it directly.
- **Baseline footprint.** A concrete, reviewable list of who a tool talks to,
  which most users have never actually seen for the MCP servers they install.
- **Allowlist generation.** Turning observed behavior into least-privilege
  domain rules that shrink blast radius in a real enforcement engine.

## What gurgl CANNOT catch (the honest part)

### 1. Exfiltration over an already-trusted host
If a malicious server sends your data out *through a host it legitimately uses*,
gurgl sees only that trusted host and nothing looks new.

**Worked example - postmark-mcp.** The malicious version added a hardcoded BCC
to an attacker's address. But the email was still sent via `api.postmarkapp.com`
 -  the *legitimate* Postmark API. The MCP server's own egress was **unchanged**;
Postmark did the delivery to the attacker. gurgl would have shown `postmark-mcp`
talking only to `api.postmarkapp.com`, exactly as before. **gurgl would not have
caught postmark-mcp.** This is the same "trusted channel" wall that sinks
IP/destination-based detection generally, and it is why gurgl does not claim to
detect exfiltration.

### 2. Anything server-side
Retention, training on your data, resale, or forwarding that happens *after* the
bytes reach a legitimate endpoint are invisible to any local network observer.
gurgl cannot verify "we don't train on your code." Do not let it imply it can.

### 3. Content
gurgl records hosts, not payloads. It cannot tell you *what* was sent to a host  - 
only that the host was contacted.

### 4. Absence
The flight plan exercises a small, fixed slice of behavior. A host reached only
under a condition the plan never triggers (a specific tool call, a crash
uploader, an error path, a paste of a URL) simply won't appear. So gurgl can
say "observed contacting X" but never "only ever contacts X." Absence in a
capture is **non-coverage**, not a clean bill of health.

### 5. Agreement with someone else's capture
`gurgl diff --against` compares your capture to a **shared capture** from someone
else. Matching it proves nothing. A shared capture is one observer's
presence-only sample under *their* flight plan - it is not a vetted or known-good
reference, it inherits every limit above (a match is still blind to trusted-channel
exfiltration and server-side behavior), and it may itself have *missed* a host
under its own plan or - since it is a file a stranger authored - been curated to
hide or invent one. gurgl therefore treats a shared capture as untrusted input and
never lets `--against` gate (no `--check`, exit `0`/`2` only): overlap is not
verification, and a clean comparison is not a pass.

## Fidelity caveats (things that can make a reading wrong)

- **Server-side feature gates / A-B cohorts.** The same version can contact
  different edge hosts on different runs. Mitigation: the reproduction gate  - 
  only hosts present in *every* trial are `Stable`/reportable. Single-run
  "drift" is never a finding.
- **Proxy fingerprinting.** A client that detects it's behind a proxy can serve
  different behavior. What you observe is what the tool did *knowing it might be
  observed*; note this per target when known.
- **Non-HTTP / pinned transports.** v1 CLI targets ship documented custom-CA
  support (enterprises demand TLS inspection), so capture works; but arbitrary
  long-tail MCP servers may pin or use non-HTTP transports and fall outside
  capture. Mark coverage gaps honestly rather than reporting silence as safety.
- **Version label vs a tampering installer.** gurgl labels a capture with the
  version the launcher actually *installed* (read from the package's own
  `package.json` / `*.dist-info` inside the sandbox), not the server's
  self-reported `serverInfo.version` - which is attacker-chosen, so a package can
  self-report `0.2.0` while installing as `2026.7.4`. That discrepancy is
  surfaced, and the installed value is the storage key. But those files are
  written by the package's own install, so a hostile postinstall could rewrite
  its own version: the derived version is resistant to a lying *server*, not
  tamper-proof against a malicious *installer*. It is read after teardown, so no
  live process races the read.

## Capture fidelity

Env-proxy capture needs **two** things from the client, and gurgl injects both
into the sandboxed server's environment (never into a system store): the client
must **route** through the proxy (`HTTPS_PROXY`) and must **trust** gurgl's lab
CA (`NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE` / ...). A client that ignores either
is not captured. This was measured, not assumed:

| Client | Routes through proxy? | Trusts CA? | Captured? |
|--------|-----------------------|------------|-----------|
| curl | `HTTPS_PROXY` yes | `SSL_CERT_FILE`/`CURL_CA_BUNDLE` yes | yes |
| Linux `python3` (urllib/requests) | `HTTPS_PROXY` yes | `SSL_CERT_FILE` yes | yes |
| Node 24+ (`https`, `fetch`) | **only with `NODE_USE_ENV_PROXY=1`** | `NODE_EXTRA_CA_CERTS` yes | yes (gurgl sets that flag) |
| Node without the flag | ignores `HTTPS_PROXY` | - | **no - bypasses the proxy** |
| macOS system `/usr/bin/python3` | `HTTPS_PROXY` yes | ignores `SSL_CERT_FILE` | **no - TLS verify fails** |

Two verified gotchas worth stating plainly:

- **Node ignores proxy env vars by default.** Both `https.get` and `fetch`
  connect *directly*, bypassing the proxy, so gurgl would see nothing. Node 24
  added `NODE_USE_ENV_PROXY=1`, which makes its core http/https client and fetch
  honor `HTTPS_PROXY`; gurgl sets it, so Node 24+ MCP servers are captured. On
  older Node, or with a library that sets its own agent, egress still bypasses.
- **The macOS system Python (3.9, LibreSSL) ignores `SSL_CERT_FILE`,** so a
  server run under `/usr/bin/python3` fails the TLS handshake to the proxy and
  captures zero hosts. Use a Python that honors the CA env (python.org / certifi).

A client that opens raw sockets or pins its certificate also escapes capture.
The tracked hardening step (network namespace + transparent redirect) forces
*routing* for everyone, but trust still requires the CA. Report coverage gaps
honestly rather than reading silence as safety.

## The one-line summary to keep in your head

> gurgl reduces blast radius and catches *new-destination* drift on the tools
> you install. It does **not** detect clever exfiltration, does **not** see
> server-side behavior, and does **not** certify anything as safe.
