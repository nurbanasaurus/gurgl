Review the current working diff (`git diff`) against gurgl's non-negotiable
framing constraints from CLAUDE.md, and report any violations.

Check specifically:

1. **No verification/certification.** Does any new code or output string emit or
   imply "safe", "clean", "verified", or a pass/fail badge for a tool? (The word
   "clean" must not appear in user-facing output.)
2. **Presence only, never absence.** Does any output claim a tool "only"
   contacts a set of hosts, or otherwise treat a capture as complete coverage?
3. **Reproduction gate intact.** Does any path surface `Intermittent` hosts as a
   finding, drift accusation, or allowlist entry? (Only `Stable` hosts may be.)
4. **Hosts, not payloads.** Any new body/content capture? (Not allowed.)
5. **No telemetry.** Any new outbound network call, analytics, or update ping
   from gurgl itself?
6. **Threat-model honesty.** Does anything imply gurgl detects exfiltration or
   sees server-side behavior? (It cannot - docs/THREAT-MODEL.md.)
7. **Publishing gate.** Does the change add a publish/share feature that names
   third parties without following docs/PUBLISHING.md?

For each violation: cite the file:line, quote the offending code/text, and
propose the minimal fix. If clean, say so plainly and note which constraints you
verified.
