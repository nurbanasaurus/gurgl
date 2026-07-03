# Publishing guardrails

gurgl is a personal tool. The moment you publish an observation that **names a
third party** ("`some-mcp`@1.4 contacts `beacon.example`"), you take on legal and
ethical exposure that a private tool never has. These rules are the price of
publishing. They are not optional, and they are deliberately conservative.

If you are not publishing named observations, none of this applies - run the
tool locally and enjoy it.

## Before you publish anything that names a vendor

1. **Form an entity and carry insurance.** Publish through an LLC (or a
   nonprofit association, the Exodus Privacy model), never as a personally
   exposed natural person. Carry media-liability / general-liability insurance
   *before* the first named post. A solo individual with no shield is the worst
   possible defendant.
2. **Understand the precedent.** In *Enigma Software v. Malwarebytes*, a
   security vendor's factual-sounding characterizations of another vendor were
   held to be **actionable statements of fact**, not protected opinion. "I only
   stated facts" is exactly the framing that precedent converts into liability.
   Well-funded companies litigated this for years; a solo publisher cannot.

## How to publish (if you do)

3. **Raw receipts only.** Machine-readable host lists, trial counts, flight-plan
   fingerprint, timestamps. Strip every alarm adjective. Never render
   "undocumented" as "wrongdoing", never a "spyware/malicious/safe/clean" label.
   Let readers draw conclusions; you report what the proxy logged.
4. **Reproduction gate is mandatory for anything published.** Only host sets that
   reproduced across all N trials, with cohort identity pinned. Never publish a
   single-run observation - server-side feature gates will otherwise turn benign
   A-B rollout into a false accusation, which is simultaneously your legal
   trigger and the death of your credibility.
5. **Coordinated pre-disclosure, always.** Notify the vendor/author and give a
   fixed window (e.g. 30-90 days) before any writeup. Publish their response
   alongside your observation. This converts "undocumented endpoint!" into "here
   is the maintainer's explanation" - the single strongest legal *and* ethical
   de-risker.
6. **Never punch down.** The tool's most attention-grabbing findings will tend to
   land on hobbyist/solo MCP authors (the best-documented vendors have the least
   to "catch"). Treat small-maintainer findings as private nudges, not public
   index entries. Do not build or publish a shame ranking of individuals. Your
   only asset is community trust; smearing a volunteer burns it.

## What not to do, ever

- No live "is this tool safe?" verdict service.
- No "verified / certified clean" badges.
- No payload contents in any published artifact.
- No implying gurgl detects exfiltration or sees server-side behavior - it does
  not (docs/THREAT-MODEL.md).

## The honest cost

Following these rules makes published output *less* sensational and *slower* to
build a reputation - the safe version is the boring-receipts version. That is
the correct trade. The reputational upside of being the careful, independent,
never-wrong observer only exists if you are, in fact, careful and never
recklessly wrong.
