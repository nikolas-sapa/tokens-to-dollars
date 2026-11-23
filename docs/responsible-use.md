# Responsible Use

This repo converts tokens to dollars by helping agents find and prove real
vulnerabilities in **programs that have explicitly invited security testing**.
Everything below is load-bearing — removing it makes you the slop problem the
ecosystem is fighting, and in many jurisdictions it makes you a criminal.

## Authorization first

- Test only assets inside a parsed rules-of-engagement manifest
  (`skills/scope-parser`). Not in the manifest → denied. No exceptions.
- A program's written policy always wins. If the policy bans automated
  scanning, AI-generated reports, specific techniques, or exceeds a rate cap —
  the manifest encodes it and the gates enforce it.
- Safe harbor matters. Programs with safe-harbor language (check diodb and
  the program policy) give you legal cover; programs without it need extra
  care. When in doubt, don't.
- Vulnerability disclosure programs (no bounty) and self-hosted `security.txt`
  programs are valid targets — the rules are the same whether or not money
  is attached.

## The human submits

- Agents find, validate, and draft. A human reviews the evidence, runs the
  dedupe verdict one last time, and hits submit.
- This is not just our preference: HackerOne's automation guidance requires
  hacker-in-the-loop submission, and the same rule is how every serious
  commercial system (XBOW included) operates. Fully-autonomous submission is
  a terms-of-service violation on the major platforms.
- Your account reputation is the asset. Signal score (valid-rate) determines
  whether your future reports get read. Ten great reports beat a hundred
  plausible ones.

## Validation before submission — non-negotiable

A finding may not be drafted for submission until:

1. It is **proven** — the boundary break was executed, not inferred from
   status codes or plausible-looking output.
2. A **deterministic validator** (not the finding agent) reproduced it.
3. A **working PoC** exists — increasingly a hard platform requirement for
   AI-assisted reports.
4. **Dedupe verdict** is clean — checked against program hacktivity, public
   disclosed corpora, CVE/GHSA, and the program's own known-issues list.
5. It is not on the **always-rejected list** (`skills/reporter`) — self-XSS,
   missing SPF/DMARC, best-practice findings, scanner output without exploit.

## Behavior while hunting

- Respect rate caps (manifest or `skills/safety-gates` defaults — many
  programs specify, e.g. 1 rps vs 60 rps).
- Never access, copy, or retain real user data. Proof-of-concept against your
  own test accounts only. If a test surfaces real user data: stop, redact,
  report the exposure path without the data itself.
- No destructive testing, no denial of service, no pivoting beyond the
  demonstrated boundary, no third-party targeting (their providers are
  usually out of scope).
- Stop conditions in `skills/safety-gates` are global — any one firing halts
  the whole engagement, not just the intent.

## If you're here to do harm

This tooling is published for defenders and invited hunters. Testing assets
you are not authorized to test is computer fraud — CFAA (US), Computer Misuse
Act (UK), and equivalents everywhere. The 2026 precedent of a multi-agent
pentest tool being abused in the wild and pulled upstream is exactly why the
authorization gates in this repo are features, not friction. They stay.

## Reporting bugs in this repo

Found a problem with the tooling itself? Normal GitHub issues.
Found a security problem in the tooling? Please disclose privately first —
see SECURITY.md contact.
