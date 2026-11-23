# Threat Model — why the gates exist

## What we're defending against

**1. The fleet being used outside authorization.**
Agentic security tools are dual-use. In 2026 a multi-agent pentest system
(ARTEX) was abused in the wild by threat actors and the upstream repo was
removed — an FBI FLASH and GTIC reporting documented the misuse. The lesson
this repo takes: *a capability without an authorization boundary is a
liability with a star count*. Every intent carries a gate (G0–G3); nothing
dispatches above its authorized gate; per-program RoE manifests can only
tighten, never loosen.

**2. The fleet flooding platforms with slop.**
AI-generated garbage reports are an active ecosystem problem — platform
report volume doubled, triagers are overwhelmed, and some programs shut down
entirely. Controls: validation gates before any draft, always-rejected list,
dedupe checking, human-in-the-loop submission, honest FP-rate scoreboard in
`evals/`.

**3. The fleet being steered by its targets.**
A hunting agent reads hostile content — error pages, JS bundles, even
writeups — that can carry injected instructions. `skills/injection-defense`
treats all fetched content as data: it can never change scope, gates, or
behavior, and instruction-like strings become warning nodes, not actions.

**4. The fleet exfiltrating what it finds.**
Secrets and user data encountered during testing are evidence, not loot.
Rules: own-test-account credentials only; real user data stops the test and
gets redacted; evidence dirs are append-once with integrity rules
(`skills/evidence`); memory is audit-able (corrections are struck through,
dated — never silent overwrites).

**5. The fleet overspending.**
Tokens are the input cost of the business model — a runaway worker is a
burn rate, not a bug. `skills/token-ledger` records every intent's spend,
and intents can carry explicit cost ceilings the planner enforces.

## Trust boundaries

| Boundary | Rule |
|---|---|
| Target content → agent | Data only; `injection-defense` rules apply |
| Agent → platform | Human-reviewed draft only; never auto-submit |
| Worker → memory | Append/anchored facts only; orchestrator dedupes |
| Manifest → gates | Can tighten, never loosen; memory never authorizes |

## Out of scope (for the repo)

- We cannot stop someone forking and ripping out the gates — same as any
  open tool. We can make the gates the documented, default, load-bearing
  path, and we do.
- Platform-side enforcement (rate limiting, program bans) belongs to the
  platforms; our job is to stay well inside what they permit.

## Prompt-vs-code enforcement

Honest accounting: the skills in this repo are prose. Mechanical
enforcement exists only at tool dispatch — `tools/wrap/wrap.py`'s
manifest gate refuses out-of-scope targets before the binary runs, the
audit chain (`tools/audit-log`) keeps the record tamper-evident, and the
evidence store (`tools/evidence-store`) enforces append-once writes.
Every other gate — G0–G3 escalation, fenced semantics, settlement,
human-submits — is convention: a misbehaving or injected worker issuing
tool calls directly could bypass it, and nothing at runtime would stop
the call. The mitigation ladder is (1) harness-level hooks —
PreToolUse-style checks that run the manifest gate on every dispatch,
wrapped or not — the next hardening step, and (2) fleet-level monitoring
for gate-skips in the audit log. ARTEX is the standing lesson: its
safety gates lived at prompt level, and prompt-level gates are exactly
what its abusers walked around.
