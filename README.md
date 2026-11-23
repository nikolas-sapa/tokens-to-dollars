# tokens→dollars

Convert LLM tokens into bounty dollars.

An open, harness-agnostic skill-pack + CLI that turns agent token spend into
validated, submission-ready bug bounty reports. The fleet hunts, proves, and
writes the PoC — you review and hit submit.

```
$4–25   cost per exploit attempt (published multi-agent results)
$1,090  average HackerOne bounty
$3,000  median critical payout (web2)
$20,000 median critical payout (Immunefi)
```

At even a 1–5% submit→paid conversion, payouts clear token costs by 10–100×.
That is the whole premise — and the repo carries the scoreboard to prove or
disprove it on your own runs.

## What this is

Not another agent runtime. Strix, ARTEX, Shannon, XBOW already hunt. The gap
nobody owns is the **bounty economics layer**: knowing which program to hit,
what its rules actually allow, whether the bug is already disclosed, what that
platform's triagers reject on sight, and what the run cost you.

This repo is that layer, packaged as skills (`SKILL.md`, works in Devin /
Claude Code / Codex / any skills-compatible agent) plus a thin set of ingest
tools. Bring your own harness and model.

## The three layers

**`skills/` — the fleet's brain**

| Skill | Job |
|---|---|
| `orchestrator` | ARTEX-style planner/worker loop on a persistent dual graph: asset graph (what exists) + exploration graph (what we tried/learned), worker trace sharing, cross-engagement learning ledger |
| `hunt` | 11 proven playbooks (GraphQL takeover, race conditions, SAML/OAuth confusion, HTML-to-PDF SSRF, AI-agent tool abuse, DeFi scoping...) with methods, gates, evidence rules |
| `scope-parser` | Program policy page → machine-enforced rules-of-engagement manifest. Nothing in scope = denied by default |
| `dedupe-check` | Is this bug already disclosed? Checks hacktivity, public corpora, CVE/GHSA, changelogs before you waste a submission |
| `reporter` | Platform-calibrated report drafts + the always-rejected list (self-XSS, missing SPF, best-practice findings) |
| `evidence` | "If it isn't recorded, it didn't happen" — req/resp capture, redaction, PoC norms |
| `safety-gates` | G0–G3 authorization gates, rate limits, stop conditions. A program's policy can only tighten these |
| `coverage-ledger` | Fleet anti-collision: parallel workers claim surfaces, don't duplicate |
| `injection-defense` | Hostile web content is data, never instructions — hardening for agents that browse targets |
| `token-ledger` | The scoreboard: $-per-intent spend → findings → payouts, cost-per-finding per technique/model |

**`tools/` — the data layer**

| Tool | Job |
|---|---|
| `ingest-scope` | Nightly pull of 6 bounty platforms' scope feeds (arkadiyt, lissy93, diodb, Immunefi) → ranked program catalog with RoE fields |
| `ingest-knowledge` | Pulls payout-labeled disclosed-report corpora (10k+ reports) for RAG/few-shot priming |
| `wrap` | Thin adapters around the atomic tools hunters actually use (subfinder, httpx, nuclei, katana, trufflehog, ffuf, Burp MCP) — wrap, never reinvent |

**`evals/` — receipts, not vibes**

| Harness | Proves |
|---|---|
| `bountybench` | Stanford's dollar-mapped benchmark: 40 real bounties, $10–$30,485 — the canonical "tokens→dollars" scoreboard |
| `fprate` | False-positive rate under our gates. Baseline to beat: an agent that flagged 105 "CONFIRMED" vulns earned $0; gated + adversarially reviewed it earned $1,100 |

## Quickstart

```bash
# 1. Pull today's program catalog (scope + payout data, ~4 keyless feeds)
python3 tools/ingest-scope/ingest_scope.py --out-dir data/programs

# 2. Seed the knowledge base (10k+ disclosed reports, payout-labeled)
python3 tools/ingest-knowledge/ingest_knowledge.py --out-dir knowledge/

# 3. Point your agent harness at skills/ — e.g. Devin/Claude Code/Codex
#    reads skills/*/SKILL.md automatically. Start a hunt:
#    "Hunt <program> under the orchestrator skill."
```

The orchestrator wakes, loads program memory, parses the RoE manifest,
dispatches intent after intent to workers, and writes every dollar spent and
found into `memory/ledger.md`.

## The honest part

- **A human always submits.** Fully-autonomous submission violates platform
  policy (HackerOne's "hackbots" guidance explicitly requires human review —
  the same constraint XBOW operates under). Agents find, validate, and draft;
  you decide.
- **Programs differ on automation.** Some ban unvalidated AI output, some
  welcome it with rate caps. `scope-parser` reads each program's actual
  policy and enforces it. Testing outside the manifest is not a bug, it's
  the design.
- **AI slop is the enemy.** Platforms are drowning in unvalidated AI reports —
  some programs have shut down over it. This repo's validation gates
  (deterministic checks, >80% confidence, executed PoC, dedupe pass) exist
  so you're on the right side of that line.
- **Payouts are power-law.** The math above is EV, not a promise. Most
  hunts burn tokens; the ledger keeps you honest about your own numbers.

## Why now

The economics crossed over in the last two years: published multi-agent
systems exploit real vulnerabilities for single-digit dollars per attempt,
payouts grew to $80M+/year on HackerOne alone, and one autonomous system hit
#1 on the US leaderboard with ~1,060 submissions in 90 days. The winners will
be the fleets that waste the fewest tokens on false positives and dead
programs — that is an economics problem, and economics problems deserve an
open scoreboard.

## Status

Early. Skills + ingest pipelines first; wrappers and eval CI next.
See `plan.md` for the roadmap and `findings.md` for the research behind it.

## Responsible use

Read `docs/responsible-use.md` before pointing this at anything. Authorization
gates are load-bearing — removing them makes the tool worse, not freer.
`docs/threat-model.md` explains why they exist.

## License

Apache-2.0. Bug writeup corpora referenced by ingest tools remain the property
of their authors — mirror internally, don't redistribute.
