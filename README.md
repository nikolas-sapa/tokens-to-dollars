# tokens→dollars

[![npm](https://img.shields.io/npm/v/tokens-to-dollars)](https://www.npmjs.com/package/tokens-to-dollars)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![install](https://img.shields.io/badge/install-npx%20tokens--to--dollars-brightgreen)](#install)

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

External tool servers (Burp, ZAP, Ghidra, live-browser attach) are wired
separately — see `docs/mcp-integrations.md`.

**`evals/` — receipts, not vibes**

| Harness | Proves |
|---|---|
| `bountybench` | Stanford's dollar-mapped benchmark: 40 real bounties, $10–$30,485 — the canonical "tokens→dollars" scoreboard |
| `fprate` | False-positive rate under our gates. Baseline to beat: an agent that flagged 105 "CONFIRMED" vulns earned $0; gated + adversarially reviewed it earned $1,100 |
| `injection` | Prompt-injection survival: hostile fixtures through `tools/content-scan` — attack-success rate, verdict accuracy, utility. Re-run per model/scanner change |

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

## Install

**One command (npm):**

```bash
npx tokens-to-dollars          # interactive setup wizard
# or: npm i -g tokens-to-dollars && t2d setup
```

The wizard asks which agent harnesses get the skills (auto-detected:
claude, codex, cursor, gemini, devin, windsurf, kiro, opencode, factory,
amp — or a custom path), takes optional API keys (`GITHUB_TOKEN` for
bounty-radar extras, `SOLODIT_API_KEY` for the audit corpus), and writes
them to `~/.config/tokens-to-dollars/config.json` (0600, never committed).

```
t2d list                       # detected harnesses + skill dirs
t2d install --only claude      # install into one harness
t2d run ingest-scope/ingest_scope.py --out-dir out/scope
t2d run bounty-radar/bounty_radar.py --rank-programs out/scope/programs.json --out-dir out/radar
```

**From a git clone:**

```bash
./install.sh --list          # which harnesses are detected, and where skills land
./install.sh                 # copy all skills/* into every detected harness
./install.sh --only claude   # or just one (claude|codex|cursor|gemini|devin|windsurf|kiro|opencode|factory|amp)
./install.sh --dry-run       # print what would happen, change nothing
```

Manual fallback for anything else: copy `skills/<name>/` into your harness's
skills dir — each skill is a self-contained directory (`SKILL.md` +
`references/`). Per-harness paths and quirks: `docs/install-matrix.md`.

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

Active development. 15 skills, 17 tools, 14 playbooks, 4 eval harnesses —
see `plan.md` for the roadmap and `findings.md` for the research behind it.
Published on npm as `tokens-to-dollars`.

## Responsible use

Read `docs/responsible-use.md` before pointing this at anything. Authorization
gates are load-bearing — removing them makes the tool worse, not freer.
`docs/threat-model.md` explains why they exist.
`docs/terms-of-use.md` (authorized testing only) and `docs/privacy.md`
(no telemetry, keys stay local) apply to all use and contributions.

## License

Apache-2.0. Bug writeup corpora referenced by ingest tools remain the property
of their authors — mirror internally, don't redistribute.
