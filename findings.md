# Findings — Tokens → Dollars (synthesis of 6 research lanes)

## Competitive field
- **Strix** (usestrix/strix, ~77k★, Apache-2.0) — dominant OSS multi-agent pentester.
  Gaps: no persistent asset graph, no program-scope memory, no bounty economics.
- **ARTEX** (Autumn-27/ARTEX → fork-chaos after upstream deleted Oct 2026, FBI
  FLASH/GTIG writeup, AGPL) — THE reference arch: planner emits intents → workers
  run real tools → dual graph (asset graph + exploration graph) + trace sharing.
  Reputation is toxic; a clean-room bounty-focused rebuild owns the narrative.
  NOTE: we already have a private ARTEX-style orchestrator + full research engine
  (14 workers, PB-1..11 playbooks, G0-G3 gates, 110-check catalogue).
- **XBOW** — closed, $120M+ raised, #1 H1 US leaderboard (~1,060 submissions/90d,
  54 critical). Proven trick: **deterministic non-LLM validators** rejecting FPs;
  human review before submit per H1 policy. Open only: validation-benchmarks.
- Long tail: Shannon (whitebox AGPL), PentAGI (34.7k), PentestGPT (stalled),
  CAI (archived→commercial CSI), Armur-Ai (OSS "XBOW alternative", alpha),
  Neo/RunSybil/ZeroPath/Gecko/Tenzai (closed commercial).
- **BountyBench** (Stanford, Apache-2.0) — 40 real bounties $10–$30,485 with
  dollar-mapped scoring = the canonical "tokens→dollars" eval harness.

## The gap nobody owns
No incumbent combines: OSS clean license + persistent dual-graph memory +
deterministic validation/evidence-bound findings + **bounty-economics loop**
(scope parsing, dedupe vs disclosed, platform-calibrated reports, $-per-token
accounting, BountyBench-style scoreboard).

## Data layers that already exist — ingest, don't build
- Scope: arkadiyt/bounty-targets-data (hourly, 6 platforms, in/out-scope +
  eligible_for_bounty); lissy93/bug-bounties (3k+ programs, excluded_methods,
  safe_harbor, payout_table — best RoE source); diodb (safe harbor); Immunefi
  public API (keyless, maxBounty); YWH/Intigriti keyless APIs; PD Chaos.
- Knowledge (payout-labeled!): bugskill-ai (9,950 H1 reports), ajaysenr
  H1 archive (12,790), reddelexc tops-per-class, Immunefi BugFixReviews,
  code-423n4 findings repos, trickest/cve, vulhub (executable envs).
- Skills to mine: trailofbits/skills (fp-check, variant-analysis,
  audit-context-building, cvss-scoring); awarexone/Agentic-Bug-Hunter (6k★,
  closest existing thing); PentAGI templates; ghostsecurity (deterministic
  tools + thin skill judgment split); 0xN0RMXL 150+ skills + REPORTING/.
- Tools to wrap (never reinvent): subfinder/amass/httpx/dnsx/katana/ffuf/
  nuclei+templates/trufflehog/notify + PortSwigger Burp MCP; hexstrike =
  reference "thin wrapper" pattern.

## Missing skills nobody packaged (our differentiators)
1. Program-policy→machine scope+RoE parser (exclusions, rate caps, safe harbor)
2. Dedup/known-bug check vs disclosed corpora pre-submission
3. Platform-calibrated reporting (what each platform's triagers reject)
4. Evidence packaging standard (req/resp pairs, redaction, PoC format)
5. Fleet coverage ledger (parallel agents don't collide)
6. Injection-hardened hunting (hostile content prompt-injecting the hunter)
7. Hard safety gates (rate limits, "no real user data", depth limits)
8. $-per-token ledger → payout accounting ("the literal tokens-to-dollars board")

## Economics
- Cost: $4–25 per exploit attempt (HPTSA ~$4.39/run; ~$24/successful zero-day;
  UIUC one-day 87% pass@5 @ ~$8.80/exploit). Cybench $0.23–$9.71/task.
- Payouts: H1 avg $1,090, $81–89M/yr, improper-access/XSS/IDOR top categories;
  median critical ~$3k; Immunefi median critical $20k, mean $114k, $10M max.
- EV: at 1–5% submit→paid conversion, payouts clear token costs 10–100×.

## Risks (must be load-bearing in design)
- AI-slop backlash: H1 +100% report volume; CoC holds submitter responsible;
  GitHub requires working PoC; Torvalds on kernel-list AI dupes; programs have
  shut down. → Human-in-the-loop submit is mandatory (H1 "hackbots" policy
  explicitly blesses this; XBOW/CAI both do it).
- Per-program divergence: Visa bans unvalidated AI output / 1 rps; Goldman
  permits AI w/ validation / 60 rps. → Per-program RoE gate is non-negotiable.
- ARTEX precedent: upstream deleted after real abuse → repo must ship
  authorization gates + responsible-use docs as first-class features.
- Power-law payouts: honest EV math, not "get rich" claims.

## Verdict
Build = package the bounty-economics layer + ARTEX-style orchestrator memory
as harness-agnostic skills (SKILL.md standard works in Devin/Claude/Codex) +
thin tool wrappers + ingest pipelines + ledger/scoreboard. Do NOT build a new
agent runtime — that's the crowded part. The wedge is the economics loop and
the missing 9 skills, riding our existing private playbooks.
