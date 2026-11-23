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

## Wave 2 — mining nikolas-sapa's own repos (6 miners, ~24 repos)
Portable artifacts found and integrated:
- toolfence: injection/Unicode regex tables → tools/content-scan +
  injection-defense signatures
- clone-attack-security: strict evidence parser (16KB cap, dup-key, sha256
  binding) → tools/evidence-store
- helm: redact-before-truncate + secret regexes → tools/evidence-store/redact
- x402-bounty-radar: competition scoring + funding classification + scam
  detection + cross-source dedupe → tools/bounty-radar (2nd feed)
- contribot: aipolicy classifier → scope-parser automation verdicts;
  checks/engine (override audit, ethics-never-loosened) → safety-gates
- release-memory-graph-hacks: gap codes + "model may only select facts" +
  SUPERSEDES lineage → evidence/verifier semantics
- genai-summit-hackathon-recon: hash-chained audit log + grounding grader →
  tools/audit-log
- oss-contribution-swarm/orca: exactly-once worker_done, heartbeat, fenced
  claims, safe-failure → orchestrator + coverage-ledger settlement
- resumed-agent-staleness (2,631-run study): provenance tags, CURRENT-value
  phrasing, verification≠protection → orchestrator memory-trust rules
- branch-ai: [D-n] decision nodes → exploration graph
- neatroots: followed-injected-instructions + quote-before-flag →
  injection-defense trace checks
- open-agent-order-evidence: receipt schema (notEstablished[], sha256 links)
  → evidence
- cinder: BUG-REPORT format (CONFIRMED/SUSPECTED, areas-cleared-cleanly) →
  reporter; sanitize.rs → injection-defense render note
- nemocascade: priced-or-silence honesty, escalate-on-verified-failure →
  token-ledger cost rules
- co-train: provider-cost precedence, cached-token upper bound → token-ledger
- sac-capital: calibration (brier_by_band), canonical-JSON commitments,
  DailyBudget → evals + evidence
- sigeval: wilson/two-proportion/holm → evals/fprate real CI gate
- hackathon-skill: install.sh + multi-harness manifests + 134-line MCP shim →
  repo distribution + tools/mcp-server.py
- skillswitch: skillsDirs map → docs/install-matrix.md (manages, not installs)
- grip-browser: injection.py + CDP browser → injection-defense + wrap table
- paraloom-core: real program policy doc → scope-parser fixture
- awesome-mcp-servers: security MCP shortlist → docs/mcp-integrations.md
- agentic-pipeline (SKIP — Postgres violates stdlib), aegis-demo/polpo/
  learn-ml/perch-mcp (SKIP), orca/hermes-agent/openclaw dirs empty locally
  (real content lives in oss-contribution-swarm/orca/)


## Wave 4 — 10-lane research sweep (Nov 2026)

Actionable deltas, ranked:

**Playbook gaps (by $/effort, H1 2025 payout data):**
- PB-12 cross-protocol IDOR/BOLA — IAC+IDOR = $16.4M pools, IDOR 2x $/report vs XSS, deterministic two-account diffing. Highest EV addition.
- PB-13 desync + cache poisoning — low competition (7-solve class), shares PB-4 tooling.
- PB-14 SSTI/server-side injection — PortSwigger #1 technique 2025.
- JWT confusion matrix — fold into PB-8 expansion.

**Skill gaps:**
- scope-parser: add `ai_disclosure` field (Intigriti/PubNub mandate, Goldman pays $50 bonus), `bounty-ineligible` verdict (NodeBB class), platform-ToS as input (Immunefi clickwrap stricter than program pages), optional `submission_cost` (YWH credits, Cantina deposits).
- reporter: expected-vs-actual + environment-asserted gate questions; Intigriti title format; AI-methodology boilerplate block (manifest-driven); video <=2min supplementary-only.
- dedupe-check: `original_state` field — Resolved original => file as regression/new report; differentiation must argue independent-fix + impact-delta.
- disclosure-email: parameterize timeline (P0 norm 90->60->30), `actively_exploited` flag (CRA 24h clock), no-reward-language check.

**Tool gaps:**
- scan.py: tag-block/varsel rules added (wave-4 fix). Remaining: sanitize() doesn't fold confusables; short-base64/hex/rot13 evasion; no egress-side rules (EchoLeak lesson — agent-emitted URLs unchecked).
- ingest-knowledge: add nuclei-templates (12k YAML), trickest/cve, DeFiHackLabs, reddelexc/hackerone-reports (unlicensed—mirror only), ARVO (vuln+patch pairs), code-423n4 org-crawl.
- ingest-scope: harvest unused diodb fields (contact_url/email/pgp_key/timeline) for email channel; scope-change diffs + HuntScore ranking.
- evals: add `evals/injection/` third harness (PINT dataset + jailbreak_llms + agentdojo); cve-bench as BountyBench sibling ($/attempt metric).

**Competitive check:** Claude-BugHunter (18.8k, MIT) covers ~80% of hunt/scope surface; PentaGI 34.9k. Surviving differentiators: payout-side EV ledger, dedupe verdict schema, policy->manifest parsing, cross-harness install, email-disclosure channel. Deterministic scope enforcement now table stakes — position as policy-parser, not allowlist.

**Consensus (load-bearing):** validation deterministic + external to model (XBOW/PortSwigger/Ghost/PD); proof = observed effect on target (OAST/canary/DOM-exec); incremental validation > end-of-run; human validates+submits is unanimous platform floor.


## Wave 6 — ARTEX lineage + systems research (Nov 2026, 6 lanes)

**ARTEX autopsy (why it died, what we already avoid):**
- All ARTEX safety was prompt-level: scope gate ran only at graph-write, judge fail-open, 4-suffix denylist, tools bypassed interception. CrowdStrike traced campaigns through its own graphs.
- Our position: wrap.py manifest gate = enforcement in code; audit chain = tamper-evident; human-submits by design. The gap that remains: gates enforced by code only at tool-dispatch — prompt-level everywhere else (threat-model should acknowledge this).

**Steals ranked (cross-lane, effort/payoff):**
1. Soliloquy check (EnIGMA): grep every [F-n] fact payload against the worker's raw trace before graph write — enforces "raw trace first" mechanically. ~30 lines.
2. POE-graded verified findings (BaaRai): finding=verified only if every evidence quote appears verbatim in stored body. Greppable invariant.
3. Sampled-logprob FP pre-scoring (RoboDuck/AIxCC): rank candidates before ten-gate verification — spend verification budget on top scores.
4. Stall counter → re-plan (Magentic-One): N intents closed with zero new anchored facts => forced replan/escalate. 5 lines in orchestrator §5.
5. Retest stage (Novee/BaaRai retester): Stage 11 — on "fixed" reports, re-run original intent packet; verdicts Still reproducible/Fixed/Cannot confirm.
6. mem0 write-gate + Graphiti validity windows (memory lane): ADD/UPDATE/DELETE/NOOP at append; strikethrough -> (valid from->to|open; superseded_by). Kills monotone memory growth.
7. Trust-tiered promotion (MINJA defense): content-derived notes cannot enter lessons/patterns without anchored finding behind them — one poisoned pattern steers every future target.
8. Council-verify (llm-council): 3-model anonymized ranking at dedupe/verify gate only — bounded cost, kills single-model blind spots.
9. Per-intent cost via proxy keys (LiteLLM/Helicone): converts est-$ e/u rows to provider-reported p; makes budget fail-closed.
10. Browser-worker role (QAX Gatling): 15th roster role — logged-in browser reach for business-logic classes HTTP replay can't hit (PB-3, PB-12).
11. Commit-triggered waves (Aardvark): change-detection worker (JS bundle hash, schema diff) as highest-yield recon trigger; feeds "unfinished chains first".
12. SQLite coverage-ledger: concurrent markdown appends can interleave; keep CLAIM/HEARTBEAT/RELEASE/STEAL semantics, swap backing store.
13. Structured TrajectoryStep JSONL + ghost replay: receipts' replay_of field becomes real; post-hunt review + PoC re-verification.
14. pass^k on fprate corpus: playbook that yields 1/8 runs is noise — reliability metric.
15. Subtask-graded evals + leak-checks (Cybench): partial credit; canary-string leak detection.
16. Egress rules (EchoLeak, from wave 4): agent-emitted URLs resolve against manifest scope — still open.
17. Memory consolidation job (Letta sleep-time): merge dup lessons, recompute yield, flag contradictions between engagements.
18. Index tier for planner briefs (claude-mem): index.md per target; fetch-on-demand detail — needed at 100+ targets.
19. [PRIOR TRACES] mandated sibling-summary (HPTSA): planner fills 2-line outcome digest per prior intent on same surface.
20. decided_by attribution on gates (ARTEX Pro): audit log records human|rule|judge per gate decision.

**Skill/distilled promotion (mythosharness):** patterns.md entries graduate to skills/distilled/<pattern>.md after N confirmations — fleet literally writes its own new skills.

**Monetization lesson:** C4 bot-race paid bots 10% of pool to DEDUPE — dedupe-check is product-shaped. XBOW #1 leaderboard masked <$40K actual payouts — receipts must be dollars, not reputation. Human-validates+submits is the universal surviving pattern (H1 Hackbot, sportsbooks, Immunefi).

**Skip:** contract-net bidding (homogeneous fleet, no info), full decentralization (authorization needs a choke point), Byzantine gossip (<10 workers = cosplay), framework rewrite (LangGraph/CrewAI features would cost the markdown auditability that IS our moat).
