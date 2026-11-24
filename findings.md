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


## Wave 6b — ARTEX source mining (local clone ~/ARTEX, horizonl fork of Autumn-27/artex, norma v0.4.3)

80 mechanisms mapped. Fork delta = Unreleased changelog: notify pipeline + 11-bug security audit + v3 delete-path rule.

Ported (wave 7b):
- assess.sh attestation->auto-lock flow concept -> wrap [platform-deny] prefix on policy denials
- minimal-scope rules (hostname->subdomain, deny-on-doubt, self-contained constraints) -> scope-parser
- worker minimal tool surface + system-prompt mandate anchoring -> worker-roster
- deny-list porosity admission (v1 missed GET-to-delete; ambiguous=>ask) -> coverage-ledger
- bounded index renderer (per-section caps + paired totals) -> consolidate.py
- retry tiers/quota classifier/breaker ladder constants -> token-ledger reference
- evidence staging->rename+GC grace -> evidence-store note (if non-atomic)

Noted, deferred:
- notify outbox same-tx + lease delivery + the fork's 11-bug notify audit (masked-secret resubmission, per-outlet escaping, dial-stage SSRF, url.Error token strip, presence-defaults, batch-poisoning) — checklist for when we build notifications
- intercept re-read-after-register race fix + decision_source rule|model|unknown
- intent admission rollback (DiscardOpenIntent), delete barriers, persisted queue holds — coverage SQLite covers semantics
- cross-task overview rune-ledger + one-hop inheritance caps (48000/8000 runes) — for memory/index tier at scale
- api-recon skill: mock-not-login pattern, >100KB bundle prohibition, grep|head + wc-l verify — candidate reference for browser worker
- platform-deny message framing: 【platform-control·not-target-defense】concept ported as [platform-deny]

Cautionary patterns confirmed from source: regex deny-lists on raw tool_input are porous by construction; exfil-pipe heuristics ship disabled due to real FPs; an open MITM proxy on 0.0.0.0 = open relay (theirs binds loopback only).


## Wave 8 — external deep-research report (Nov 23, 2026) key deltas

Report confirmed core design (deterministic validators, human-gated submit, tiered models) and added numbers:

**Platform enforcement (Oct 2026):** H1 Signal slider -1..7 + 3-trial->90d pause; Bugcrowd IDV+CAPTCHA+6/wk@<50% acc; Intigriti IDV@submission + mandatory AI disclosure; YWH credits refund+bonus; Immunefi bans AI-written reports outright (KYC pre-payout); Signal math: Resolved+7, dup-prepublic +2, dup-postpublic -5, N/A -5, Spam -10.

**Validator primitives:** OAST token (preamble+nonce, bare pingback=Informative), DOM oracle at target origin, canary planting, dual-connection desync (90-95% naive claims are pipelining FPs), multi-role differential, incremental per-link validation, impact-escalation (severity = demonstrated not plausible).

**Dedup:** 4-view (Desc/Repro/Loc/Impact) + path-normalization ~90% dup elimination; Coinbase attrition 44% dup/37% info/15% invalid/4% paid.

**EV model:** EV = p_find*prec*(1-r_dup)*(1-r_info)*B_ref - (C_scan + p_find*C_HITL). Class priors: XSS $635 saturated (78-82% hackbot volume), IDOR $1,265, AI-target $15k-172k (whitespace: ~12% of AI firms run programs), Immunefi critical median $20k. Tiers: $0.10/$1/$10/$100 per task. Supply elasticity: bounty cuts -> -22% valid reports.

**Defense:** bidirectional unicode strip (we have inbound, needed egress), MCP schema-hash pinning (rug pull), Guardian-model concept (independent action adjudicator blind to justification), external-image/link stripping in egress.

**Corpus adds (queued):** huntr AI/ML bugs, Solodit API (web3 findings, 10k/day), MegaVul/PrimeVul (cleaner vuln+patch vs ARVO), MoreFixes/CVEfixes.

**Report-writing:** raw HTTP+script pair (Intigriti), direct-upload only (3rd-party hosting = CoC violation), NMI speed matters (Google 1.2x needs <3-day precise replies), per-platform schemas encoded.

**Caution data:** static CTF inflation 2.2-2.4x (memorization); failed runs burn 3.4-5.8x more tokens; XBOW #1 masked <$40K payouts; Kroda plain-Codex nearly matches scaffolded agents (moat is validation+policy+economics, not orchestration complexity).


## Wave 10 — coordination/memory/eval/economics reports (Nov 23, 2026) deltas

Confirmed (no build): dual-graph+pheromone blackboard, fenced claims, hash-chained audit ≈ Temporal event-history, guardian ≈ ScopeJudge, council-verify read-only (debate+tools amplifies attacks — MADBench 11/12), fact-verify ≈ NeuroSploit evidence-grounding, trust-tiered promotion ≈ 3-zone IFC.

Key data encoded wave 10:
- MAST taxonomy (1642 traces): step repetition 17%, reasoning-action mismatch 13%, termination 12% -> step-repetition detector added (stall counter covered only no-new-facts).
- MAPTA early-stop: ~40 calls / $0.30 / 300s per hypothesis; failed runs 3.4-5.8x cost -> per-intent defaults.
- Beta-Bernoulli yield: prior Beta(.5,9.5), 180d half-life, LCB90 score, 75-80/20-25 exploit/explore -> replaces naive hit-rate (1/1=0.136 vs 6/20=0.217 posterior).
- Stake math: staked submit requires p > S/(B+S); Sherlock 250 USDC/$5k -> 4.8%; >=20% Issues Ratio floors; Immunefi pay-to-submit $25-100 + credits (forfeit on invalid/slop).
- Reserve-settle: worst-case = (est_in + max_out)*1.1, atomic check, integer micro-dollars, TTL sweep.
- Verifier-canary: 4 adversarial outputs (null/random/injection/tampered) through real gates — null must fail (Berkeley RDI: conftest hack, curl trojan, out-of-sandbox grading).
- Planner-brief funnel: hard-filter -> tag/BM25 RRF -> LCB90 score -> coverage-pack + model-tier top-k; skill lifecycle: version_bounds/last_verified_at/in-place revision/active->archived.
- MDASH: patch-offer in reporter (55/99 merged, remediation = bottleneck).

Notable intel (findings only):
- Graphiti invalidation bugs (#1728: 41% retired/75% false; #1970 crowding) -> validates deterministic supersession over LLM contradiction judges.
- Single strong agent ≈ fleet on tight tasks (Kroda, single-Bedrock 84.6%); fleet wins on breadth/parallel (Anthropic +90.2% research eval at 15x tokens) -> fleet only where parallel discovery pays.
- 10/12 OSS pentest harnesses sandbox-escapable; 36.7% MCP servers SSRF-vulnerable; LiteLLM PyPI compromise -> pin digests.
- Attribution blindness 53.5%/14.2% -> decided_by + lineage already covers.
- Economics verdict: hybrid human+agent high-severity = only verified positive $/compute (XBOW Chrome 6.25x gross); fully-autonomous everything else = negative (Olas -19.2%, Circadian $0.62/day); audit contests collapsed ($14.20/sub actual).
- curl lesson: removing cash removed slop, validity rebounded -> quality gates beat AI bans; GitHub VIP tier + 4-sub caps = signal moats.


## Wave 11 — 8-lane research sweep (Nov 23, 2026) deltas

**Session-broker** (Thacker/XBOW/Strix): vault holds creds+TOTP seeds, broker holds live tokens + re-auth, injection proxy stamps auth at egress — workers NEVER see secrets (the 80%-token-waste fix). Build as session-broker tool.

**PB-2 AI-target**: Google tiers $20k rogue/$15k exfil, MS Copilot $250-30k (0-click x-user exfil=Critical), OpenAI ≤$172k (1-click ATO $51,577), 0DIN $5-15k execute. Primitives: canary+OAST exfil proof, CSP laundering (blob.core/teams/googleusercontent), ref-style markdown bypass, invisible-text channels, memory pollution. FP rules: self-injection, prompt-leak-only, hallucination-no-effect, sandbox-intended-exec, victim-config, MS "no security impact".

**PB-12 IDOR**: second-identifier swap (path validated, body/header trusted), GID base64 decode+increment, cross-tenant headers (X-User-Id/X-Account-Id/X-Forwarded-User), alias-batch 200 objs/req, GraphQL nested re-check bypass. Kill-list: CDN cache 200, public-by-design, self-IDOR, 404-masking, empty-soft-fail, seq-ID-public-only. UUID IDOR = valid if obtainable. Response table: 200+B data=IDOR, 200+A=hunt 2nd param, 403=enforced, 404=masked?, 200-empty=soft-fail.

**PB-13 desync**: 0.CL+early-response gadgets, parser-discrepancy (H-V/H-T primitives), dual-CL/multipart/byteranges/TE-gzip triggers, dangling-byte RQP, Shared-Parser Confusion, client-side desync. Kettle: ~700 vulns across authorized sites, $200k/2wk. Cache: entanglement (normalized keyed comps), Akamai key-leak headers, persisted_on_clean proof mandatory.

**Web3/PB-10**: post-launch pays $20k median crit, 10%-of-funds-at-risk (capped, floored ~$25-50k), Foundry/Hardhat fork PoC mandatory (inline or gist), deployed>repo, ANY live tx = permaban. Fees: Immunefi $25 + Credits refund; Cantina $5-100 deposits; Sherlock $250 stake (52% hit rate). KYC 87/154.

**Radar EV**: use avg_bounty not max; bounty_velocity=paid_90d/reports_90d; competition via hackers_thanked; time_to_bounty lag; informative_rate; fresh<48h boost; scope_breadth (wildcards, auth surface); invite_only+; dup-prone-.

**Sources**: BUILD algora/opire keyless APIs, sherlock contests, bbscope /updates, YWH/Intigriti JWT APIs, diodb offers_bounty+policy_url_status harvest, securitytxt parser (Expires=dead flag), lookup.disclose.io client, PD public-bbp list. KILL: polar (dead), federacy (dead), issuehunt (stale), c4 (wind-down), hackerhive (dead).

**change-detect**: kind tags js|schema|changelog|fingerprint; poll-ct (crt.sh); poll-feed keyword gate (auth|payment|admin|oauth|upload|billing|permission); signal→action table; scope-diff in ingest-scope; don't wake on content-only diffs.

**Recon**: add wraps gau/waybackurls/arjun/x8/subzy/wafw00f/naabu-passive; asset-graph fields (subdomain source+ips+cdn+takeover-fp, service proto+banner+tls, app tech+favicon_mmh3+waf, endpoint methods+params+auth_required+state_changing); CT monitoring new-subdomain trigger; OOS-neighbor leads.

**Dedupe**: informative_rate from hacktivity; informative-prone scopes deprioritized; Intigriti informative=neutral.


## Wave 12 — production-systems audit (Nov 2026) deltas

**The moat, empirically settled**: model scale ≠ results. ToB 2nd at AIxCC on non-reasoning models; Tenzai #1 H1 Q3 on open-weight GLM 5.2 (3.5% FP, -30% cost vs Opus 4.6); AISLE 6 curl CVEs where Mythos+Codex got 0; Anthropic 55.9% reject on un-triaged OSS scanner. Deterministic oracle + externalized scope + triage quality = the whole game. Our architecture bets confirmed.

**New mechanisms to encode:**
- patch-hunter: diff/commit-seeded variant analysis (Big Sleep; KNighter 30 CVEs; CopyFail 9yr bug in 1hr from 2-line prompt). PatchSlop: 3.2% of kernel CVEs are introduced by prior fix commits — every fix commit is a hunt seed.
- Verifier funnel: cheap score → top-20% agent verify (RoboDuck $0.001→$0.50/report); cache validated Input Encoders; race parallel attempts, kill siblings on first success.
- Failure taxonomy log (unreachable path | missing precondition | wrong build config | insufficient control) → feeds consolidate yield scoring (FORGE RL-loop analog).
- Blackboard: persist disproven paths (not just findings); rejected PoC → hard search constraint for next wave (Sangfor evidence graph).
- Dedupe: +AST structural view (~45% dup cut pre-PoC, FORGE).
- Reporter: severity discount (AI claims inflate 91.5%→51.3% maintainer-confirmed; downrate unless proof is strong); auto-WAF-mitigation section (Tenzai/Terra); security-vs-ordinary-bug framing mandatory (the post-slop failure class — accurate reports that misjudge security impact); repro script + screenshot proof artifacts (Tenzai standard).
- Guardian: Harmless-Mode action classes — real-time block file writes/deletes/tunneling/DoS/persistence/brute-force.
- Evals: report-content injection (H1 #2372363 — invisible injection hijacked triage agent severity); scope-bait fixture (360's scraped-URL slip).
- Orchestrator: GUI-conditional bugs route to human (ARTEMIS: all agents missed web-GUI RCE 80% of humans caught); dual-line taint (forward+reverse) in source-audit.
- Meta: exploit_agent in the wild (GTIG Nov 2026) = patch-diff→exploit is now a race; speed post-disclosure matters. Attribution hygiene: only 2/2,544 CVEs use TOOL credit type — keep claims honest (tiers: direct credit > audited ledger > human-tandem > vendor claim).


## Wave 13 — ARTEX fork-ecosystem + production-agent audit deltas

**Fencing/leases**: ARTEX claim-lease = 15s heartbeat / 90s TTL / owner-token — stale workers cannot overwrite. Encode in blackboard claim protocol.
**Noise governor**: target-noise pacing at proxy layer (per-host req budget); v0.7.0 fixed bypass by pacing Bash at recording proxy via userinfo markers — pacing must live in the egress path, not worker discipline.
**Judge must not fail open**: ARTEX LLM judge evaluated isolated tool calls, never generated scripts → silent deletes shipped with zero denials. Guardian must inspect generated payloads/scripts, and fail-closed (already does).
**Hash-chained decisions + L1/L2/L3 policy tiers** (br0ny4 fork): every allow/deny logged tamper-evident.
**Hierarchical budgets + wrap-up reserve**: reserve tokens for final settlement/report, not just per-step caps.
**Nonce envelope**: per-message nonce isolating target-derived data → injection boundary marker (EchoLeak-class).
**Retest workflow**: 2-min manual retest preserves historical evidence + marks patched state — remediation retest loop.
**Deterministic code owns scope/leases/receipts, not LLM** (PentestGPT 2026 rewrite — the convergent answer; also eBPF/nftables egress as true containment).
**Defaults shipped unsafe**: ARTEX = unlimited timeouts, capture off, judge off, fail-open. Our default must be the hardened config.
**Strix**: 90% sub-agent stop rule (graduated spend reserve). Shannon: no-exploit-no-report gate (have). Hydra effect: 444+ tracked copies after takedown — deletion ≠ containment.
**Community-db gap**: no mature user-submitted bounty-program database (diodb/arkadiyt = curated feeds, not crowdsourced submissions). Buildable.
