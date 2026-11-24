# Reference — Worker Roster

Companion to the `hunt` skill (`../SKILL.md`). The fifteen specialist worker roles: what each covers, the catalogue categories and playbooks it owns, its gate ceiling, and how it claims surfaces via `../../coverage-ledger`.

Workers are dispatched by the orchestrator as intent packets (`../../orchestrator`). Every worker executes exactly one intent at a time, works only the surface it claimed, and returns evidence-backed findings, inconclusive hypotheses, and coverage gaps.

## The roster

| # | Worker | Focus | Owns (checks / playbooks) | Gate ceiling |
|---|--------|-------|---------------------------|--------------|
| 1 | Reconnaissance Researcher | Technologies, public routes, features, services, exposed interfaces; fills the asset graph | Attack-surface inventory, API-01, API-16, API-20, INFRA-02, INFRA-06, INFRA-15 | G1 |
| 2 | Client Asset & Information Exposure Researcher | Publicly served assets, config disclosures, source maps, diagnostic info, exposed sensitive resources | WEB-18, WEB-19, INFRA-08; exposure paths in `exposure-investigation.md` | G1 (G2 to confirm with owned data) |
| 3 | Authentication Researcher | Registration, login, sessions, recovery, MFA, OAuth, SSO, token validation | ID-01–ID-14; PB-5 (SAML), PB-7 (OAuth) | G3 (SAML lifecycle) |
| 4 | Authorization Researcher | Object ownership, role enforcement, cross-account boundaries, cross-tenant isolation, protected operations | AUTH-01–AUTH-12, the authorization matrix | G2 |
| 5 | API Security Researcher | REST, GraphQL, gRPC, WebSockets, webhooks, endpoint permissions, schemas, data exposure | API-01–API-20; PB-1 (GraphQL) | G3 (API-06 batching, API-15 budgets) |
| 6 | Web Input Security Researcher | Input-validation weaknesses, browser security, injection indicators, unsafe rendering, parser risks | WEB-01–WEB-20; PB-6 (CSRF), PB-9 (PDF SSRF) | G3 |
| 7 | Database & Storage Researcher | Publicly observable database permissions, storage access, row-level security, synthetic object isolation | AUTH data-layer checks, INFRA-03, BIZ-10; storage exposure in `exposure-investigation.md` | G2 |
| 8 | Business Logic Researcher | Workflows, financial controls, subscriptions, privileges, quotas, business invariants | BIZ-01–BIZ-12; PB-4 (races) | G3 |
| 9 | Infrastructure Exposure Researcher | Public infrastructure metadata, deployment info, DNS, TLS, hosting config, exposed diagnostics | INFRA-01–INFRA-16 | G3 |
| 10 | Supply Chain & Specialized Systems Researcher | Dependencies, mobile apps, desktop clients, release artifacts | SPEC-01–SPEC-09 | G3 |
| 11 | AI System Security Researcher | AI tool permissions, prompt-injection boundaries, conversation isolation, RAG authorization, cost safeguards | AIX-01–AIX-07; PB-2 (agent tools), PB-3 (captcha-gated agent endpoints) | G3 |
| 12 | Attack-Path Analyst | Correlates proven findings into trust-boundary and impact chains; aggregates individually-low findings into demonstrated chain reports | Attack-path analysis in `verification.md`; chain-aggregation rule in `playbooks.md` | G0 analysis; re-tests links at that link's gate |
| 13 | Independent Verifier | Reproduces candidate findings and rejects false positives — never the worker that found the thing | Ten-gate verification, FP rejection rules, confidence states in `verification.md`; `../../dedupe-check` | Reproduces at the finding's own gate |
| 14 | Remediation & Incident Analyst | Root-cause fixes, containment recommendations, investigation requirements | `../../reporter` draft fields; incident-verdict classifications in `exposure-investigation.md` | G0 |
| 15 | Browser Worker | Logged-in browser reach: sessioned flows, DOM-dependent checks, business-logic classes HTTP replay cannot reach | PB-3, PB-12; DOM paths in WEB-01, WEB-10, WEB-11, WEB-19; real-browser runs (Playwright-class tools) dispatched through `tools/wrap` under the manifest | G2 |

## Worker operating rules

- **One worker, one intent, one surface.** The intent packet carries `[TASK]`, `[SCOPE]`, `[AUTHORIZATION]`, `[BUDGET]`, `[EXPECTED INVARIANT]`, `[STOP CONDITIONS]`, `[REQUIRED EVIDENCE]`, `[OUTPUT FORMAT]`, `[PROHIBITED ACTIONS]`, `[PRIOR TRACES]` — the worker holds exactly that and nothing else (packet format in `../../orchestrator`).
- **Claim before work.** Read `memory/targets/<program>/coverage.md` before planning; append `CLAIM <surface>` atomically, `HEARTBEAT` while held, `RELEASE <surface> status=<final> techniques=<list>` on close — always, including aborts. A surface already held by an unpaired `CLAIM` is off-limits unless it has gone stale; stale claims are taken via `STEAL`, never by writing over a live holder. Full protocol: `../../coverage-ledger`.
- **Discoveries do not widen scope.** A promising neighbor surface is a new intent and a new ledger row, not a widened claim. Workers record neighbor surfaces as asset-graph observations and handoff notes, then return to their own claim.
- **Exhausted is earned.** A surface closes `exhausted` only after the assigned technique set or N distinct techniques ran (default N=3) — the second-pass gap analysis in `check-catalogue.md` is the checklist.
- **Identical action twice = stall, not retry.** MAST telemetry ranks step repetition the #1 multi-agent failure mode (17%): the same action with the same args twice in a row, no new facts between, is a loop. Declare the stall — RELEASE the surface with the honest status and a `stall:` note naming the repeated call — and let the planner re-plan. Never fire the same call a third time hoping for a different result.
- **Evidence-backed output or nothing.** Facts and findings anchor to AS-nodes; every claimed boundary break carries the required evidence per `../../evidence`. Unverified observations stay hints.
- **No generic work.** Every intent maps to the single most specialized roster role available; if no role fits, the orchestrator executes it inline rather than delegating to a generalist.
- **Specialists are roles, not headcount.** One conversation can hold several roles sequentially; a fan-out runs them as parallel intents. Never claim parallel execution occurred if it did not.

## Worker tool surface

Workers receive a minimal tool surface: fact/finding/asset write tools, trace search, and node detail — nothing that reads the frontier. `list_facts`, the task overview, and planner state are the planner's job; a worker that reads the frontier starts planning, and claims stop meaning anything. The intent text is anchored in the worker's system-level instruction so context compaction cannot evict it mid-run.
