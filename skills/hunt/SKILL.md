---
name: hunt
description: Systematic bug-bounty hunting across two layers — a 110-check coverage catalogue (identity, authorization, API, web, business logic, infrastructure, supply chain, AI systems) plus 14 field-sourced technique playbooks (GraphQL introspection-to-takeover, AI-agent tool abuse, WebSocket/captcha-gated agent endpoints, race conditions, SAML assertion confusion, CSRF token-validation absence, OAuth code/token leakage and low-severity chaining, SSO audience confusion, HTML-to-PDF SSRF, smart-contract/DeFi program scoping, program-rules extraction with report-quality triage, cross-protocol IDOR/BOLA object-diffing, front-end/backend trust-boundary request smuggling and cache poisoning, and SSTI/server-side template injection). Includes the staged hunt pipeline (Stage 0 authorization intake through Stage 10 reporting), a 14-role worker roster, and the ten-gate verification standard. Use when hunting on an authorized bug-bounty program or running technique-driven testing on an owned application.
---

# hunt — systematic coverage plus playbook-driven technique

Two layers, complementary:

- **The catalogue is breadth.** `references/check-catalogue.md` carries the 110-check master catalogue across eight categories (ID, AUTH, API, WEB, BIZ, INFRA, SPEC, AIX), the attack-surface inventory fields, the authorization matrix, custom-check rules, and the second-pass gap analysis. Every applicable check gets a recorded disposition — that is what "covered" means, and it is how a surface earns `exhausted` in `../coverage-ledger`.
- **The playbooks are technique.** `references/playbooks.md` carries the expanded method for PB-1–PB-14 — provenance, tooling, evidence bars, FP-rule refinements — for surfaces where a named technique applies. A check says *what* to test; a playbook says *how*.

Supporting references: `references/worker-roster.md` (the 14 specialist roles and their per-worker gates), `references/verification.md` (security invariants, the ten-gate FP verification system, confidence states, attack-path outcome classes), `references/exposure-investigation.md` (external-to-internal exposure paths, extortion/breach-claim investigation, authorized internal review).

All techniques are for authorized testing only — targets named in the scope manifest, entitled labs, or programs whose written policy permits the technique.

## The hunt pipeline

Stages 0–10, one line each; gates and limits come from `../safety-gates`, the manifest from `../scope-parser`.

- **Stage 0 — Authorization intake.** Record the scope manifest (`../scope-parser`): exact hosts, methods, techniques, identities, budgets, contacts. No manifest, no traffic.
- **Stage 1 — Passive reconnaissance.** Inventory externally visible functionality at G1; classify each resource as authorized / discovered-but-out-of-scope / unknown-ownership. Discovery never grants permission.
- **Stage 2 — Test identity preparation.** Where G2 is approved: create accounts A and B, two owned tenants where supported, uniquely marked synthetic objects, disposable credentials.
- **Stage 3 — Baseline observation.** Compare each endpoint across logged-out / A / B / low-privilege / high-privilege / revoked-session; record expected versus observed.
- **Stage 4 — Threat modeling.** Name the assets, trust boundaries, ownership, tenant separation, and the security invariants a bug would violate (`references/verification.md`).
- **Stage 5 — Hypothesis generation.** Map applicable catalogue checks and custom hypotheses to each surface; assign gate, request estimate, and evidence bar per test.
- **Stage 6 — Controlled testing.** Dispatch intents at or below the authorized gate; minimal requests, sanitized evidence capture, stop the moment the boundary is demonstrated.
- **Stage 7 — False-positive rejection.** Run the ten-gate verification and the FP rejection rules (`references/verification.md`).
- **Stage 8 — Independent reproduction.** A verifier — never the finder — reproduces confirmed candidates with owned test resources (`../evidence`).
- **Stage 9 — Attack-path analysis.** Correlate confirmed findings into chains; classify every link Demonstrated / Supported but not fully validated / Hypothetical (`references/verification.md`).
- **Stage 10 — Reporting.** Dedupe via `../dedupe-check`, draft via `../reporter` through the harm gate and the seven report-quality questions; a human submits.

A proven finding triggers stop-on-proof for that weakness; the hunt continues on independent authorized surfaces.

## How a worker hunts

1. **Claim the surface first.** Read `memory/targets/<program>/coverage.md`; append `CLAIM`, heartbeat while held, `RELEASE` with final status on close — the protocol and exhaustion semantics live in `../coverage-ledger`. Worker specialization (recon, client-exposure, auth, authz, API, web-input, DB/storage, business-logic, infra, supply-chain, AI-system, attack-path, verifier, remediation) and each role's gate ceiling are in `references/worker-roster.md`.
2. **Pick the coverage layer by intent.** Systematic pass: work the applicable catalogue checks for the claimed surface and record a disposition per check. Technique pass: match the surface to the "when to use" column in the playbook index below — a GraphQL endpoint goes to PB-1, an embedded AI agent with registered tools goes to PB-2, a server-side PDF export goes to PB-9. The wrong playbook is the wrong method; PB-11 applies to every program engagement regardless of surface.
3. **Read the reference before testing.** Catalogue checks: `references/check-catalogue.md`. Playbooks: `references/playbooks.md` — each carries a provenance block (who published the technique, how well it is verified, what is reconstructed or self-published), the expanded method, a tooling list, evidence requirements, and an inline FP-rule refinement.
4. **Follow the method steps under the G0–G3 gates.** Gate definitions, approval requirements, request budgets, and the hard prohibitions that override program policy (no credential brute-forcing on live targets, no exfiltrating real secrets, no using discovered production credentials for deeper access) are defined in `../safety-gates`. G3 is disabled by default and needs separate, specific approval — staging preferred. Lab-only steps (credential-guessing variants, first-sequence sync, memory-corruption validation on your own instance) are labeled inside the playbooks and are non-negotiable.
5. **Meet the evidence bar.** Each playbook states exactly what must be captured — full request/response pairs, baseline-before-bypass diffs, sync-quality data for races, committed-state proof (not just successful responses). Capture, redact, and store per `../evidence`. Scope-proof — the program-policy line permitting the technique — ships with the evidence or the report dies at triage.
6. **Apply the FP rules before claiming.** Every playbook ends with an FP-rule refinement stating what does NOT count: introspection visibility is not a vulnerability, a rendered CAPTCHA widget is not enforcement, a signed assertion replayed is not a finding until a session is issued, two 200s are not two committed operations. The general rules and the ten-gate process are in `references/verification.md`.
7. **Report through the triage gate.** Harm gate first, then the seven report-quality questions — run via `../reporter`. Separate demonstrated impact from plausible chains in writing; argue severity from what the victim loses, never the sum of component severities. Submission is always a human decision.

## Playbook index

| PB | Name | When to use | Gate ceiling |
|----|------|-------------|--------------|
| PB-1 | GraphQL: introspection-to-takeover | Target exposes a GraphQL endpoint; highest value where identity mutations (password reset, email change, OTP, token issuance) take arbitrary `username`/`email` args | G3 (abuse primitives; credential-guessing variant lab-only) |
| PB-2 | AI agent tool abuse (confused deputy) | Application embeds an AI agent with registered tools; map tool capabilities and read them for absent boundaries | G3 (cloud-metadata probes through an SSRF sink) |
| PB-3 | WebSocket event protocols and captcha-gated agent endpoints | CAPTCHA/bot-gated chat or agent endpoints; WS protocols where a client-submitted event flips server-side authorization | G2 |
| PB-4 | Race conditions: single-endpoint TOCTOU and HTTP/2 single-packet | Check-then-act writes to shared state — contact confirmation flows, coupon/fund redemption, rate-limit windows | G3 (G3 throughout method B; first-sequence sync lab-only) |
| PB-5 | SAML assertion confusion | SAML service providers in enterprise SSO; replay, single-variable mutation, XSW | G3 |
| PB-6 | CSRF: token issued, never validated | Mutating session-cookie endpoints; CSRF tokens present but possibly unchecked; validated-token escalation variants | G2 |
| PB-7 | OAuth code/token leakage and low-severity chaining | OAuth/OIDC flows; redirect validation, Referer exfiltration, scope escalation, login-CSRF chaining | G2 |
| PB-8 | SSO audience confusion and upload-parser reach | Multiple apps behind one identity provider; upload pipelines whose primary validator cannot decode accepted formats | G3 (memory-corruption validation on your own instance only) |
| PB-9 | SSRF through HTML-to-PDF export pipelines | Server-side PDF/export features, URL→PDF APIs; renderer engines as SSRF primitives | G3 (internal pivoting/metadata endpoints) |
| PB-10 | Smart-contract and DeFi program scoping | Contract/DeFi bounty programs (Immunefi-style, Safe-style); program scoping, PoC discipline, severity sizing | G2-lab (local forks only; live deployments prohibited) |
| PB-11 | Program-rules extraction and report quality | Every program engagement — extract rules first, mandatory before writing any report | G2 |
| PB-12 | Cross-protocol IDOR/BOLA object-diffing | Per-user objects addressable by identifier across REST and GraphQL; two test accounts available; priority-tier deterministic class | G2 |
| PB-13 | Front-end/backend trust boundary: request smuggling and cache poisoning | Target behind a front-end tier (CDN/proxy/LB); desync probes on owned requests only, unkeyed-input and web-cache-deception testing | G3 (queue-poisoning and H2-downgrade steps; detection limited to own request pairs) |
| PB-14 | SSTI and the server-side injection family | User-controlled strings rendered through server-side template engines, including agent-toolchain report/PDF/email renderers | G3 (post-identification escalation; detection polyglots at G2) |

## Standing rules for all playbooks

- **Scope gate before any probe.** Techniques run only against manifest targets, entitled labs, or programs whose written policy permits them. Discovery never grants permission.
- **Stop at proof.** Demonstrate the minimal security consequence, then stop exploiting that weakness.
- **Demonstrated versus plausible, in writing.** Separate what the evidence shows from model-dependent or unexercised chain links; classify each per the outcome classes in `references/verification.md`.
- **Program-scope proof accompanies technique evidence.** Credential-, concurrency-, and auth-bypass-class reports must carry the program-policy line that permits the technique, or they fail triage.
- **Playbooks change the method, never the authority.** Every step remains subject to `../safety-gates` regardless of what a program's policy allows.
