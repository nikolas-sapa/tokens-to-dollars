---
name: hunt
description: Playbook-driven vulnerability hunting across 11 techniques — GraphQL introspection-to-takeover, AI-agent tool abuse (confused deputy), WebSocket/captcha-gated agent endpoints, race conditions (single-endpoint TOCTOU and HTTP/2 single-packet), SAML assertion confusion, CSRF token-validation absence, OAuth code/token leakage and low-severity chaining, SSO audience confusion, HTML-to-PDF SSRF, smart-contract/DeFi program scoping, and program-rules extraction with report-quality triage. Use when hunting on an authorized bug-bounty program or running technique-driven testing on an owned application.
---

# hunt — playbook-driven vulnerability hunting

Eleven field-sourced playbooks (PB-1–PB-11) for authorized bug-bounty hunting and technique-driven testing of owned applications. Full method detail, provenance, and per-playbook evidence bars live in `references/playbooks.md`.

All techniques are for authorized testing only — targets named in the scope manifest, entitled labs, or programs whose written policy permits the technique.

## How a worker uses a playbook

1. **Pick the playbook by target surface.** Match the authorized surface to the "when to use" column in the index below — a GraphQL endpoint goes to PB-1, an embedded AI agent with registered tools goes to PB-2, a server-side PDF export goes to PB-9. The wrong playbook is the wrong method; PB-11 applies to every program engagement regardless of surface.
2. **Read the playbook entry in `references/playbooks.md`.** Each playbook carries a provenance block (who published the technique, how well it is verified, what is reconstructed or self-published), the expanded method, a tooling list, evidence requirements, and an inline FP-rule refinement.
3. **Follow the method steps under the G0–G3 gates.** Gate definitions, approval requirements, request budgets, and the hard prohibitions that override program policy (no credential brute-forcing on live targets, no exfiltrating real secrets, no using discovered production credentials for deeper access) are defined in `../safety-gates`. G3 is disabled by default and needs separate, specific approval — staging preferred. Lab-only steps (credential-guessing variants, first-sequence sync, memory-corruption validation on your own instance) are labeled inside the playbooks and are non-negotiable.
4. **Meet the evidence bar.** Each playbook states exactly what must be captured — full request/response pairs, baseline-before-bypass diffs, sync-quality data for races, committed-state proof (not just successful responses). Capture, redact, and store per `../evidence`. Scope-proof — the program-policy line permitting the technique — ships with the evidence or the report dies at triage.
5. **Apply the FP rule before claiming.** Every playbook ends with an FP-rule refinement stating what does NOT count: introspection visibility is not a vulnerability, a rendered CAPTCHA widget is not enforcement, a signed assertion replayed is not a finding until a session is issued, two 200s are not two committed operations.
6. **Report through the triage gate.** Harm gate first, then the seven report-quality questions — run via `../reporter`. Separate demonstrated impact from plausible chains in writing; argue severity from what the victim loses, never the sum of component severities. Submission is always a human decision.

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

## Standing rules for all playbooks

- **Scope gate before any probe.** Techniques run only against manifest targets, entitled labs, or programs whose written policy permits them. Discovery never grants permission.
- **Stop at proof.** Demonstrate the minimal security consequence, then stop exploiting that weakness.
- **Demonstrated versus plausible, in writing.** Separate what the evidence shows from model-dependent or unexercised chain links; classify each per the outcome classes in `../evidence`.
- **Program-scope proof accompanies technique evidence.** Credential-, concurrency-, and auth-bypass-class reports must carry the program-policy line that permits the technique, or they fail triage.
- **Playbooks change the method, never the authority.** Every step remains subject to `../safety-gates` regardless of what a program's policy allows.
