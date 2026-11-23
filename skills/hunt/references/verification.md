# Reference — Invariants, Verification & Impact Analysis

Companion to the `hunt` skill (`../SKILL.md`). Covers: the security invariant model, the ten-gate false-positive verification system, FP rejection rules, confidence classification, finding verification requirements, and attack-path & impact analysis.

This is the verification layer a candidate finding passes through before it can be called a finding: Worker 13 (Independent Verifier, see `worker-roster.md`) owns it, capture mechanics live in `../../evidence`, and the outcome classes below are the ones `../SKILL.md` and `playbooks.md` cite for demonstrated-versus-plausible separation.

---

# SECURITY INVARIANT MODEL

A security vulnerability should represent the violation of a legitimate security expectation.

Define application-specific invariants before testing — each intent packet's `[EXPECTED INVARIANT]` field carries one (`../../orchestrator`).

Examples:

**Cross-account confidentiality**

Account B must not read account A's private synthetic object without legitimate sharing permission.

**Cross-tenant isolation**

Users in tenant B must not access tenant A's private test resources.

**Role authorization**

A viewer must not perform an administrator-only action.

**Server-controlled properties**

A normal user must not modify a protected role or ownership attribute through ordinary object updates.

**Session revocation**

A revoked test session must not continue accessing new protected resources beyond the documented revocation policy.

**Payment integrity**

The server must enforce authoritative payment, entitlement, and transaction state.

**Resource ownership**

A private uploaded test file must not be accessible through unauthorized identities.

**AI tool security**

Untrusted content must not cause an AI agent to execute actions outside the user's approved permissions.

If the intended security rule is unknown, classify the result as needing product-owner clarification.

---

# TEN-GATE FALSE-POSITIVE VERIFICATION SYSTEM

Every suspected vulnerability must pass the relevant checks below.

## Candidate pre-scoring — verify the top of the ranking first

Before the gates run, the verifier scores every candidate finding on confidence (1-5). The score is a sampled self-rating: rate each candidate several times independently and average — one shot ratings are noise. Candidates are verified highest-score-first; low scorers get a capped verification budget and are dropped when it is exhausted rather than worked until something sticks. This is the RoboDuck/AIxCC triage pattern: the gate sequence is expensive, so spend it where the prior is strongest. The pre-score ranks work order only — it never raises a finding's confidence class and never substitutes for a gate.

## Gate 1 — Permission

Was the exact asset, path, method, identity, and technique authorized?

If not, stop testing.

## Gate 2 — Reachability

Does the affected functionality actually exist in the deployed application?

Documentation references alone are insufficient.

## Gate 3 — Security invariant

What specific security expectation should hold?

Is it based on documented requirements, product behavior, or confirmed ownership rules?

## Gate 4 — Positive and negative controls

Establish expected normal behavior and a controlled comparison.

Use synthetic data and permitted accounts.

## Gate 5 — Reproducibility

Does the behavior repeat when safely tested?

Do not repeat dangerous actions solely to increase confidence.

## Gate 6 — Causality

Does the controlled difference explain the observation?

Account for:

- Caching
- Retries
- Session refresh
- Load balancing
- Browser behavior
- Eventual consistency
- Application feature flags
- Different permissions
- Time-dependent behavior

## Gate 7 — Data ownership

Does the researcher control the affected identity, session, token, and data?

If real personal information or someone else's credentials appear, stop and escalate privately.

## Gate 8 — Demonstrated impact

Did an unauthorized action genuinely succeed?

A status code alone is insufficient.

Verify the security consequence using owned test data.

## Gate 9 — Alternative explanations

Consider:

- Public or intentionally shared resources
- Documented functionality
- Delegated permissions
- Cached pages
- Stub responses
- Frontend-only changes
- Non-persistent server echoes
- Delayed permission propagation
- Vendor backports
- Test-environment differences

## Gate 10 — Reporting validity

Is the issue supported by a minimal reproducible proof?

Is the vulnerability type within scope?

Are the evidence and data handling appropriate?

Has independent review been completed where practical?

Bounty eligibility, technical validity, impact severity, and confidence must be assessed separately.

---

# FALSE-POSITIVE REJECTION RULES

Apply the following rules before confirming findings. Playbook-specific refinements extend these in `playbooks.md`.

## Authorization

An endpoint returning HTTP 200 does not establish unauthorized access.

A private synthetic object or protected operation must actually cross an authorization boundary.

## Administrator interfaces

An administrative route rendering a single-page application shell is not administrative access.

A protected function must genuinely execute under an unauthorized test identity.

## Mass assignment

A server echoing a submitted property is not proof that the protected property was persisted.

Verify the effective server-side state of an owned resource.

## Authentication bypass

A browser displaying cached content is not proof that an invalid session can perform protected API actions.

## Injection

An error message, timing change, or unusual response alone does not prove interpreter control.

Require appropriate safe causal evidence.

## XSS

A reflected string is not necessarily executable script.

Require evidence of unintended execution in an authorized context.

## SSRF

A legitimate URL preview fetching an allowed public destination is not automatically SSRF.

A violation of the documented destination security policy must be established.

## CORS

Permissive headers alone do not prove an exploitable confidentiality violation.

Consider credentials, browser enforcement, and protected data readability.

## CSRF

A missing explicit CSRF token is not always exploitable.

Consider cookie behavior and real cross-origin request conditions.

## CVEs

A publicly visible version string does not prove that the vulnerable code is present, unpatched, or reachable.

## Public storage

Publicly accessible static assets are not private-data leaks.

Prove unintended access with approved synthetic files.

## WebSockets

A successful protocol handshake does not demonstrate authorization failure.

Protected event delivery or an unauthorized action must be established.

## GraphQL

Introspection and schema visibility are not automatically vulnerabilities.

## AI prompt injection

A model repeating instructions is not equivalent to executing an unauthorized tool call.

Distinguish generated text from actual system side effects.

## Race conditions

Two successful HTTP responses do not establish two committed business operations.

## Sensitive-looking strings

A value resembling a credential is not sufficient evidence that it is usable or secret.

Do not attempt to use discovered credentials to prove validity.

---

# CONFIDENCE CLASSIFICATION

Use these exact finding states.

## signal_only

An unusual observation exists, but there is insufficient evidence of a security flaw.

## plausible

A coherent security hypothesis exists, but necessary proof is missing.

## reproducible_but_impact_unknown

The behavior repeats, but violation of a protected security boundary has not been established.

## confirmed_minimal_poc

A permitted, controlled test demonstrates violation of a security invariant using owned resources.

## refuted

Evidence contradicts the original hypothesis.

Do not report as a vulnerability.

## blocked_by_scope

Further testing would exceed permitted techniques, targets, identities, or data access.

## needs_owner_confirmation

The necessary verification requires internal information, source review, monitoring evidence, financial state, or administrator confirmation unavailable to external research.

Never automatically elevate confidence based solely on LLM judgment.

---

# SECURITY FINDING VERIFICATION

Every confirmed finding must demonstrate:

1. The affected function exists.
2. The target is authorized.
3. The expected security behavior is clear.
4. The test uses permitted owned data.
5. A controlled normal request behaves as expected.
6. A controlled negative request demonstrates the failure.
7. The result is not merely a misleading status code.
8. The consequence is reproducible or adequately evidenced.
9. Relevant alternative explanations have been considered.
10. The report does not claim more impact than the evidence supports.

## Mechanical grounding — verification by grep, not judgment

Two checks run as `tools/fact-verify/verify_claims.py` and fail closed:

- **Soliloquy rule.** Every `[F-n]` fact's asserted payload must grep-match the worker's raw trace *before* the node is written to the exploration graph. A payload absent from the trace means the claim was never observed — the node stays a `[H-n]` hint. Facts are grounded in recorded output or they are not facts.
- **POE-verified invariant.** A finding is `verified` only when every quoted evidence string in its receipt appears verbatim in the stored evidence body — checked by `verify_claims.py --verbatim`, never by reading the quote and judging it plausible. A quote that is not verbatim-present is a fabrication signal: the finding drops to `plausible` and the receipt is treated as defective (BaaRai proof-of-evidence invariant).

Both are mechanical. A verifier who "knows" the quote is right but cannot show it in the stored bytes has an unverified finding.

## Deterministic primitives

Five class-specific primitives turn "looks vulnerable" into mechanically checkable ground truth. Each produces an artifact a verifier can re-run without trusting the agent's judgment — the same fail-closed discipline as the grep checks above.

### OAST correlation (blind classes)

SSRF, XXE, blind RCE, and async deserialization leave no response-side trace, so confirmation requires an out-of-band callback. Issue a unique Interactsh-style token per probe — `<preamble><nonce>.oast.live` — with the nonce bound to the single request that carried it, and watch both DNS and HTTP channels for an inbound hit whose nonce correlates to that request. A correlated callback proves the server fetched attacker-controlled infrastructure. Note the bar: a bare OAST pingback alone is widely triaged Informative, so for payout the finding must escalate the primitive into a demonstrated data-read or state-change, not stop at the callback.

### Browser DOM oracle (client-side classes)

XSS and DOM-based classes are confirmed only by actual JavaScript execution observed in a headless browser running at the target origin. An encoded payload that appears reflected in the markup but never executes is not a finding — it is an escaped string. Anti-reward-hacking rule: the confirmation signal must originate from target-origin execution, never from an agent-asserted string claiming the payload fired.

### Canary planting (authorized accounts and staging)

Where the program permits owned test data, plant a unique canary value and retrieve it through the claimed path: file contents for LFI, database rows for SQLi, fields on account A's profile for IDOR. Retrieval of the exact planted value across the claimed boundary is ground truth; an anomalous response that never surfaces the canary is still a hypothesis.

### Dual-connection desync proof (request smuggling)

A desync is confirmed only when a second connection observes the smuggled effect: response-queue poisoning where a follow-up request receives the smuggled response, or a Collaborator callback fired by the smuggled request. A timeout delta alone is pipelining noise — 90-95% of naive desync claims are HTTP/1.1 pipelining false positives. Method and FP refinements live in `playbooks.md` PB-13.

### Multi-role differential (authorization classes)

Authorization failures are proved only by replaying the same action under a second identity. An admin deactivates account A and token A still reaches the resource — broken. `PUT {"role":"admin"}` replays and the persisted value stays `role=customer` — disproven. Two-account method lives in `playbooks.md` PB-12.

### Two rules for every primitive

- **Incremental step-wise validation.** Each link in an exploit chain is verified before the next intent is attempted — never confirm the whole chain at the end. An unverified middle link makes everything after it unverified too.
- **Impact-escalation.** The validator must demonstrate the impact it claims: the data read, the callback hit, the state change. Severity is what was demonstrated, never what was plausible — a chain that stops at signal stays `signal_only` or `plausible` regardless of where it was headed.

## Retest verdicts

When a program reports a finding fixed, re-run the *original intent packet* — same task, same scope, same expected invariant — and record exactly one verdict:

- **Still reproducible** — the boundary break still fires. Append the new evidence and the verdict; the finding stays open.
- **Fixed** — the original trigger no longer violates the invariant under the same controlled test. The finding closes as fixed.
- **Cannot confirm** — the retest could not exercise the original path (asset changed, account revoked, endpoint gone). Say so; do not call it fixed.

The verdict updates the finding without deleting or editing the original evidence — the pre-fix capture stands as the record of what was demonstrated, and the retest lands as new dated files plus a `notes.md` line per the append-once rule in `../../evidence`. Re-run `dedupe-check` on every retest.

## Verification priority

Prioritize potentially serious findings:

- Unauthorized cross-tenant exposure
- Unauthorized access to private synthetic objects
- Privilege-boundary failures
- Sensitive credential exposures
- Server-side authorization failures
- Unintended protected data disclosure
- Financial integrity weaknesses
- Privileged tool execution risks
- Public exposure of genuinely sensitive infrastructure artifacts

Do not perform progressively more invasive demonstrations after minimal proof is sufficient.

---

# ATTACK-PATH AND IMPACT ANALYSIS

For every confirmed vulnerability, consider whether it contributes to a broader security failure. Worker 12 (Attack-Path Analyst) owns this step.

Model:

**Entry point → Verified weakness → Security boundary crossed → Demonstrated access → Potential consequential capabilities → Required remediation**

## Evaluate potential outcomes

- Unauthorized data disclosure
- Cross-user information access
- Cross-tenant access
- Unauthorized modification of test resources
- Account impersonation
- Privilege escalation
- Administrative operation exposure
- Protected file access
- Sensitive credential disclosure
- Financial workflow manipulation
- Paid API cost abuse
- Unauthorized notification or email actions
- Persistent malicious content risk
- Service availability risk

## Outcome classes

Classify each outcome — these are the classes cited wherever demonstrated-versus-plausible separation is required:

- Demonstrated
- Supported but not fully validated
- Hypothetical
- Refuted
- Not tested

Do not infer full database compromise from one authorization failure.

Do not infer administrative compromise from an exposed route.

Do not infer usable credentials from a key-shaped value.

Do not infer historical intrusion from the presence of a vulnerability.
