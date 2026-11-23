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
