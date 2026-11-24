# Reference — Attack-Surface Inventory & Master Check Catalogue

Companion to the `hunt` skill (`../SKILL.md`). Covers: complete attack-surface inventory fields, the 110-check master catalogue, application-specific research, the authorization matrix, and second-pass gap analysis.

The catalogue is the systematic-coverage layer: it answers "what must be checked" where `playbooks.md` answers "how a specific technique works". Every applicable check must receive a recorded disposition — in the exploration graph and the coverage row per `../../coverage-ledger`. A catalogue entry is a testing hypothesis, not proof of a vulnerability.

The indicated gate is the minimum catalogue gate (gate definitions in `../../safety-gates`); the program manifest may require a stricter gate or prohibit testing entirely.

---

# ATTACK-SURFACE INVENTORY

For each explicitly authorized service, enumerate relevant metadata.

## Required endpoint fields

- Unique endpoint ID
- Scheme
- Exact hostname
- Port
- Base path
- Endpoint path
- API version
- HTTP methods
- Transport type
- Content types
- Authentication mechanism
- Session requirements
- Required role
- Required scopes
- User-controllable fields
- Object identifiers
- Tenant identifiers
- Pagination behavior
- Filtering behavior
- Response schema
- Sensitive fields
- State-changing behavior
- Financial consequences
- Notification consequences
- External integrations
- Caching behavior
- Error behavior
- Documentation source
- Actual observed behavior
- Applicable security tests
- Testing authorization
- Coverage status

## Supported transport types

Investigate those actually present and authorized:

- REST
- GraphQL
- gRPC
- WebSocket
- Webhook
- Server-sent events
- Browser application routes
- Mobile application API routes
- Background job interfaces

Avoid speculative probing of undocumented protocols without permission.

---

# MASTER SECURITY TEST CATALOGUE

The following 110 checks are the core catalogue.

Every applicable check must receive a recorded disposition.

The indicated gate is the minimum catalogue gate; the actual target policy may require a stricter gate or prohibit testing entirely.

A catalogue entry is a testing hypothesis, not proof of a vulnerability.

## CATEGORY A — IDENTITY AND SESSION SECURITY

**ID-01 | G2 — Registration and identity verification**

Determine whether unverified accounts receive capabilities requiring verified identity.

**ID-02 | G2 — Password reset and account recovery**

Evaluate reset token ownership, expiration, reuse, revocation, and identity binding using owned accounts.

**ID-03 | G2 — MFA enforcement**

Verify that protected test-account authentication and recovery paths enforce required factors.

**ID-04 | G2 — MFA enrollment and backup codes**

Assess factor replacement, backup code uniqueness, reauthentication, and change notification.

**ID-05 | G1 — Session cookie defenses**

Review Secure, HttpOnly, SameSite, Domain, Path, and relevant cookie scope.

**ID-06 | G2 — Logout and session revocation**

Verify server-side session invalidation using owned sessions and harmless protected actions.

**ID-07 | G2 — Token validation**

Evaluate issuer, audience, expiration, signature, and intended-use enforcement using permitted test-token variants.

**ID-08 | G2 — OAuth/OIDC security**

Review state, nonce, PKCE, redirect binding, token audience, and account linking with owned identities.

**ID-09 | G3 — SAML and SSO lifecycle**

Review assertion validation, provisioning, deprovisioning, and trust configuration in an approved environment.

**ID-10 | G2 — Passkeys and WebAuthn**

Assess credential ownership, origin, relying-party identity, challenge validity, and credential lifecycle.

**ID-11 | G2 — Account enumeration**

Compare only owned known and unknown identities with minimal requests.

**ID-12 | G2 — Session fixation and device management**

Check appropriate session rotation and device revocation.

**ID-13 | G2 — Account linking and invitations**

Evaluate identity-to-account binding and test invitation authorization.

**ID-14 | G1 — Password and secret exposure**

Review whether owned credentials or tokens appear in URLs, browser storage, referrers, or telemetry.

---

## CATEGORY B — AUTHORIZATION AND MULTI-TENANCY

**AUTH-01 | G2 — BOLA and IDOR**

Verify per-object authorization using two researcher-owned identities and synthetic private objects.

**AUTH-02 | G2 — Broken function-level authorization**

Compare actual execution permission between legitimate test roles.

**AUTH-03 | G2 — Object-property read authorization**

Verify that protected object fields are omitted from unauthorized test-role responses.

**AUTH-04 | G2 — Mass assignment and write authorization**

Check whether server-controlled properties of synthetic objects can be improperly changed.

**AUTH-05 | G2 — Cross-tenant isolation**

Test tenant boundaries using two owned organizations and uniquely marked resources.

**AUTH-06 | G2 — Collection filtering, search, and export authorization**

Compare object-detail permissions with list, search, aggregation, and export behavior.

**AUTH-07 | G2 — File links and signed URLs**

Assess access scope, expiration, revocation, and sharing behavior for test files.

**AUTH-08 | G2 — Ownership transfer and sharing**

Validate controlled sharing and permission transitions using reversible test operations.

**AUTH-09 | G2 — Indirect and background execution**

Determine whether asynchronous operations respect authorization and permission changes.

**AUTH-10 | G2 — Authorization across transports**

Compare the same harmless protected operation across available in-scope APIs and clients.

**AUTH-11 | G2 — Role changes and stale entitlements**

Verify that revoked roles lose protected capabilities according to documented behavior.

**AUTH-12 | G2 — Object identifier normalization**

Evaluate authorization consistency across supported identifier representations in an approved environment.

---

## CATEGORY C — API SECURITY

**API-01 | G1 — Complete API inventory**

Map approved REST, GraphQL, gRPC, WebSocket, webhook, and versioned interfaces.

**API-02 | G1 — OpenAPI/Swagger documentation drift**

Compare official schema documentation with observed normal API behavior.

**API-03 | G2 — HTTP method authorization**

Verify permitted methods and authorization enforcement on harmless test operations.

**API-04 | G2 — Content types and parsers**

Assess validation consistency across supported request formats.

**API-05 | G2 — GraphQL resolver authorization**

Check authorization at relevant fields, nested relationships, and resolvers using synthetic data.

**API-06 | G3 — GraphQL batching and complexity**

Review query cost protections in an explicitly approved environment.

**API-07 | G2 — GraphQL subscriptions**

Verify event isolation using researcher-owned tenants and synthetic events.

**API-08 | G2 — WebSocket security**

Evaluate authorization at handshake and message level, including session changes.

**API-09 | G2 — gRPC metadata and streaming authorization**

Review method and stream permissions using approved identities.

**API-10 | G2 — Webhook authentication and replay**

Assess signature validation, freshness, and idempotency using sandbox events.

**API-11 | G2 — Outbound webhooks and callbacks**

Evaluate authorized callback destination restrictions with controlled endpoints.

**API-12 | G2 — Idempotency and duplicate changes**

Assess harmless reversible duplicate operations in a sandbox.

**API-13 | G2 — Pagination, filtering, and cursor security**

Verify authorization consistency across controlled synthetic datasets.

**API-14 | G1 — CORS origin and credential policy**

Review whether browser origins can read protected cross-origin content beyond intended access.

**API-15 | G3 — API rate limits and resource budgets**

Review quotas and resource controls without generating production load or charges.

**API-16 | G1 — API version lifecycle**

Identify documented legacy APIs and relevant authorization assumptions.

**API-17 | G2 — Third-party response trust**

Review trusted partner data handling using approved integration fixtures or sandbox events.

**API-18 | G2 — Response caching and private information**

Check user and tenant cache separation with synthetic content.

**API-19 | G1 — API error handling**

Observe whether ordinary malformed requests expose sensitive information.

**API-20 | G1 — API discovery through client applications**

Extract public client references and classify discovered endpoints before further testing.

---

## CATEGORY D — WEB AND INPUT SECURITY

**WEB-01 | G2 — Reflected, stored, and DOM XSS**

Assess unintended script execution using benign controlled markers.

**WEB-02 | G3 — SQL, NoSQL, and LDAP injection**

Investigate interpreter boundary risks through authorized source review, laboratory fixtures, or specifically approved low-impact tests.

**WEB-03 | G3 — Template injection**

Assess whether user content reaches unsafe template evaluation using a controlled environment.

**WEB-04 | G3 — Command injection and execution risks**

Review potential execution sinks using code analysis or authorized laboratory testing.

**WEB-05 | G3 — Path traversal and unintended file access**

Validate only against harmless owner-provided fixtures.

**WEB-06 | G2 — File uploads and serving behavior**

Assess file types, ownership, content handling, and serving security with inert test samples.

**WEB-07 | G2 — CSRF**

Evaluate whether cross-origin conditions allow unauthorized reversible test-account state changes.

**WEB-08 | G1 — Open redirects**

Assess redirect destinations and relevant security impact using benign controlled locations.

**WEB-09 | G1 — CSP and clickjacking**

Review browser containment controls and meaningful impact on sensitive functionality.

**WEB-10 | G2 — postMessage and DOM sinks**

Evaluate message-origin validation with controlled frames and synthetic messages.

**WEB-11 | G3 — Prototype pollution**

Review unsafe object merging in authorized source or isolated test environments.

**WEB-12 | G3 — HTTP request smuggling**

Restrict investigation to specifically approved specialist environments.

**WEB-13 | G2 — Header injection and response splitting**

Assess improper header construction using harmless values where permitted.

**WEB-14 | G3 — XML entity handling**

Review parser behavior in a controlled environment without reading protected files.

**WEB-15 | G3 — Unsafe deserialization**

Investigate untrusted object handling using laboratory fixtures or authorized source review.

**WEB-16 | G2 — SSRF through URL-fetching functionality**

Assess intended destination restrictions using a permitted controlled public endpoint only.

**WEB-17 | G3 — Cache poisoning and cache-key separation**

Investigate shared cache integrity only through isolated authorized test cases.

**WEB-18 | G1 — Source maps and public secrets**

Review publicly shipped assets for inadvertent source or credential disclosure.

**WEB-19 | G1 — Browser storage and URL tokens**

Analyze owned-session tokens in storage, history, navigation, and referrers.

**WEB-20 | G2 — Exception and fallback security**

Assess whether permitted low-impact error conditions change authorization behavior.

---

## CATEGORY E — BUSINESS LOGIC AND FINANCIAL SECURITY

**BIZ-01 | G2 — State-machine bypass**

Verify protected workflow transitions using reversible synthetic objects.

**BIZ-02 | G3 — Price and coupon integrity**

Review server-authoritative pricing in a zero-value sandbox.

**BIZ-03 | G3 — Payments and refunds**

Assess transaction authorization and webhook integrity through payment provider test fixtures only.

**BIZ-04 | G2 — Subscription and entitlement transitions**

Evaluate subscription-related rights in a free sandbox or owner-provided test tenant.

**BIZ-05 | G2 — Invitations and organizational ownership**

Check role grants, invitations, and ownership boundaries using test organizations.

**BIZ-06 | G3 — Usage quotas and metering**

Review paid-resource accounting using mocks, configuration evidence, or bounded test resources.

**BIZ-07 | G3 — Race conditions and double spending**

Use isolated test workflows with explicit authorization and bounded concurrency.

**BIZ-08 | G3 — Inventory and reservation integrity**

Review resource holds and availability in a staging environment with artificial inventory.

**BIZ-09 | G3 — Referral and loyalty abuse**

Evaluate eligibility controls using fictional test accounts without real benefits.

**BIZ-10 | G2 — Export and deletion lifecycle**

Verify authorization of test-owned resource exports and lifecycle actions.

**BIZ-11 | G2 — Notifications and event integrity**

Check tenant and recipient boundaries through harmless synthetic messages.

**BIZ-12 | G3 — Auditability and fraud controls**

Review owner-supplied monitoring architecture and security control evidence.

---

## CATEGORY F — INFRASTRUCTURE, CLOUD, AND DELIVERY SECURITY

**INFRA-01 | G1 — TLS and HTTPS enforcement**

Review certificates, protocols, and HTTPS security on approved hosts.

**INFRA-02 | G1 — DNS and dangling service references**

Identify potentially abandoned references without attempting takeover.

**INFRA-03 | G2 — Public storage permissions**

Validate privacy boundaries only with owner-provided or researcher-owned test objects.

**INFRA-04 | G3 — Cloud IAM**

Review explicitly authorized policy exports and privilege relationships.

**INFRA-05 | G2 — CDN, origin, and reverse-proxy trust**

Evaluate configuration consistency through authorized observations and owner-supplied configuration.

**INFRA-06 | G1 — Administrative consoles and diagnostics**

Identify exposed interfaces without attempting default-credential authentication.

**INFRA-07 | G3 — Network service exposure**

Permit bounded service inspection only when exact hosts, ports, and techniques are authorized.

**INFRA-08 | G1 — Secrets in public artifacts**

Identify exposed credential material and record redacted evidence without using it.

**INFRA-09 | G3 — CI/CD trust boundaries**

Review approved workflow files and sandbox build configurations.

**INFRA-10 | G3 — Container and Kubernetes isolation**

Evaluate provided manifests, policy exports, and test-cluster configuration.

**INFRA-11 | G1 — Dependency versions and CVEs**

Correlate observable versions with actual affected configurations and vendor advisories.

**INFRA-12 | G1 — Email authentication**

Review SPF, DKIM, DMARC, and approved domain configuration evidence.

**INFRA-13 | G3 — Cloud metadata and internal services**

Analyze possible exposure only through design review or explicitly authorized laboratory testing.

**INFRA-14 | G3 — Security telemetry**

Review owner-approved evidence of logging and alert coverage.

**INFRA-15 | G1 — Third-party dependency boundaries**

Inventory external services without expanding active testing scope.

**INFRA-16 | G2 — Backups, snapshots, and staging data**

Assess public exposure indicators; sensitive data verification must be owner-led.

---

## CATEGORY G — SUPPLY CHAIN, MOBILE, AND SPECIALIZED SYSTEMS

**SPEC-01 | G1 — Dependency and SBOM security**

Analyze authorized dependency information, affected code reachability, and patch status.

**SPEC-02 | G3 — Package registry and namespace trust**

Review build manifests and dependency resolution policies without registering deceptive packages.

**SPEC-03 | G1 — Artifact provenance and signatures**

Review release integrity and trusted update provenance.

**SPEC-04 | G2 — Mobile secure storage**

Inspect researcher-owned sessions in an authorized app build or emulator.

**SPEC-05 | G2 — Mobile deep links**

Review intent and universal-link authorization using harmless test destinations.

**SPEC-06 | G2 — Mobile certificate and transport handling**

Evaluate approved development or test builds.

**SPEC-07 | G2 — Desktop client and updater trust**

Analyze permitted update metadata and integrity requirements.

**SPEC-08 | G3 — IoT/OT firmware and interfaces**

Restrict testing to owned hardware or designated isolated devices.

**SPEC-09 | G3 — Native-code and memory safety**

Prefer isolated build fuzzing, static review, and controlled crash triage.

---

## CATEGORY H — AI SYSTEMS AND AGENT SECURITY

Apply only when the authorized application contains relevant AI functionality.

**AIX-01 | G2 — Prompt injection**

Assess whether untrusted documents or messages cause unauthorized instructions or tool actions using harmless test goals.

**AIX-02 | G2 — RAG tenant isolation**

Verify retrieval permissions using synthetic documents in two test workspaces.

**AIX-03 | G2 — Agent tool authorization**

Assess whether tool execution respects user roles, approval boundaries, and permissions.

**AIX-04 | G2 — Memory, conversation, and file isolation**

Evaluate cross-session or cross-account disclosure using synthetic markers.

**AIX-05 | G2 — Unsafe downstream rendering**

Check whether AI-generated content is interpreted unsafely by authorized application components.

**AIX-06 | G3 — Agent resource and spending budgets**

Evaluate API, token, email, and compute quotas through test fixtures or zero-cost environments.

**AIX-07 | G1 — Model safety versus application security**

Distinguish model-generated text from actual unauthorized system actions.

---

# APPLICATION-SPECIFIC RESEARCH (CUSTOM CHECKS)

The 110-check catalogue is a baseline, not an exhaustive universe of vulnerabilities.

After completing applicability mapping, conduct a product-specific security review.

For each important application capability:

1. Identify its intended purpose.
2. Identify which identities may invoke it.
3. Identify which objects it can read.
4. Identify which objects it can change.
5. Identify whether it creates financial cost.
6. Identify whether it contacts outside services.
7. Identify which user-controlled values influence it.
8. Identify the server-side security decisions.
9. Identify the expected state transitions.
10. Identify failure-handling behavior.
11. Identify possible differences between interfaces.
12. Identify which trust boundaries the operation crosses.

Generate additional hypotheses when these relationships reveal risks not covered by the standard catalogue.

Mark custom hypotheses with IDs such as:

CUSTOM-001

CUSTOM-002

CUSTOM-003

Each custom check must use the same authorization, evidence, and verification rules as the predefined checks.

---

# AUTHORIZATION MATRIX

For every applicable sensitive operation, model expected permissions.

## Identity dimensions

- Anonymous
- Account A
- Account B
- Same-tenant viewer
- Same-tenant editor
- Same-tenant administrator
- Other-tenant user
- Revoked test identity

Use only identities actually owned or supplied for testing.

## Operation dimensions

- Read object
- List objects
- Search
- Create
- Update
- Delete test-owned object
- Export
- Share
- Invite
- Approve
- Administer
- Subscribe to events
- Upload
- Download
- Trigger background action

For every cell record:

- ALLOW
- DENY
- UNKNOWN

Then compare expected authorization with permitted observations.

An unknown expected permission is not automatically a vulnerability.

---

# SECOND-PASS GAP ANALYSIS

After the initial research pass, review the complete inventory again — this is how a surface earns `exhausted` in `../../coverage-ledger` rather than merely being visited.

Ask:

- Which discovered endpoints have no security disposition?
- Which authorization-sensitive operations were not compared across test identities?
- Are different API versions covered?
- Were list, search, export, and object-detail permissions evaluated consistently?
- Are file permissions aligned with record permissions?
- Were authentication lifecycle transitions evaluated?
- Did public client assets disclose additional in-scope interfaces?
- Were relevant public exposure risks investigated?
- Were business-critical operations included?
- Are backend and infrastructure dependencies mapped?
- Are expensive resources appropriately gated?
- Did any new observation invalidate an earlier conclusion?
- Were suspected vulnerabilities independently verified?
- Were false-positive explanations considered?
- Are some checks blocked by safety restrictions?
- Which unknowns would materially change the risk assessment?

Do not repeat tests without a meaningful new hypothesis.

The second pass should reduce important coverage gaps, not simply increase request volume.

---

# 2026 TACTICS — PROBE / ORACLE / FP-TRAP

Wave-14 additions from disclosed-writeup mining (Nov 2026). Full methods in `playbooks.md` PB-15/16/17; this is the checklist form.

| Surface | Probe | Oracle (proof shape) | FP trap |
|---|---|---|---|
| Any server-side fetch | Point at own echo endpoint; read request headers | `x-envoy-peer-metadata*` (pod IP/name/namespace) or stack-identifying header + internal read response | OAST hit alone = egress only, not internal reach |
| PDF/report/error renderers | `<iframe src=oast>` in fields reflected into error text | OAST callback from server IP; internal body embedded in generated artifact | "HTML in PDF" w/o server-side fetch proof |
| GraphQL | `__type(name:"Mutation")` when `__schema` blocked; enumerate security-sensitive mutations | Victim password/pin changed; admin created | "introspection enabled" alone = informational |
| SAML SPs | Swap NameID in own signed assertion; cross-SP replay; parser differentials | Session minted as victim | XSW theory without forged-session PoC |
| OAuth callbacks | `referrerpolicy="unsafe-url"` + img subresource; `redirect_uri/../` path confusion | Attacker log holds live `code`, exchanged for victim session | Leak-to-own-page w/o code in URL |
| Token-in-URL pages | Inventory SDK sinks (RUM, Segment, GA, Intercom) | Live token + identity field in telemetry payload, still redeeming | Token-in-URL alone; expired/self-scoped replay |
| Multi-step signup flows | Replay minted tokens days later; dork param names | Stale token replays authenticated PII | Self-scoped or expired tokens |
| Chat/support widgets | Boot with victim-shaped `user_data.email`, no hash | Victim chat history loads | `Missing user_hash` = configured; bare 200 ≠ vuln |
| Gateway-fronted APIs | `X-HTTP-Method-Override` / `_method` on undefined-method req | 200-with-data vs 401 baseline | Headers ignored → same 401 both ways |
| CAPTCHA-verify endpoints | Empty/missing/whitespace/garbage tokens | `{"success":true}` for all + privileged surface reachable | Client-side-only success w/o backend privilege |
| Check-then-act endpoints | 20-30 reqs in one H2 packet (slow responders = wide window) | N successes where limit = 1 (negative balance, quota+1) | Flooded 200s w/o business-logic delta |
| WAF + client-side sink pairs | `ja.va.sc.ri.pt.:`-style mismatch payloads (strip order differs) | `alert(document.domain)` on sensitive origin, second account | Self-XSS; delivery needing >2 steps |
| Consent/authorize pages | Popup double-clickjacking under cursor | Recorded PoC + code redeemed | Needs iframe when XFO blocks it — popup is the variant |
| JWT-bearing APIs | jwt_tool battery: `none`, RS256→HS256 w/ public key, `kid` traversal, weak-secret crack | Forged claims accepted / admin granted | Key-shaped value without working forge |

**Credential-shape checks (all surfaces):** classify before testing — publishable (`pk_`*, Supabase publishable, analytics, API client keys) = not a finding; private = authenticate once, prove unlock, deauthenticate. Never exercise a live credential beyond the first proof.

**Desync FP screen:** two responses on one connection is usually keep-alive concatenation, not smuggling — PoCs needing `requestsPerConnection>1` or same-connection send-groups are FPs. Confirm via a *separate*-connection follow-up receiving the prefixed victim response (PortSwigger pipelining-vs-smuggling rule).

**Soft-404 screen:** apps returning 200 for all paths poison every content-discovery result — baseline-probe a nonsense path, fingerprint body hash+length, suppress matching responses. Findings matching the soft-404 fingerprint are FPs.

**Cache-artifact screen:** a 200 on a cached path is not deception — the marker-based proof requires a victim-only marker appearing in the attacker's response to the same cache-keyed URL.
