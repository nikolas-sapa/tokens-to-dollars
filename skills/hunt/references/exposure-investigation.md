# Reference — Deep Exposure Investigation, Extortion Claims & Internal Review

Companion to the `hunt` skill (`../SKILL.md`). Covers: external-to-internal exposure investigation, extortion and historical-compromise investigation, and authorized internal security review.

All activity stays inside the G0–G3 gates and stop conditions in `../../safety-gates`; evidence capture follows `../../evidence`.

---

# DEEP EXTERNAL-TO-INTERNAL EXPOSURE INVESTIGATION

## Objective

Determine whether an authorized external observer can discover publicly exposed resources or security weaknesses involving deeper system components.

The purpose is to map potential access paths and establish safe minimal evidence — not to obtain unrestricted access to protected systems.

## Source code and build exposure

Investigate publicly served authorized resources for:

- Source maps
- Original source files
- Build manifests
- Debug builds
- Accidentally published source archives
- Client-side configuration
- Internal API route references
- Publicly indexed repository references
- Exposed deployment metadata
- Public CI/CD artifacts
- Internal documentation references
- Sensitive comments and development metadata

Determine whether exposed information is genuinely confidential.

Never treat public client configuration as secret merely because it contains an API identifier.

## Backend exposure

Investigate approved application interfaces for observable references to:

- Administrative functionality
- Internal API routes
- Serverless functions
- Background jobs
- Diagnostic features
- Monitoring
- Runtime metadata
- Application service configuration
- Privileged operations
- Backend authentication assumptions

Compare intended and observed authorization boundaries.

Do not authenticate to protected services using accidentally discovered credentials.

## Database and storage exposure

Evaluate publicly accessible and authorized interfaces for:

- Misconfigured anonymous permissions
- Broken row-level security
- Cross-account test-object access
- Cross-tenant synthetic-data exposure
- Incorrect storage object ownership
- Private file exposure
- Overly broad API reads
- Overly broad API writes
- Sensitive error disclosures
- Unsafe data caching
- Inconsistent backend authorization

Use test-owned data only.

## Infrastructure and operational exposure

Investigate permitted public evidence of:

- Exposed diagnostics
- Public monitoring output
- Application logs inadvertently published
- Deployment configuration leaks
- Build artifact exposure
- Backup references
- Public storage configuration
- DNS ownership anomalies
- Cloud integration details
- Insecure administrative interface exposure

Distinguish a discovered reference from actual unauthorized access.

## Access-path mapping

For each potential path, produce:

**External entry point → Public discovery → Suspected security weakness → Trust boundary → Safely verified capability → Potential deeper consequence → Unverified requirements**

Possible states:

- DIRECTLY EXPOSED
- AUTHORIZATION FAILURE CONFIRMED
- PLAUSIBLE ACCESS PATH
- UNVERIFIED HYPOTHESIS
- OWNER-SIDE REVIEW REQUIRED
- NOT REPRODUCED
- OUT OF SCOPE

Do not assert that source-code, database, infrastructure, or administrative compromise has occurred without supporting evidence.

## Internal review escalation

Where deeper verification requires protected access, prepare an owner-authorized follow-up request identifying the minimum necessary evidence.

Examples:

- Read-only source review
- Cloud IAM policy export
- Database permission export
- Redacted audit logs
- Deployment configuration review
- Authorized infrastructure manifests
- CI/CD workflow review
- Storage policy inspection

Conduct internal reviews only after the relevant access has been explicitly granted.

---

# EXTORTION AND HISTORICAL COMPROMISE INVESTIGATION

## Scenario

The application owner may have received a claim that an outside party gained unauthorized access and demands payment.

Treat the claim as unverified.

Investigate whether the application's observable security weaknesses could plausibly support the claimed access.

Separate the following conclusions:

1. A vulnerability exists.
2. The vulnerability may enable unauthorized access.
3. Unauthorized access was safely reproduced.
4. Evidence indicates an actual third party previously exploited it.

These are fundamentally different claims.

## Required compromise assessment

Report:

- Verified access paths
- Possible but unverified paths
- Security boundaries affected
- Demonstrated privileges
- Potential consequences
- Historical evidence unavailable externally
- Logs and records requiring owner review
- Immediate protective measures
- Confidence level

## Verdict classifications

**CONFIRMED ACCESS PATH**

A relevant unauthorized capability was safely reproduced using permitted test resources.

**PLAUSIBLE ACCESS PATH**

Serious evidence supports a possible route, but complete validation is unavailable or unsafe.

**NOT REPRODUCED**

The authorized tests did not establish the claimed unauthorized capability.

**INDETERMINATE**

Insufficient evidence, authority, or technical access exists to decide.

Never declare that a real intrusion happened merely because an exploit path exists.

---

# INTERNAL SECURITY REVIEW WHEN AUTHORIZED

When the owner provides authorized internal evidence, expand the assessment beyond black-box testing.

## Source-code review

Evaluate:

- Backend authorization
- Identity validation
- Unsafe data flows
- Sensitive operations
- Secret handling
- File processing
- Injection sinks
- Input validation
- Error handling
- Session management
- Business rules
- Dependency risks
- Logging and monitoring coverage

## Database configuration review

Evaluate:

- Role permissions
- Row-level security
- Tenant isolation
- Service-account privileges
- Public data access
- Storage policies
- Data export restrictions
- Backup protections
- Audit logging

## Infrastructure review

Evaluate:

- IAM policies
- Cloud role trust
- Network isolation
- Service configuration
- Deployment permissions
- CI/CD secrets
- Public storage
- Backup access
- Monitoring permissions
- Container privileges
- Kubernetes manifests

## Incident evidence review

Evaluate provided:

- Authentication logs
- Session events
- Administrative activity
- API access logs
- Database audit events
- Storage logs
- Cloud control-plane events
- Financial usage records
- Privilege changes
- Configuration changes

Use only resources explicitly provided or made available through approved access.

Do not attempt to gain internal access through discovered secrets.
