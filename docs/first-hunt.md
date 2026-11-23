# Your first hunt — a worked example

End-to-end run of the `../AGENTS.md` pipeline on a fictional program:
"Acme Corp" on HackerOne (handle `acme`). Paths, formats, and gates are
real; the target and token counts are not.

## Step 0 — pull the catalog, pick the program

```bash
python3 tools/ingest-scope/ingest_scope.py --out-dir data/
# optional: python3 tools/ingest-knowledge/ingest_knowledge.py --out-dir knowledge/
```

`data/programs.tsv` arrives ranked by `max_payout`:

```tsv
platform   name        max_payout   safe_harbor   n_in_scope   url
hackerone  Acme Corp   20000        true          14           https://hackerone.com/acme
```

Pick on payout ceiling, safe harbor, and scope fit — a wildcard plus an
API beats a lone marketing site. Then: `Hunt acme under the orchestrator skill.`

## Step 1 — scope-parser writes the manifest

`skills/scope-parser` merges the catalog record with the live policy page.
Acme's policy says, in part:

> In scope: `*.acme.example`, `api.acme.example`. Out of scope:
> `status.acme.example`, third-party services. No DoS, no social
> engineering. Own test accounts; safe harbor provided.

Policy is silent on automation and AI — restrictive defaults apply.
Output: `memory/targets/acme/roe-manifest.md` (excerpt):

```markdown
## authorized_assets
- asset: "*.acme.example"   type: wildcard-domain  eligible_for_bounty: true
- asset: "api.acme.example" type: domain           eligible_for_bounty: true
## hard_denylist
- "status.acme.example"          # wildcard carve-out
## prohibited_methods
- method: dos                  blocks: [flooding, load-testing]   ceiling: G2-capped, manual only
- method: social_engineering   blocks: [phishing, pretexting]     ceiling: G0
## automation_policy
ai_output: validation-required   # policy silent -> restrictive default
submitter: human                 # ALWAYS human
## rate_limits
rps_cap: null                    # unstated -> default-safe profile (<=1 rps, jittered)
## unknowns
- "automation/AI clause"         # absent -> treated as validation-required
```

Takeaways: `status.acme.example` stays denied despite the wildcard scope,
and `validation-required` means every drafted claim needs executed proof.

## Step 2 — orchestrator wake

The orchestrator loads `memory/targets/acme/` (empty first run), records
`target-profile.md`, builds the planner brief, opens `exploration-graph.md`:

```markdown
- [G-1] goal: prove one bounty-eligible boundary break inside the acme manifest — type: web-program
- [I-1] intent: enumerate api.acme.example surface from JS + test-account walk — spawns: G-1 — gate: G1 — technique: recon — status: done
- [F-1] fact: /graphql answers {"data":{"__typename":"Query"}}; Apollo fingerprint — derived_from: I-1 — anchor: AS-0007
```

## Step 3 — a worker finds a candidate

F-1 points at PB-1 (GraphQL). The worker claims the surface in
`memory/targets/acme/coverage.md` before touching it:

```markdown
| surface | claimed-by | status | technique tried | notes | AS-node |
|---|---|---|---|---|---|
| api.acme.example/graphql | int-0007 | in-progress | introspection, schema-map, cross-acct-read | Apollo; user(id:) exposed | AS-0007 |
```

Introspection succeeds; `user(id:)` returns `email`, `phone`,
`ssn_last4`. With two owned test accounts the worker reads A's record as B:

```markdown
- [F-6] fact: user(id:4471) returns acct-A PII under acct-B session — no object-level authz — derived_from: I-3 — anchor: AS-0007
```

## Step 4 — validation gate: what "proven" means

A candidate, not a finding — a second worker (never the finder) confirms
it under `skills/evidence`:

- **Reproduced independently.** Clean session as acct-B; acct-A's record again.
- **Committed-state checked.** Fresh `Date`+nonce; server-side, not a misread 200.
- **Evidence bound.** `evidence/int-0009-a/` holds verbatim req/resp, a
  `notes.md` naming both test accounts + scope line, a curl PoC.

Three checks pass → the fact becomes `- [FD-1] finding:` on the graph.

## Step 5 — dedupe-check verdict

Before drafting, `skills/dedupe-check` appends to the finding record:

```yaml
dedupe:
  verdict: novel
  checked_at: 2026-03-01T16:44:00Z
  searched:
    - source: program_hacktivity   queries: 3  hits: 0
    - source: cve_nvd_ghsa         queries: 2  hits: 0
    - source: changelog            queries: 1  hits: 0
    - source: knowledge_corpus     queries: 0  hits: 0   # not ingested this run
  matches: []
  differentiation_required: false
```

Three sources clean, one gap declared — silent gaps are how duplicates slip.

## Step 6 — reporter drafts, ledger counts

`skills/reporter` writes `reports/acme/int-0009-a.md` (skeleton):

```markdown
# IDOR on api.acme.example allows any user to read arbitrary user PII

## Summary
The `user(id:)` resolver at /graphql does no object-level authz — any
free-tier account reads another user's PII by numeric id.

## Steps to reproduce
1. Register free account B; keep its bearer token.
2. POST {"query":"{user(id:4471){email phone}}"} to /graphql
   (verbatim in evidence/int-0009-a/request.txt).
3. Response contains account A's record. Repeat with another id.

## Impact
Attacker: any registered user. Action: read any user's PII by id
(demonstrated between two owned accounts). Victim: Acme's user base.
Loss: per-record PII exposure over a sequential id space.
```

`skills/token-ledger` records the cost in `memory/ledger.md`:

```markdown
| date | program | intent-id | worker | model | in-tokens | out-tokens | est-$ | outcome | finding-id |
|------|---------|-----------|--------|-------|-----------|------------|-------|---------|------------|
| 2026-03-01 | acme | int-0007 | hunt-graphql | flagship | 182400 | 11900 | 3.63 | fact | - |
| 2026-03-01 | acme | int-0009 | hunt-graphql | flagship | 141800 | 14800 | 3.24 | finding | int-0009-a |
| 2026-03-01 | acme | int-0010 | verify | mid-tier | 61200 | 5400 | 0.26e | fact | - |
```

One finding, ~$7.10 burned. That arithmetic is the entire business model.

## Step 7 — the human submits

The pipeline ends at `reports/acme/SUBMIT-CHECKLIST.md`:

```markdown
- [ ] int-0009-a — IDOR/BOLA on api.acme.example/graphql — severity high — evidence ok — dedupe clean — pending human submit
```

Before you check that box:

1. Open the draft; paste the PoC yourself — verbatim, clean test account.
   Every claim needs a file in `evidence/int-0009-a/`.
2. Re-run dedupe — the verdict admits `knowledge/` wasn't searched.
3. Check the always-rejected list; argue Acme's own severity table.
4. Submit via the platform UI; log `submitted`/`paid` in `memory/ledger.md`.

Agents found it, proved it, priced it, wrote it up — you decided it
ships. That division of labor is the product.

If the channel is email — the program runs a VDP or publishes a
security.txt contact instead of a platform page — the checklist line is
the same, but step 4 becomes "send the mail":

- The address comes from the manifest `contact` block only
  (security.txt, diodb, policy page). No source, no draft — it's an
  `unknowns` entry.
- Draft per `skills/reporter/references/disclosure-email.md`: same
  evidence rules, plain text, attachments by filename, a stated 90-day
  disclosure timeline.
- Program publishes a PGP key? The checklist records it; encrypting is
  the submitter's call.
