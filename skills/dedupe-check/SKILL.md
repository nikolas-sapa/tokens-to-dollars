---
name: dedupe-check
description: Determine whether a validated finding is already disclosed or a known-accepted-risk before any report is drafted. Searches the program's disclosed activity, the knowledge/ disclosed-report corpus, CVE/NVD/GHSA, program changelogs, and platform always-rejected lists, then appends a cited verdict to the finding record. Run after validation and before the reporter skill, every time.
---

# dedupe-check

Duplicates and known issues are the #1 reason AI-assisted reports get closed
N/A. This skill runs **before** any submission is drafted: a `novel` verdict
clears the finding for reporting; anything else reroutes or kills it.

## Finding signature

Extract once from the finding record; every search below uses it:

```yaml
signature:
  asset: "checkout.acme.example"     # in-scope host / app / contract
  vuln_class: "CWE-79"               # CWE preferred; else short class label
  endpoint_pattern: "/cart?next="    # path + param, generalized
  primitive: "reflected XSS via next param"   # exploit primitive, one line
```

Generalize `endpoint_pattern` (strip IDs, collapse path params) or matches
against disclosed reports will not fire.

## Sources

Search all five; record every query and hit count.

| # | Source | What you check |
|---|--------|----------------|
| 1 | Program disclosed activity | H1 hacktivity / activity feed, Bugcrowd / Intigriti / YWH disclosed lists for this program: same class on same asset |
| 2 | `knowledge/` corpus | Local mirror of H1 disclosed archives (indexed by CWE + program), ingested by `tools/ingest-knowledge`: signature match |
| 3 | CVE / NVD / GHSA | Vuln class + affected component/version: the finding may be a published advisory on an in-scope dependency |
| 4 | Program changelog / release notes / security page | Recently-fixed classes: fix may have shipped between discovery and your retest |
| 5 | Platform always-rejected lists | Self-XSS, missing SPF/DMARC, missing security headers, clickjacking on login-less pages, etc. See the always-rejected classes list maintained by `../reporter` |

## Method

1. Build the signature.
2. Search sources 1–5. Log each query and its hit count. **Zero hits still
   gets recorded**, because the verdict must state what was searched.
3. For each hit compare on four axes: same asset? same vuln class? same root
   cause (endpoint/param pattern)? same primitive?

## Multi-view dedup

The four-axis check is necessary but shallow — two reports can share asset
and class and still be different bugs. Score each candidate match on five
views independently:

- **Description** — same stated root cause and trigger, not just same CWE.
- **Reproduction** — same steps and same payload shape after normalization.
- **Location** — same code path, not just same host. Normalize before
  comparing: numeric, UUID, and hex path/parameter segments collapse to
  `{id}` (`/users/4821/orders/9f3a` -> `/users/{id}/orders/{id}`), so an ID
  difference never masks a same-endpoint match.
- **Impact** — same demonstrated consequence; a weaker variant of a
  disclosed bug is still a dup.
- **Structural** — same code shape under renaming. Normalize the candidate
  to a structural signature and compare signatures, not text. Same
  signature + same asset = same bug pre-PoC even when identifiers, param
  names, and payload strings all differ — the analog of the ~45% pre-PoC
  duplicate cut structural matching buys before an exploit is attempted.
  A different sink or source type is a different signature; the view
  abstains when neither side exposes code or a normalized request pair.

### Structural signature format

`shape:<func-shape>/sink:<sink-type>/src:<source-type>` — computed by pure
pattern rules over the implicated code or request pair, no AST library:

1. Collapse every identifier to `id` and every string/numeric literal to
   `lit` in the implicated code or request pair.
2. `func-shape` — the control-flow skeleton carrying tainted data, as a
   hyphen-joined call/flow sequence (`assign-then-call`,
   `concat-then-sink`, `loop-filter-then-sink`).
3. `sink-type` — the dangerous operation class: `sql-query`, `exec-shell`,
   `redirect`, `template-render`, `deser`, `file-read`, `file-write`,
   `ssrf-fetch`, `dom-write`, `eval`, `authz-check`.
4. `src-type` — where attacker input enters: `query-param`, `path-seg`,
   `header`, `cookie`, `body-field`, `file-upload`, `ws-msg`,
   `graphql-arg`.

Example: `shape:concat-then-sink/sink:sql-query/src:header` is one
signature whether the header was `X-Ref` or `Referer` and the payload
`' OR 1=1` or `1'`.

The fix boundary is the real test. **Same root cause closed by one patch =
duplicate**, even across different endpoints or params. **Different fixes
needed = related-not-duplicate** — score as `partial-overlap` and argue
independent fix-ability.

Platform math (Coinbase 2026 attrition): 44% duplicate / 37% informative /
15% invalid / 4% paid. Dedup before submission is the difference between
Signal-positive and a 90-day H1 pause.

## Verdicts

- **novel**: no source produced a same-root-cause match. Clears for reporting.
- **duplicate**: a disclosed report, advisory, or changelog entry covers the
  same root cause on the same asset. Do not draft. Log the collision in the
  exploration graph and move on.
- **partial-overlap**: same class or same area, different root cause,
  endpoint, or primitive. Forces an **impact-differentiation paragraph** in
  the report ("prior report #X covered `/logout?next=`; this finding reaches
  the payment frame via `/cart?next=`"), or reroute back to hunt for a more
  distinct variant. The paragraph must argue two things: **independent
  fix-ability** (the fix is a separate code change, and separate fixes earn
  separate rewards) and **impact delta** (what this variant reaches that
  the original did not).
- **known-accepted-risk**: the program or platform explicitly lists the class
  as out of scope or always-rejected. Do not report. Ever.

## Output

Append to the finding record in the exploration graph:

```yaml
dedupe:
  verdict: novel            # novel | duplicate | partial-overlap | known-accepted-risk
  checked_at: 2025-01-14T10:02:00Z
  searched:
    - source: program_hacktivity   queries: 3  hits: 0
    - source: knowledge_corpus     queries: 4  hits: 2
    - source: cve_nvd_ghsa         queries: 2  hits: 0
    - source: changelog            queries: 1  hits: 0
    - source: reject_list          queries: 1  hits: 0
  matches:
    - id: "H1-2345678"  url: "https://hackerone.com/reports/2345678"
      overlap: "same class, different param"
      original_state: resolved            # resolved | triaged | open | unknown
  differentiation_required: false
```

## Example

Finding: reflected XSS on `checkout.acme.example` via `GET /cart?next=`.

- Source 1 (hacktivity): report H1-2345678, disclosed 3 months ago: stored
  XSS in the cart `notes` field on the same host. Different root cause,
  different primitive -> not a duplicate.
- Source 2 (knowledge/): two hits for CWE-79 + acme, both on `blog.acme.example`
  -> not same asset.
- Sources 3–5: no hits; `checkout.acme.example` not on the always-rejected list.

Verdict: `partial-overlap`. Report must differentiate from H1-2345678
("prior finding was stored XSS in `notes`; this is reflected XSS in `next`
reaching the payment frame"), with H1-2345678 cited in `matches`.

## Rules

- **Absence of evidence is not evidence of novelty.** A `novel` verdict with
  an empty or missing `searched` list is invalid. If a corpus is unavailable
  (e.g. `knowledge/` not yet ingested), the verdict says so explicitly.
- **`partial-overlap` never silently passes**: either the differentiation
  paragraph ships in the report, or the finding goes back for a variant.
- **A Resolved original is a new report, not a dup.** When a match's
  `original_state` is `resolved` and the bug is back — or the fix is
  bypassed — file fresh as "regression/bypass of #N" with the original
  cited in `matches`; the verdict stays `novel` or `partial-overlap`,
  never `duplicate`.
- **Citations are mandatory** for any non-`novel` verdict: list the report
  IDs/URLs that caused it in `matches`.
- **Dedupe again on retest.** If a finding is revisited days or weeks later,
  re-run this skill. Someone may have disclosed the same bug in the meantime.

## Platform duplicate mechanics (Nov 2026)

- **First-valid wins everywhere** — all four platforms resolve dups by
  first *valid + reproducible*, never first-received. Submission-
  squatting stubs are sanctioned against (Bugcrowd explicit anti-
  squatting rule, Mar 2026). Never race a partial.
- **H1 dedupe = 4 factors:** same vuln type AND same endpoint AND same
  method AND same root cause — SQLi on /api/users vs /api/orders are
  NOT dups. Root cause = "one fix/deploy resolves both."
- **Bugcrowd 3 principles:** (1) "touch the code, pay the bug" — a WAF
  rule doesn't dedupe app-layer bugs; (2) similar ≠ same — distinct
  code paths needing independent fixes pay separately; (3) many ≠
  systemic — missing anti-CSRF on 5/50 endpoints = 5 findings, missing
  framework-wide = 1 systemic.
- **Intigriti:** related findings (same class, different code paths,
  separate fixes) rewarded individually; first TWO valid reports of a
  structural multi-endpoint issue both pay; impact-escalation pays the
  delta (open-redirect→RCE pays RCE minus open-redirect); regressions
  count as net-new.
- **Dup payouts are $0 cash** but account-safe (YWH refunds stake; H1
  refunds trial pre-disclosure; Intigriti counts valid dups positive).
  Killing N/A matters more than killing dups.
- **Calibration:** XBOW's 886-report run hit 23.5% dup + 23.6%
  informative even with deterministic validators — informative =
  policy/impact-framing failure (third-party components, excluded
  classes), not wrongness. Check program exclusions before treating
  "real but unrewarded" as safe.
- **Regression harvesting:** 3–8% of closed bugs resurface via
  incomplete fixes; a re-found regression = net-new report (and paid
  retests earn +rep). Track our Resolved-target surface for re-checks.

## Non-duplicate rules

Two reports matching on any of these are explicitly NOT duplicates —
record `overlap:` but keep the verdict at `novel`/`partial-overlap`:

- **Different parameter, same endpoint** — the bug lives in the input
  handling of a specific parameter; a sibling parameter's defect is its
  own report.
- **Different root cause** — stored vs reflected in the same field,
  missing authz vs broken authz, different primitive class sharing a UI
  symptom.
- **Different severity** — a Medium path and a Critical chain through the
  same code are distinct submissions.
- **Different auth context** — authenticated-vs-unauthenticated reach of
  the same defect = different attacker preconditions = different findings.
- **Different protocol binding** — same bug reachable over REST vs
  GraphQL vs WebSocket is per-binding until shown to share one code path.

When in doubt, split — platforms dedupe on merge for you at no cost; a
merged-out finding that was actually distinct is unrecoverable.

## Council verify

At the verify gate only — a candidate about to be called `verified` —
fan the signature, the hit list, and the draft verdict out to 3
independent runs/models, then cross-rank the returned verdicts
anonymized (each run ranks the others' reasoning without knowing
provenance). Majority verdict stands; a split council keeps the finding
at `plausible` and names the dissent in `matches`.

- Bounded cost: exactly 3 runs, once per candidate, capped tokens each.
- Never per intent, never per fact — council fires once per candidate
  reaching the verify gate, not during exploration.
- Council output appends to the `dedupe` block as `council: {runs: 3,
  verdicts: [...], consensus: <verdict>}` — the disagreement is recorded,
  not averaged away.
