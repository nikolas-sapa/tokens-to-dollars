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

## Verdicts

- **novel**: no source produced a same-root-cause match. Clears for reporting.
- **duplicate**: a disclosed report, advisory, or changelog entry covers the
  same root cause on the same asset. Do not draft. Log the collision in the
  exploration graph and move on.
- **partial-overlap**: same class or same area, different root cause,
  endpoint, or primitive. Forces an **impact-differentiation paragraph** in
  the report ("prior report #X covered `/logout?next=`; this finding reaches
  the payment frame via `/cart?next=`"), or reroute back to hunt for a more
  distinct variant.
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
    - id: "H1-2345678"  url: "https://hackerone.com/reports/2345678"  overlap: "same class, different param"
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
- **Citations are mandatory** for any non-`novel` verdict: list the report
  IDs/URLs that caused it in `matches`.
- **Dedupe again on retest.** If a finding is revisited days or weeks later,
  re-run this skill. Someone may have disclosed the same bug in the meantime.
