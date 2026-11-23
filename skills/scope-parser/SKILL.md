---
name: scope-parser
description: Parse a bug bounty program's policy page plus platform scope data into a machine-enforced rules-of-engagement manifest. Run at gate G0 before any worker touches a target, and re-run whenever the manifest is stale. The manifest is the only scope authority — memory of past scope never authorizes.
---

# scope-parser

Converts prose program policy into `roe-manifest.md`: a per-program,
machine-checkable rules-of-engagement file at
`memory/targets/<program>/roe-manifest.md`. Every asset check, rate decision,
and worker dispatch in later gates reads this file and nothing else.

## Inputs

1. Normalized program record from `tools/ingest-scope` (`data/programs.json`):
   `platform`, `name`, `url`, `max_payout`, `safe_harbor`,
   `excluded_methods[]`, `in_scope[]`, `out_of_scope[]`, `testing_policy_url`.
2. The program's public policy page, fetched live at run time
   (`testing_policy_url`, falling back to the platform program page). Store
   the SHA-256 of the fetched body as `policy_hash`; it drives staleness.
3. The platform's own ToS / code of conduct. Platform rules bind on top of
   the program page — the Immunefi Safe-Harbor clickwrap accepted at signup
   is stricter than most program pages. Same stricter-reading
   reconciliation as the page itself.

Never work from memory or a stale fetch. If the policy fetch fails, still emit
a manifest seeded from `programs.json` with everything else in `unknowns`.
That manifest denies almost everything, which is the correct failure mode.

## Procedure

1. Load the `programs.json` record; seed scope lists and `excluded_methods`.
2. Fetch the policy page. Extract, in order of authority:
   a. explicit in/out-of-scope asset tables (override feed data on conflict)
   b. prohibited testing methods and their carve-outs
   c. automation / AI / scanner clauses
   d. rate limits, test-account rules, VPN/Tor or header requirements
   e. safe-harbor text, disclosure and embargo terms
3. Reconcile feed vs page: **the stricter reading wins** on every conflict.
4. Write `roe-manifest.md` (schema below). Anything not found in a source goes
   in `unknowns`: never invent a rule.
5. Record `fetched_at` and `policy_hash`.

## Staleness

Re-run this skill when `now - fetched_at > 7 days` OR a refetched policy hash
differs from `policy_hash`. A stale or missing manifest blocks the gate; do
not test on it.

## Manifest schema

```markdown
# RoE Manifest — <program name>

## identity
platform:     hackerone
program:      <handle>
policy_url:   https://...
fetched_at:   2025-01-14T09:30:00Z
policy_hash:  sha256:...
contact:                        # report channel; read by reporter's channel pick
  email:        null            # report-to address; null = submit via platform
  source:       null            # security-txt | diodb | policy-page — never guessed
  securitytxt:  null            # the /.well-known/security.txt that supplied it
  encryption:   null            # published PGP key URL, if offered
  languages:    null            # security.txt Preferred-Languages, if given

## authorized_assets
# eligible_for_bounty=false assets may be mapped for context but never attacked
- asset: "*.example.com"        type: wildcard-domain  eligible_for_bounty: true
- asset: "api.example.com"      type: domain           eligible_for_bounty: true
- asset: "internal.example.com" type: domain           eligible_for_bounty: false

## hard_denylist
# wildcard carve-outs: "*.example.com" in scope does NOT include these
- "excluded.example.com"
- "*.staging.example.com"
- pattern: "third-party:*"    # any asset not program-owned

## prohibited_methods          # source clause -> blocked techniques -> gate ceiling
- method: dos                  blocks: [flooding, load-testing, resource-exhaustion]  ceiling: G2-capped, manual only
- method: social_engineering   blocks: [phishing, pretexting, vishing, smishing]      ceiling: G0
- method: automated_scanning   blocks: [nuclei, dirb-fuzzing, mass-crawling]          ceiling: G1 for automation
- method: physical             blocks: [onsite, hardware, badge-cloning]              ceiling: G0
- method: third_party          blocks: [vendor attacks, supply-chain probes]          ceiling: G0

## automation_policy
ai_output: validation-required   # stated-allowed | validation-required | banned
ai_disclosure: unstated          # required | incentivized | not-required | unstated
submitter: human                 # ALWAYS human — autonomous submission is out of scope

## rate_limits
rps_cap: null                    # null = unstated -> default-safe profile (<=1 rps, jittered)
test_accounts: unstated          # required | provided | forbidden | unstated
submission_cost: null            # optional — YesWeHack credits (refunded + bonus on acceptance),
                                 # Sherlock USDC stake (forfeited on invalid), Cantina deposits
notes: ""

## safe_harbor
status: true
disclosure: coordinated          # coordinated | nda-bound | none | unstated
embargo_days: null

## enforcement
# program-reality, not scope — these shape EV and pacing, never authorization;
# anything unstated defaults to its most restrictive reading
signal_gate: null                # min account Signal to submit — H1 programs gate at a
                                 # configurable -1.0..7.0; newcomers get 3 trial reports,
                                 # then a 90-day pause on the 3rd failure
submission_throttle: null        # account-level report-rate cap — Bugcrowd: 6/week below
                                 # 50% accuracy; new accounts throttled by default
idv_required: unstated           # payout | submission | none — Intigriti moved IDV to
                                 # submission Oct 2026; Bugcrowd mandatory on managed programs
trial_quota: null                # newcomer allowances — H1: 3 trial reports; GitHub: 4

## unknowns
# not found in source: each item is treated as its most restrictive reading
- "embargo window"
- "retest policy for fixed findings"
```

## Enforcement rules (load-bearing)

- **Not in `authorized_assets` = denied.** Wildcards do not expand into
  denylisted carve-outs; subdomains of a denied asset are denied.
- **Stricter reading wins** on every feed-vs-page, page-vs-platform-ToS,
  or intra-page conflict.
- **`unknowns` default restrictive**: unstated automation = validation-required;
  unstated rps = <=1; unstated safe harbor = treat as absent.
- **The manifest is the only scope authority.** Past runs, memory graph nodes,
  and older manifests never authorize anything.
- **Prohibited-method ceilings are hard.** A worker that cannot operate under
  the ceiling for a target is not dispatched there.
- **`enforcement` fields are program-reality, not scope.** Signal gates,
  throttles, IDV, and trial quotas shape EV and pacing — they never
  authorize, widen, or narrow `authorized_assets`.

## Minimal-scope extraction

- **A hostname in the goal text means subdomain scope.** `api.acme.com`
  stays `api.acme.com` — never collapse it to `acme.com`. Only bare
  root-domain or entire-site phrasing ("acme.com", "all acme properties")
  produces a wildcard or root-domain entry.
- **Constraints are self-contained.** Rewrite deictic references — "the
  target", "this program", "it" — to the concrete asset or program at
  extraction time. A constraint that only parses inside the source
  paragraph is a bug, not shorthand.
- **Deny on doubt.** An asset whose scope kind is ambiguous resolves to
  the narrower reading: `domain` over `wildcard-domain`, context-only
  (`eligible_for_bounty: false`) over eligible, `unknowns` over a guess.
- **Scope widens only via explicit top-level writes** to
  `authorized_assets` — never as a side-effect of a derived entry, an
  inference, or denylist arithmetic.

## Worked example

Policy text (fake program "Acme Corp"):

> In scope: `*.acme.example`, `api.acme.example`. Out of scope:
> `status.acme.example`, any third-party service. No DoS testing, no social
> engineering, no automated scanners. Tooling must stay under 5
> requests/second. Create your own test accounts. Acme provides safe harbor.
> Reports generated solely by unverified AI tools will be closed as N/A.

Produces (excerpt):

```markdown
## authorized_assets
- asset: "*.acme.example"   type: wildcard-domain  eligible_for_bounty: true
- asset: "api.acme.example" type: domain           eligible_for_bounty: true
## hard_denylist
- "status.acme.example"     # wildcard carve-out
- pattern: "third-party:*"
## prohibited_methods
- method: dos                 blocks: [flooding, load-testing]    ceiling: G2-capped, manual only
- method: social_engineering  blocks: [phishing, pretexting]      ceiling: G0
- method: automated_scanning  blocks: [nuclei, dirb-fuzzing]      ceiling: G1 for automation
## automation_policy
ai_output: validation-required   # "unverified AI ... closed as N/A"
submitter: human
## rate_limits
rps_cap: 5
test_accounts: required           # "create your own"
## safe_harbor
status: true
disclosure: coordinated
## unknowns
- "embargo window"
- "duplicate-handling policy"
```

Note the AI clause: the program banned *unverified* AI output, not AI itself —
mapped to `validation-required`, not `banned`. When a program states a harder
rule (e.g. "no automated or AI-generated reports", as some fintech programs
do), `ai_output: banned` hard-blocks the pipeline at G0.

## Automation policy — verdict taxonomy

The automation clause gets a classifier pass, not a vibe read (ported from
contribot's `aipolicy.ts`). Each candidate sentence — any line matching AI /
LLM / automation / machine-generated terms — is classified, and the verdicts
roll up:

| Verdict | Meaning | Manifest mapping |
|---|---|---|
| `banned` | ≥1 negative-matching clause, zero positive | `ai_output: banned` — hard-blocks at G0 |
| `welcomed` | ≥1 positive clause, zero negative | `ai_output: stated-allowed` |
| `bounty-ineligible` | AI reports accepted but excluded from payout (the NodeBB class) | `ai_output: stated-allowed` + `notes` carries the unpaid flag — the reporter must not price a reward |
| `ambiguous` | both polarities present, or AI terms appear with no clear polarity | `validation-required` + the evidence lines kept for the human |
| `unmentioned` | no AI/automation clause found | `validation-required` (default restrictive, per `unknowns`) |

Every clause that fed the verdict is kept as an evidence line
(`<source>: <clause>`) — the manifest's `notes` field carries them so the
human can audit the call.

`ai_disclosure` rides alongside `ai_output` — a separate axis recording
whether the program demands AI involvement be declared. Intigriti and
PubNub mandate it; Goldman pays a $50 bonus for it (`incentivized`).
`required`/`incentivized` makes the reporter emit its AI-methodology
block; `unstated` defaults to omitting it.

**Negation traps** — the three ways a naive "contains 'not'" classifier
misfires, handled explicitly:

| Trap | Shape | Correct read |
|---|---|---|
| `NEGATED_POSITIVE` | "AI reports are **not** permitted / not welcome / never allowed" | Negative — the negation attaches to a permission word |
| `DOUBLE_NEGATIVE` | "**not** against / does not prohibit AI assistance" | Positive — negating a prohibition word cancels to a permission |
| `NULL_CONTEXT` | "**no** restrictions on tooling / no policy on AI use" | Not a ban — "no" scopes a noun (policy, restrictions), not the activity |

Worked clause extraction (fake + real policy lines):

| Policy clause | Verdict | Evidence line |
|---|---|---|
| "Reports generated solely by unverified AI tools will be closed as N/A" | negative → `validation-required` | `policy: reports generated solely by unverified ai tools will be closed` |
| "We do not accept AI-generated submissions" | negative → `banned` | `policy: we do not accept ai-generated submissions` |
| "AI-assisted research is welcome; humans must verify" | positive → `stated-allowed` | `policy: ai-assisted research is welcome` |
| "Submissions are not permitted to be machine-written" | `NEGATED_POSITIVE` → `banned` | `policy: not permitted to be machine-written` |
| "Nothing in this policy restricts your tooling" | `NULL_CONTEXT` → not a ban; no AI verdict | `policy: no restrictions on tooling` |
| "We are not opposed to automation" | `DOUBLE_NEGATIVE` → positive | `policy: not opposed to automation` |

Mixed pages (a program welcoming AI recon but banning AI-written reports)
land `ambiguous` — both evidence lines are kept and `validation-required`
applies, which is the conservative reading anyway.

A second, real-policy worked example — a full severity/USD table,
numbered exclusions, and channel-by-severity reporting rules — is in
`references/paraloom-policy-example.md`.
