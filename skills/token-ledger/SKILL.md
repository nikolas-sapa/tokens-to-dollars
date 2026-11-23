---
name: token-ledger
description: Per-intent token spend and payout accounting. The scoreboard skill — every closed intent gets a ledger line, every finding gets payout tracking, all metrics derived on demand. Cost-honesty rules: provider-reported beats computed, priced-or-silence totals, cheap-first escalate-on-verified-failure routing. Answers "dollars in, dollars out."
---

# token-ledger

The scoreboard. Bug bounty hunting is an economics problem: tokens go in,
validated findings and payouts come out. This skill defines the append-only
ledger the orchestrator writes to, the cost-estimation rules, and the metrics
anyone can compute from it. If the ledger can't show a positive return, the
fleet is burning money — say so, don't hide it.

## The ledger file

`memory/ledger.md` — append-only, plain markdown tables, greppable by design.
Two sections. Never edit existing rows; corrections and status changes are
new rows. `memory/` is user-local and gitignored: the ledger never leaves
the machine.

### Intent rows

One line per **closed** intent (a unit of dispatched work, see
`../orchestrator`):

```
| date | program | intent-id | worker | model | in-tokens | out-tokens | est-$ | outcome | finding-id |
|------|---------|-----------|--------|-------|-----------|------------|-------|---------|------------|
| 2026-03-01 | acme-h1 | int-0142 | hunt-idor | opus | 182400 | 11900 | 4.87 | finding | F-0031 |
| 2026-03-01 | acme-h1 | int-0143 | hunt-xss | mini | 96400 | 8200 | 0.62e | blocked | - |
```

- `outcome` ∈ `finding | fact | FP | blocked`
  - `finding` — passed all gates, submit-ready; `finding-id` links to evidence.
  - `fact` — no vuln, but durable knowledge produced (asset map, fingerprint).
  - `FP` — flagged, rejected by validation or review. Real burn; log it.
  - `blocked` — killed by scope/RoE, dedupe, or cost ceiling. Still cost tokens.
- `est-$` — the suffix declares the basis: `p` provider-reported (`4.87p`),
  `u` computed upper bound (`5.20u`), `e` estimated (`0.62e`), `?` not
  priced. Bare number = computed from real usage at named rates. Never mix
  silently — the marker is part of the number.

### Payout rows

One line per finding status change:

```
| date | program | finding-id | status | amount |
|------|---------|------------|--------|--------|
| 2026-03-05 | acme-h1 | F-0031 | submitted | - |
| 2026-03-19 | acme-h1 | F-0031 | paid | 1500 |
```

- `status` ∈ `submitted | triaged | resolved | paid | N/A`
  (`N/A` covers closed-without-bounty, including duplicates).
- `amount` in USD, `-` until `paid`.

## Cost estimation

Real token counts come from the harness's API response when available. When
the agent can't see them, estimate: `in-tokens ≈ context size`, `out-tokens ≈
generated chars / 4`, and mark the row with the `e` suffix.

**Model pricing lives here — update this table when models or prices change.**
Rows are costed at the rate in effect at write time:

```
| model   | $/M in | $/M out |
|---------|--------|---------|
| flagship | 15.00 | 75.00  |
| mid-tier | 3.00  | 15.00  |
| budget   | 0.30  | 1.20   |
```

`est-$ = (in-tokens / 1M × rate-in) + (out-tokens / 1M × rate-out)`.
Rates above are examples; check your provider's current pricing.

## Cost honesty

- **Provider beats computed.** A provider-reported `cost` outranks any
  arithmetic here — it already knows cache discounts, tiers, and rounding.
  Mark the row `p`.
- **Cached input tokens are a separate quantity.** `prompt_tokens`
  excludes cache reads, which live in `cached_input_tokens` and are
  usually billed at a discount. Track them beside `in-tokens` (notes or a
  dedicated column), priced at a cached rate when configured — at full
  input rate otherwise, flagged `u` (upper bound). `reasoning_tokens` are
  already inside `out-tokens`; never add them twice.
- **Priced or silence.** A total is reported only when every row in it is
  priced. Any `e`/`?` member makes the total "unavailable (pricing
  incomplete)" — never invent a dollar figure to fill the gap. `$0.00`
  reads as free, not unmeasured.
- **Name the rates.** Every computed figure records the rates behind it
  (row notes or ledger header: `rates: in=$3/M out=$15/M`). A dollar
  figure with no rate beside it cannot be audited — quote it with its
  rates or not at all.
- **Cheap first, escalate on verified failure.** Route each intent to the
  cheapest model plausibly able to run the technique; escalate one tier
  only when a deterministic validator says the attempt failed — replay
  mismatch, rejected invariant test, tool refusal, missing artifact. A
  worker's own sense it is struggling is not a validator. Each tier is its
  own row (model + cost recorded); which tier solved it and the first-tier
  success rate feed `../orchestrator`'s yield routing. The failed step's
  evidence rides the escalated packet — escalation continues the attempt,
  it does not restart it.

## Derived metrics (computed on demand, never stored)

The ledger is the only stored truth; dashboards are throwaway views computed
by `tools/ledger` or any script over the tables:

- **Cost per finding** — Σ est-$ / count(finding), sliced by program,
  technique/playbook, and model. Answers "which lane earns its tokens."
- **Yield ranking** — findings (and paid $) per 1M tokens per technique.
  This feeds `../orchestrator`'s technique ledger: the planner allocates more
  intents to high-yield lanes and starves losers.
- **EV tracking** — Σ payout amount / Σ est-$. EV > 1 means the fleet pays
  for itself. Report per program; power-law payouts mean median EV ≪ mean.
- **Breakeven dashboard** — cumulative token $ vs cumulative payout $ over
  time, plus spend-remaining-vs-ceiling per program.

## Rules

- **The orchestrator writes rows at intent close — workers never write their
  own.** A worker grading itself produces inflated counts and quiet
  omissions. The dispatcher holds the pen.
- **Honest accounting.** `FP` and `blocked` rows stay in and count toward
  cost-per-finding. Deleting or downgrading embarrassing rows turns the
  scoreboard into marketing — the one unforgivable ledger sin.
- **Cost ceiling.** Intents may carry a `cost-ceiling` field (max est-$).
  The planner polls cumulative spend and kills the intent on breach, logging
  a `blocked` row. This is the brake on runaway spend.
- Append-only. Payout status changes are new rows, not edits.

## Feeds

- `../orchestrator` — yield ranking drives technique allocation; cost
  ceilings bound dispatched intents.
- `../reporter` — finding-ids and payout statuses line up with submission
  tracking; a `paid` row should trace back to a submitted report.
