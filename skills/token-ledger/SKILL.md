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

## Per-intent cost attribution

Route each intent's calls through a distinct proxy key or session tag —
a LiteLLM virtual key, a Helicone `session-id`, a per-intent OpenRouter
key — so the provider's own usage record arrives already split by intent.

- **Attribution upgrades the marker.** When the proxy reports spend per
  key or session, `e`/`u` rows flip to provider-reported `p` with no
  token arithmetic to audit — the highest-trust figure becomes the
  default, not the exception.
- **Budgets fail closed.** Set the key's hard `max_budget` equal to the
  intent's `cost-ceiling`: the ceiling is enforced at request time by
  the proxy refusing the call, not by the planner polling cumulative
  spend between calls. Polling is advisory; the key is the brake.
- **One key per intent, never shared.** A shared key smears spend across
  rows and makes per-intent EV uncomputable. Record the key alias —
  never the secret — in the intent's notes so a `p` row traces back to
  the provider report.

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

## EV model + cost-tier routing

Realized EV (Σ payout / Σ est-$) grades the past. Target selection needs
predicted EV, scored per candidate target before dispatch:

`EV = p_find × prec_val × (1 − r_dup) × (1 − r_info) × B_ref − (C_scan + p_find × C_HITL)`

- `p_find` — P(the technique yields a reportable vuln on this target).
- `prec_val` — validator precision on candidates; require ≥ 0.95 from
  deterministic validators (replay, invariant tests) — below that the
  pipeline burns HITL review on noise.
- `r_dup` — P(duplicate); rises with program age and hunter density
  (bounty-radar `competition_score` is the usable proxy).
- `r_info` — P(closes N/A: informative, out-of-scope, intended behavior).
- `B_ref` — reference payout for the vuln class × severity (priors below).
- `C_scan` — token cost of the scan pass. `C_HITL` — human validation cost,
  paid only on confirmed candidates, hence `p_find × C_HITL` — never always.

Model-cost routing frontier (XBOW fall-2026 data): ~$0.10/task micro/RL
models for breadth screening; ~$1/task open-weight fast models for standard
vuln classes; ~$10/task mid-tier for multi-step logic chains; ~$100/task
deep-reasoning for high-value chains. Route cheap → escalate only on
verified evidence (per Cost honesty above); never open on the $100 tier.

Class-EV priors from 2026 payout data, for seeding `B_ref` and `p_find`:
commodity XSS ≈ $635/paid report — saturated at 78-82% of hackbot volume,
avoid; IDOR/authz ≈ $1,265; AI-target vulns $15k–$172k flagships —
fastest-growing class and whitespace (only ~12% of top AI firms run
programs); Immunefi critical median $20k.

Supply elasticity: a program that cuts its reward table sees ~22% fewer
valid reports (~50% fewer criticals). Deprioritize programs that recently
cut bounties; prefer rising tables — feed reward-table velocity from
bounty-radar when detectable.

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

## Provider resilience

Provider calls fail in three distinct ways; handle them as three
distinct policies:

- **Layered retry.** Connect failures fast-fail with capped exponential
  backoff; empty responses retry on a separate counter; a streamed
  request is never replayed after its first output byte — a replay
  double-bills the intent and corrupts the row's token counts.
- **Quota classifier.** Rotate provider only on hard exhaustion —
  billing or balance errors. Transient `429`/`401`/`403`/`5xx` retries
  in place; rotating on a transient smears spend across keys and breaks
  the one-key-per-intent attribution above.
- **Per-profile circuit breaker.** A `1m → 5m → 30m` failure ladder per
  provider profile, persisted across restarts, reset on success. A
  tripped breaker answers "skip" before the call is made, not after the
  failure lands.
