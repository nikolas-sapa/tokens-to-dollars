# ledger

Scoreboard for the `skills/token-ledger` skill: parses `memory/ledger.md`
and prints spend, yield, cost-per-finding, EV, open pipeline, and
cost-ceiling warnings. Python 3.9+, stdlib only.

## Usage

```sh
python3 ledger.py                          # reads memory/ledger.md
python3 ledger.py --ledger path/to.md
python3 ledger.py --program acme-h1        # one program only
python3 ledger.py --ceiling 100            # warn above $100 spend, 0 findings
python3 ledger.py --json                   # machine-readable output
```

| arg | default | effect |
|---|---|---|
| `--ledger` | `memory/ledger.md` | ledger file to parse |
| `--program` | all | exact (case-insensitive) program filter |
| `--ceiling` | `50` | WARN when a program exceeds this spend with 0 findings |
| `--json` | off | emit one JSON object instead of text tables |

## Where the ledger comes from

`memory/ledger.md` is written by the orchestrator at intent close — workers
never write their own rows (see `skills/token-ledger/SKILL.md`). Two
append-only markdown tables:

- intent rows `| date | program | intent-id | worker | model | in-tokens | out-tokens | est-$ | outcome | finding-id |`
- payout rows `| date | program | finding-id | status | amount |`

`memory/` is gitignored local state; `tools/bootstrap.py` seeds the file
with both table headers.

## reserve.py — budget holds

Pre-dispatch reserve/settle accounting for `skills/token-ledger`'s
"Budget enforcement" rules. SQLite at `memory/budget.db` (gitignored);
all amounts integer micro-dollars — no floats, float drift breaks caps.

```sh
python3 reserve.py cap 25.00                    # set (or show) the spend cap
python3 reserve.py reserve int-0142 \
    --est-in 182000 --max-out 16000 \
    --price-in 0.015 --price-out 0.075          # USD per 1k tokens
python3 reserve.py settle int-0142 \
    --actual-in 182400 --actual-out 11900       # idempotent per intent-id
python3 reserve.py sweep                        # release TTL-expired holds
python3 reserve.py status                       # cap / settled / reserved JSON
```

Worst case = (`est-in`×price-in + `max-out`×price-out) × 1.1, floored to
micro-dollars. `reserve` exits 1 with `{"ok": false, "reason":
"insufficient"}` when settled + reserved + wrap-up tranche + worst-case
would exceed the cap; the check-and-hold runs in one `BEGIN IMMEDIATE`
section. Holds default to a 1800s TTL (`--ttl`) so `sweep` frees budget
leaked by crashed workers; `settle` of an intent with no reservation
still records actuals but then requires `--price-in`/`--price-out`.

Budgets are hierarchical: each hold pins an extra `--reserve-pct`
(default 15%) as `wrap_micro` — a wrap-up tranche held back for the
settlement/report phase so worker intents can never consume the funds an
engagement needs to close out. `settle` never touches it (its
`wrap_held_micro` is reported, not released); only `sweep` frees it —
run `sweep` at wrap-up phase start to release the accumulated tranche
(`freed_wrap_micro` in the sweep output) for verifier/reporter spend.

## Predicted EV (planning-side, not stored)

The EV table reports realized EV (Σ paid / Σ est-$). Picking the next target
uses predicted EV — these terms are planning inputs from
`skills/token-ledger` ("EV model + cost-tier routing"), not ledger columns,
since `p_find`/`prec_val`/`r_dup` are per-target estimates, not per-intent
actuals:

`EV = p_find × prec_val × (1 − r_dup) × (1 − r_info) × B_ref − (C_scan + p_find × C_HITL)`

p_find = P(finds a reportable vuln) · prec_val = validator precision
(≥0.95 required) · r_dup = P(duplicate) · r_info = P(N/A closure) ·
B_ref = class × severity reference payout · C_scan = scan token cost ·
C_HITL = human validation cost, paid on confirmed candidates only.

## Honesty note

`est-$` mixes real usage (bare number) and estimates (`e` suffix). Both are
estimates of dollar cost — token prices change, and `e` rows were guessed
from context size. The spend total reports how many rows were estimated;
treat every dollar figure here as approximate, and never edit or delete
embarrassing `FP`/`blocked` rows to make the numbers look better.
