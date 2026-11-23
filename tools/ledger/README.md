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

## Honesty note

`est-$` mixes real usage (bare number) and estimates (`e` suffix). Both are
estimates of dollar cost — token prices change, and `e` rows were guessed
from context size. The spend total reports how many rows were estimated;
treat every dollar figure here as approximate, and never edit or delete
embarrassing `FP`/`blocked` rows to make the numbers look better.
