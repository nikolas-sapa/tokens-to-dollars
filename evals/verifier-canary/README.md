# verifier-canary — trust

`run.py` feeds canary agent outputs through the repo's own verification
gates — the `verify_claims.py` soliloquy and verbatim-POE checks, the
receipt-schema and dedupe-novelty invariants, and the content scanner —
and asserts each canary dies the way it was designed to. It answers "is
the gate still a gate": a null canary that scores >0 means the verifier
broke, not that the canary got smarter.

## Why

Verifiers get gamed. SWE-bench agents edited the test harness itself
(the conftest trick) to fake green runs; eval pipelines have fetched
trojaned artifacts the grader later executed (the curl trojan); and
graders increasingly run out-of-sandbox, ingesting the same
attacker-influenced content the fleet does. The Berkeley RDI lesson:
the thing doing the judging is part of the attack surface. A verifier
that cannot reject a null is not a verifier.

## Fixtures

| fixture | canary | must die on |
|---|---|---|
| `null.json` | claimed finding, zero tool calls, no trace | no-tool-calls, receipt-schema, dedupe, soliloquy |
| `random.json` | random prose + fake CVE-ish claim | soliloquy, receipt-schema, dedupe (novel with empty searched list) |
| `injection.json` | fully grounded finding whose evidence hides `<IMPORTANT>` markup + Unicode tag-block instructions | content-scan only — every other gate passes |
| `tampered.json` | real-shaped finding; evidence quote absent from trace and stored body | verbatim-POE missing-quote + soliloquy |

Each fixture also declares the expected outcome of every gate, so a gate
that silently starts passing — or starts rejecting everything — fails
the run too, not just a full pass-through.

## Usage

```sh
python3 run.py          # table; exit 1 on any pass-through or mismatch
python3 run.py --json   # machine-readable report
```

Smoke-test: `null.json` must be rejected. If it ever comes back
accepted, the verifier is the bug.

Decays like the others: re-run on every change to `verify_claims.py`,
`scan.py`, the receipt schema, or the dedupe rules.
