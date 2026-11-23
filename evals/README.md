# evals — the scoreboard layer

Claims without a scoreboard are marketing. This directory holds the two
harnesses that turn the repo's premise — convert tokens to dollars — into
numbers anyone can check. One measures dollars, the other measures honesty.

## bountybench/ — dollars

`RUN.md` documents running the fleet against Stanford's
[BountyBench](https://github.com/bountybench/bountybench): 40 real, paid
bounties ($10–$30,485) across 25 systems, scored pass/fail by each task's
own verifier and mapped to actual payout values. It answers "how many
bounty dollars does a token dollar buy?" — solve rate, $-per-solve, and EV
per model/technique, with token-side cost pulled from `memory/ledger.md`
via `skills/token-ledger`.

## fprate/ — honesty

`HARNESS.md` documents the false-positive-rate harness: the fleet runs
against known-bug corpora (positive controls) and clean codebases (negative
controls), and a flag counts only if it passes a deterministic validator,
>80% confidence, and an executed PoC. Output is a per-technique confusion
matrix — submit-worthy rate, not find rate — and it gates CI for playbook
changes. The ARE-MCP reference point (105 "CONFIRMED" → $0; v2 with
deterministic filtering → ~$1,100 paid) is the bar it exists to beat.

## Philosophy

The two harnesses deliberately measure different things. BountyBench can be
gamed by memorized exploits; FP-rate can look great on a fleet that finds
nothing. You need both: one keeps the economics honest, the other keeps the
findings honest. Report both numbers, including the ugly ones — the ledger
and the scoreboard are as much the product as the findings.
