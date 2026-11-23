# BountyBench — the dollar-mapped scoreboard

## What it is

[BountyBench](https://github.com/bountybench/bountybench) is Stanford's
benchmark of 40 real, paid bug bounties across 25 open-source systems.
Payouts range $10–$30,485. Three task types cover the vulnerability
lifecycle:

- **Detect** — given a codebase and running target, find a new vulnerability.
- **Exploit** — given a bounty writeup, produce a working exploit.
- **Patch** — given a bounty writeup and exploit, patch the vulnerable code.

Tasks run in Docker: the agent gets a Kali container, the codebase, and
network access to the target. Scoring is pass/fail via the task's own
`verify.sh` (exit 0 = exploit confirmed), mapped to the real dollar value
of the bounty. Apache-2.0.

## Why it's the canonical tokens→dollars eval

Every other security benchmark scores in abstract points. BountyBench scores
in dollars: each task carries the actual payout of the actual bounty. That
makes it the closest public proxy for this repo's core metric — token spend
in, bounty dollars out — without touching a live program's scope, RoE, or
triage queue.

## Running the fleet against a task

Prereqs: Docker running, Python env for the bench harness, model API keys.

1. Clone the bench:
   ```bash
   git clone https://github.com/bountybench/bountybench.git
   cd bountybench
   ```
   Tasks live under `bountytasks/<system>/`, with per-bounty metadata
   (dollar value, report text), `verify_files/verify.sh`, `exploit_files/`,
   and `patch_files/`.
2. Pick a task and type. Start with Exploit/Patch (writeup provided) to
   smoke-test the pipeline, then Detect — no writeup, the hard mode and the
   honest one.
3. Stand up the environment per the task's harness. Their reference runner
   (`python -m workflows.runner --workflow-type …`) handles the Docker
   lifecycle and can serve as the execution env your workers shell into;
   or start the task's containers manually if bypassing their agent loop.
4. Point the orchestrator at it:
   - program = the bounty task; scope = the provided codebase + target only.
   - dispatch hunt/playbook intents as on a live program.
   - every intent closes → row in `memory/ledger.md` (see
     `../../skills/token-ledger`).
5. Score: success = the task's `verify.sh` exits 0 after your `exploit.sh`.
   Record finding-id and cumulative est-$ from the ledger for that task.
6. Compare: bounty dollars earned ÷ token dollars spent = run EV. The
   bench's dollar-mapped scoring covers the payout side; the ledger covers
   the spend side.

## Metrics to report

Per model/technique/config, across the tasks actually run:

- **Solve rate** — % tasks passed, split by Detect / Exploit / Patch.
- **$-per-solve** — total est-$ spent ÷ tasks solved. Include failed tasks
  in the spend — that's the honest number.
- **$ earned** — summed bounty values of solved tasks. Report alongside
  spend, never instead of it.
- **FP rate** — flagged candidates that failed `verify.sh` or would have
  been N/A'd. Pair with `../fprate/HARNESS.md`.

## The honest caveat

Benchmark wins ≠ live-bounty wins. These are known, already-paid bugs in
frozen snapshots: no dedupe against prior disclosures, no triager, no RoE,
no scope ambiguity, and Exploit/Patch writeups leak the answer's shape. A
good score shows the fleet *can* execute; only real submissions show the
pipeline pays. Treat BountyBench as CI for capability, not proof of income.

## Judging notes

- **Judge the end state, not the trajectory.** Score the final artifacts —
  the produced exploit, the patched tree — against ground truth. A fluent
  trace ending in a `verify.sh` exit-1 is a fail; a messy trace ending in
  exit-0 is a pass. Trajectory grading rewards plausibility, the same FP
  failure mode `../fprate` exists to measure.
- **Normalize against human time.** Report results in METR-style honest
  form: "the fleet clears ≤N human-hour tasks at p=0.5," with N derived
  from the human effort the original bounty represents — never a bare
  "solved X% of BountyBench." Dollar value and human-hours are both in
  the task metadata; report both.
