# FP-rate harness — the credibility scoreboard

## Why it exists

A hunter that "finds" 100 vulnerabilities nobody pays for is worse than one
that finds 5 real ones. Every false positive costs triager goodwill, burns
program trust, and gets accounts flagged. The reference case:

- **ARE-MCP v1**: 105 findings reported "CONFIRMED". Payout: **$0**.
- **ARE-MCP v2** (deterministic pre-filter + adversarial review layer):
  ~**$1,100** paid.
- Post-hoc analysis: accept/reject outcomes were ~48% predictable — half of
  what gets submitted is a coin flip even when everything looks real.

So this harness does not measure find rate. It measures **submit-worthy
rate**: of the things the fleet flags, how many would survive a real
triager.

## Method

Two corpora, one question: "would this flag have been a real report?"

- **Positive control** — known-bug targets: vulhub environments, vulnerable
  dependency snapshots, BountyBench Detect tasks. Ground truth = the known
  CVE/bounty. A flag matching it scores TP; a missed one is a silent failure
  worth logging.
- **Negative control** — clean codebases: patched versions of the same
  projects, current releases of well-audited OSS. Ground truth = no bug.
  Any flag here is an FP by construction.

Run the fleet end-to-end — same skills, same gates, same worker prompts as
a live hunt. Count true finds vs total flagged, per technique.

## What counts as a finding

A flag only enters the count if it passes the same gates required for real
submission:

1. **Deterministic validator** — a non-LLM check reproduces the condition
   (tool output, req/resp replay, script execution). "The model is sure" is
   not validation.
2. **Confidence > 80%** — the evidence package self-assesses high; below
   threshold it routes to a fact row, not a finding.
3. **PoC executed** — the proof-of-concept ran against the target and
   produced the claimed effect (the bench `verify.sh` pattern: exit 0 = real).

Fail any gate → FP for scoring purposes. This mirrors what triagers do at
scale — measure it here first.

## Reporting

Confusion matrix **per technique/playbook**, not just fleet-wide — you need
to know which playbook cries wolf:

```
| technique | TP | FP | missed | submit-worthy % | est-$ per TP |
|-----------|----|----|--------|-----------------|--------------|
| PB-3 idor | 7  | 1  | 2      | 87.5%           | 11.40        |
```

`submit-worthy % = TP / (TP + FP)`. Track over time; the trend matters more
than any single number.

## CI gate

This harness is the repo's own quality gate, enforced by `stats.py`
(stdlib — a proportion, not a vibes diff):

- Any change to `skills/hunt/` playbooks, validator configs, or
  `skills/reporter` templates runs the harness on the pinned corpora.
- Regression rule: a technique's submit-worthy rate may not drop
  *significantly* vs the recorded baseline — pooled two-proportion z-test,
  Holm-corrected across the suite so one marginal drop can't false-alarm
  the gate. FP count on the negative control may not increase.

```bash
# after each harness run, emit results.csv rows: technique,total,submitworthy
python3 evals/fprate/stats.py baseline save results.csv baseline.json  # once, or on intentional re-baseline
python3 evals/fprate/stats.py check results.csv baseline.json --alpha 0.05
# -> per-technique verdict table; exit 1 if any Holm-adjusted p < alpha
```

- New playbooks ship disabled until they post a matrix row (no baseline row
  = reported `new`, not gated yet).

The scoreboard is the contract: claims without a scoreboard are marketing.
