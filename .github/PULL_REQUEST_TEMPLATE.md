## Summary

<!-- What changed and why. One line per idea. Link the issue. -->

## Files touched

<!-- `path` — what changed, one line each. Surgical edits only: if a file
wasn't part of the change, it shouldn't be in the diff. -->

## Test plan

- [ ] `python3 tools/bootstrap.py` runs clean
- [ ] Smoke pass — `python3 tools/ledger/ledger.py --ledger memory/ledger.md`; a `tools/wrap` call exits 127 cleanly on a missing binary
- [ ] New/changed tool invoked for real (command and output below), not just `--help`
- [ ] `tools/` stays Python 3.9+ stdlib-only; fails soft per-source
- [ ] No private engagement data, no emoji, relative cross-references

## Evals

<!-- Required when touching skills/hunt, gates, tools/content-scan,
tools/fact-verify, or evals/. Paste the command and the tail of the output.
Delete this section otherwise. -->

- [ ] `python3 evals/injection/run.py` — ASR 0, no pass-to-fail flips
- [ ] `python3 evals/verifier-canary/run.py` — all canaries die as designed
- [ ] `python3 evals/fprate/stats.py check results.csv baseline.json` — no Holm-adjusted regression

## VERIFY_REAL

<!-- One line: what you ran against a real target, what you saw, and which
check would have gone red if the change didn't work. "Tests pass" is not
verification — name the thing that can fail. See CONTRIBUTING.md. -->

VERIFY_REAL:
