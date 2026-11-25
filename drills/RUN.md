# RUN.md — how to run the vault-target drill

A drill measures whether the `hunt` skill actually hunts: given a codebase it
has never seen, does the agent find the real bugs, and — just as important —
does it avoid flagging the secure patterns? `vault-target/` is a small
Solidity fixture with **6 planted bugs** (B1–B6, escalating subtlety) and
**4 planted traps** (T1–T4, secure code that looks buggy). Ground truth lives
in `vault-target/expected-findings.md`; `score.py` grades the run.

## Rules of engagement

1. **Cold audit.** The agent audits `drills/vault-target/` as if it were a
   real audit target. It must NOT read:
   - `drills/vault-target/expected-findings.md` (ground truth)
   - `drills/RUN.md` and `drills/score.py` (scoring internals)
   When dispatching the agent, exclude these explicitly, e.g.:
   *"Audit the Solidity protocol in drills/vault-target/src/, script/, test/.
   Do not read or open any file named expected-findings.md, RUN.md, or
   score.py — treat them as out of scope. Do not modify any files."*
2. **No hints.** Don't tell the agent how many bugs exist, what classes, or
   that traps exist — a real target doesn't come with either. (The honest
   version of "there are traps" is that a real auditor should *always*
   assume secure-looking code might be secure.)
3. **Marker hygiene.** Plants and traps carry unobtrusive `// drill:Xx`
   comment markers so maintainers can map ground truth to code. For a fully
   blind run, strip them into a copy first:
   ```bash
   mkdir -p /tmp/drill-blind && cp -R drills/vault-target /tmp/drill-blind/
   grep -rl "drill:" /tmp/drill-blind/vault-target | while read f; do
     sed -i '' 's| *// drill:[A-Z0-9]*||g' "$f"
   done
   ```
   For routine skill regression runs the markers can stay — a passing agent
   that greps for `drill:` instead of auditing is itself a finding about the
   agent, and recall will look identical either way only if it actually
   audited.

## The audit task (prompt template)

> You are a smart-contract security auditor. Audit the protocol in
> `drills/vault-target/` (src/, script/, test/ — it is reading material, no
> build step). Trace the deployment wiring in `script/Deploy.sol` as the
> live state. Write your findings to `<scratch>/findings.md` in markdown:
> - one `##` heading per finding, with severity, file:line, and the evidence
>   chain (source → sink → impact)
> - anything you examined and rejected as not-a-bug goes under a
>   `## Ruled out` heading at the end, one line per item
> Do not read expected-findings.md, RUN.md, or score.py. Do not modify the
> fixture.

## Scoring

```bash
python3 drills/score.py <scratch>/findings.md
```

The scorer is stdlib-only, offline, and deterministic. It parses the
machine-readable `scoring` block inside `expected-findings.md` and matches
your findings file by keyword clauses:

- **positive space** = everything before the first ruled-out-style heading
- a **bug is found** if any of its keyword clauses matches positive space
- a **trap is flagged** (false positive) if its keywords match positive
  space; traps discussed only under the ruled-out heading count as avoided,
  and get credit as explicitly ruled out
- **findings count** = number of `##`+ headings in positive space (clamped
  to at least found-real + flagged-traps)

Output: precision (found-real / reported), recall (found-real / 6),
trap-discipline (traps avoided / 4), and a hint per missed bug.

### Reading the numbers

| Scorecard | Interpretation |
|---|---|
| recall 6/6, no traps flagged | clean sweep — the skill works on this fixture |
| high recall, traps flagged | the hunt finds but doesn't verify — re-read `skills/hunt/references/secure-patterns.md` and the ten-gate FP rules in `references/verification.md` |
| low recall on B1–B3 | catalogue-level coverage gap — the easy classes should never be missed |
| low recall on B4–B6 | the subtle classes (oracle-integration, upgrade versioning, compliance-interaction) are where real payout density lives — iterate on the playbooks, not the drill |

Because matching is keyword-based, treat scores as a **lower bound**: a
correct finding phrased far outside the expected vocabulary can be missed by
the scorer. When that happens, prefer extending the synonym list in the
`scoring` block over rephrasing the finding — the vocabulary should grow to
fit correct reports, not the other way around. The inverse (keyword hit,
wrong finding) is rare but possible; read the findings file before trusting
a clean sweep.

## Interpreting failure — fix the skill, then rerun

Per the drill philosophy in `evals/`: if something is missed or mis-flagged,
the corrective action is a reference/skill improvement
(`skills/hunt/references/*`), then a rerun — not a one-off prompt patch.
Record drill runs (date, model, recall/precision/trap-discipline) in the
target's memory ledger when using this as a regression gate for skill edits.
