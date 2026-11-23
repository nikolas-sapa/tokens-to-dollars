# memory-consolidate

Sleep-time maintenance for the `memory/` learning substrate
(`skills/orchestrator` §8). Scans `memory/lessons/*.md` and
`memory/targets/*/lessons.md`, then does four things — all reported as JSON
to stdout, `--dry-run` supported, nothing ever deleted (append/rewrite of
markdown only).

```bash
python3 tools/memory-consolidate/consolidate.py --root . --dry-run
python3 tools/memory-consolidate/consolidate.py --root .
```

## Passes

- **merge** — live bullet lines (`- `) whose normalized token sets score
  Jaccard > 0.8 collapse to one: the newest dated line wins (latest position
  breaks ties), losers are struck through and dated, never removed.
  Already-struck lines are history and are never re-touched.
- **yield recompute** — recounts `[Y-n]` records per technique across the
  scanned files (`- [Y-3] I-12 → technique (idor) → outcome: finding —
  intents spent: 2`) and regenerates `memory/lessons/technique-yield.md`
  deterministically: header + ranked table, sorted by findings then records.
  Content under a `## manual notes` heading survives regeneration.
- **contradictions** — a normalized claim that appears both struck and live
  (in the same or different files) is flagged to stdout. Never auto-resolved;
  a human decides which side is true.
- **index build** — `memory/targets/<t>/index.md` gets a `file | nodes |
  latest-date | one-liner` table (node ids are `[AS-…]`/`[F-…]`-style
  anchors; date is the latest `YYYY-MM-DD` in the file). `memory/index.md`
  gets a lessons list plus a per-target summary table.

Normalization for merge/contradictions: strike markers, dates, `[X-n]` ids
and punctuation removed, lowercased, token-set compare — so "same claim,
new wording tick" still dedupes.

All writes are idempotent (`unchanged` when content is identical), so it is
safe under cron; `writes` in the JSON report names every file touched with
`written | unchanged | would-write`.
