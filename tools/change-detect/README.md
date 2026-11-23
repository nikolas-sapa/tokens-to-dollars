# change-detect

Engagement change-detector for commit-triggered waves. Watches URLs that move
when a target ships — JS bundles, API schema endpoints, changelog pages,
security.txt — and reports what changed so the orchestrator can fire a new
wave (and pick up unfinished chains first). Python 3.9+, stdlib only.

```bash
# register watches (no fetch — add never touches the network)
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    add https://acme.com/app.js

# refetch every watch; --only-host is REQUIRED (exact host, repeatable).
# HEAD-then-GET, 30s timeout, sha256 over the body. JSON to stdout + changes.md
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    check --only-host acme.com

# same but keep bodies so diffs render
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    --store-bodies check --only-host acme.com
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ diff
```

## State layout (`--target <dir>`)

- `state.json` — per-URL `{added, sha256, last_checked, status, etag,
  last_modified, content_type, bytes}` plus `last_run`.
- `bodies/<key>.prev|.cur` — last and current bodies, only with
  `--store-bodies`. `diff` decodes by recorded charset and prints
  `difflib.unified_diff` per changed URL.
- `changes.md` — regenerated every check: counts, per-URL table, and a
  `## new-wave candidates` section listing changed URLs.

## Results and gating

Per URL: `baseline` (first fetch), `unchanged`, `changed`, `error`. Errors
cover fetch failures and hosts outside the allowlist.

Gating mirrors `skills/safety-gates`: the allowlist names assets, so `check`
refuses to run without `--only-host`, matches exact hosts only, and the
redirect handler refuses hops to non-allowlisted hosts — authorization never
propagates through redirects. There is no retry storm: one HEAD + one GET per
watch per run, 30s timeouts, sequential.
