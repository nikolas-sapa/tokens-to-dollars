# change-detect

Engagement change-detector for commit-triggered waves. Watches URLs that move
when a target ships — JS bundles, API schema endpoints, changelog pages,
security.txt — and emits `kind`-tagged trigger lines so the orchestrator can
fire the right new wave (and pick up unfinished chains first). Python 3.9+,
stdlib only.

```bash
# register watches (no fetch — add never touches the network).
# kind: js | schema | changelog | fingerprint | generic (default).
# Re-add with an explicit kind to retag; bare add never downgrades.
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    add https://acme.com/app.js js

# refetch every watch; --only-host is REQUIRED (exact host, repeatable).
# HEAD-then-GET, 30s timeout, sha256 over the body. JSON to stdout + changes.md
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    check --only-host acme.com

# same but keep bodies: diff renders, and the don't-wake gate gets a real diff
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    --store-bodies check --only-host acme.com
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ diff

# crt.sh cert-log poll: new names -> new-subdomain triggers
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    poll-ct acme.com --only-host acme.com

# releases.atom / changelog poll: keyword-gated entries -> changelog triggers
python3 tools/change-detect/detect.py --target memory/targets/acme/change/ \
    poll-feed https://acme.com/releases.atom --only-host acme.com
```

## State layout (`--target <dir>`)

- `state.json` — per-URL `{added, kind, sha256, last_checked, status, etag,
  last_modified, content_type, bytes}` plus `last_run`, `ct_seen` (deduped
  crt.sh names per domain), and `feeds` (seen entry ids per feed URL).
- `bodies/<key>.prev|.cur` — last and current bodies, only with
  `--store-bodies`. `diff` decodes by recorded charset and prints
  `difflib.unified_diff` per changed URL.
- `changes.md` — regenerated every check: counts, per-URL table (with kind),
  `## new-wave candidates`, and `## triggers`.
- `triggers.jsonl` — append-only; one `{"kind", "url", "signal", "ts", ...}`
  line per fired trigger. This is the file the orchestrator tails — kind maps
  to the action, signal says why it fired.

## Triggers

| kind | produced by | signal examples |
|---|---|---|
| `js`, `schema`, `changelog`, `fingerprint` | `check` on a changed watch | `new-endpoint`, `new-asset-url`, `version-bump`, `new-host`, `content-hash-changed` |
| `new-subdomain` | `poll-ct` | `ct-log` (+ `priority: high` when a label starts with `api`/`staging`/`admin`/`dev`/`beta`) |
| `changelog` | `poll-feed` | `keyword:<kw>` — one per matched keyword |

Signal → action mapping (orchestrator side):

| signal | action |
|---|---|
| `new-endpoint` | enqueue endpoint into recon + param-discovery waves (x8/arjun via wrap) |
| `new-asset-url` | fetch/diff the asset, harvest routes, secrets, sourcemaps |
| `version-bump` | re-fingerprint the stack, map new version to known-CVE list |
| `new-host` | scope-check the host against the manifest, then probe (httpx) |
| `ct-log` / `new-subdomain` | scope-check → alive-probe → register as a watch; `priority: high` jumps the queue |
| `keyword:<kw>` | read the entry, map the keyword to an attack surface (e.g. `oauth` → auth-flow wave) |
| `content-hash-changed` | low-confidence wave — emitted only for non-`generic` kinds when no stored body exists to diff; use `--store-bodies` for the precise gate |

## Don't-wake gate

A `changed` watch only fires a trigger when the diff introduces a *new*
deploy-shaped token: an endpoint path, an asset URL, a version/build string,
or a host reference. Detection is token-set delta (`new − old`), so a minified
bundle that rebuilds the same routes fires only when a genuinely new token
appears. CSS, media files, `.map` refs, and status-text churn yield no tokens
→ `changed` is recorded with `gated: no deploy signal` and nothing wakes.

Without `--store-bodies` there is no diff: non-`generic` kinds fire
`content-hash-changed` (a sha move on a schema/security.txt/bundle is itself
the coarse deploy signal), `generic` watches stay quiet.

`poll-ct` queries `https://crt.sh/?q=%.<domain>&output=json`, splits
`name_value` on newlines, strips `*.`, keeps names inside the queried zone,
dedupes against `state.json`, and bumps priority when a label starts with
`api|staging|admin|dev|beta`. `poll-feed` parses Atom `<entry>`/RSS `<item>`
(namespace-agnostic), dedupes entry ids, and gates on
`auth|payment|admin|token|session|oauth|upload|billing|permission` in
title+summary.

## Results and gating

Per URL: `baseline` (first fetch), `unchanged`, `changed`, `error`. Errors
cover fetch failures and hosts outside the allowlist.

Gating mirrors `skills/safety-gates`: the allowlist names assets, so `check`
and `poll-feed` refuse to run without `--only-host`, match exact hosts only,
and the redirect handler refuses hops to non-allowlisted hosts —
authorization never propagates through redirects. `poll-ct` names the queried
domain in `--only-host` and pins the fetch host to `crt.sh`. There is no
retry storm: one HEAD + one GET per watch per run (one GET per poll), 30s
timeouts, sequential.
