# patch-hunter

Diff-seeded variant analysis. Every security fix commit is a hunt seed: the
patch tells you the bug class, the vulnerable API shape, and exactly what the
missing guard looked like — everything needed to grep for the same mistake
still unfixed elsewhere. Python 3.9+, stdlib only (`git` via subprocess).

## Why this works

- **Big Sleep (Project Zero / DeepMind)** found a real SQLite stack-buffer
  underflow by *variant analysis*: take a known-buggy pattern and search the
  codebase for siblings. A fix commit is the highest-quality variant seed
  that exists — the diff itself is the pattern spec.
- **KNighter** turns a patch into a checker: extract the pre-patch shape from
  the diff, then sweep for sites that never got it. `seed` is the
  patch → spec half; `variants` is the checker half (grep-grade, no build).
- **CopyFail:** one published fix implies unpatched siblings — copied code,
  parallel call sites, drivers forked from the same skeleton. A 9-year-old
  kernel bug was found in ~1 hour of variant analysis off a 2-line prompt.
- **PatchSlop:** fixes introduce bugs too — ~3.2% of kernel CVEs trace back to
  a prior fix commit. The seed's own added lines are worth a second look;
  `bug_class.evidence` keeps the added-line matches separate for that pass.

## Pipeline

```
fix commit ──seed──> seed.json ──variants──> variants.jsonl ──> human verifies
                (bug class, sibling terms,     (pre-patch-shape
                 guard shape)                   call sites)
```

`watch` sits in front as the feed: poll a repo, and every new commit whose
message hits `fix|security|cve|overflow|bounds|auth` emits a
`kind:patch-seed` trigger line — same `{kind, url, signal, ts}` envelope as
change-detect, so the orchestrator can hand off to `seed` automatically.

## Usage

```bash
# 1. Seed from a fix commit (local repo — fully offline).
python3 tools/patch-hunter/patch_hunter.py seed \
    --repo /path/to/linux --commit 9f8d2c1 --out seed.json

# a..b range works too (diff a b, metadata taken from b)
python3 tools/patch-hunter/patch_hunter.py seed \
    --repo /path/to/repo --commit v6.1..v6.1.1 --out seed.json

# remote repo: cloned under --clone-dir; host must be allowlisted
python3 tools/patch-hunter/patch_hunter.py seed \
    --repo https://github.com/owner/repo --commit abc123 \
    --clone-dir clones/ --only-host github.com

# 2. Hunt siblings (grep-grade: no build, no index)
python3 tools/patch-hunter/patch_hunter.py variants \
    --seed seed.json --out variants.jsonl

# 3. Poll for new fix commits
python3 tools/patch-hunter/patch_hunter.py watch manifest.json --fetch \
    --only-host github.com
```

### seed.json

| field | meaning |
|---|---|
| `commit` | sha, parents, author, date, subject, body (capped) |
| `files[]` | per-file status/adds/dels + hunks (added/removed lines, capped 80 each) |
| `changed_functions` | function names from `@@ ... @@ <ctx>` hunk headers |
| `calls.removed` / `calls.added` | call identifiers on `-`/`+` lines — `removed` is the pre-patch API usage |
| `added_guard_terms` | identifiers inside the patch's new `if (...)` conditions — the guard shape |
| `bug_class` | `bounds`/`null-deref`/`uaf`/`overflow`/`injection`/`auth`/`unknown` with per-class scores + evidence (`@msg` w3, `@added`/`@removed` w1, delta-shape boosts for the kind of guard added) |
| `sibling_candidates` | `same-file` / `caller-of` / `api-user` / `missing-guard` search specs |

### variants.jsonl

One line per callsite hit in the repo:

```json
{"path": "drv/x.c", "line": 412, "term": "copy_from_user",
 "shape": "pre-patch-shape", "candidate": "api-user",
 "context": "n = copy_from_user(buf, ubuf, len);", "bug_class": "bounds",
 "commit": "9f8d2c1"}
```

`shape` is `pre-patch-shape` when none of the seed's `added_guard_terms`
appear within `--window` lines (default 8) of the hit — the CopyFail
signature — else `guarded-callsite`. Same-file hits (siblings inside a
patched file) are tagged `candidate: same-file`, others `api-user`. `.git`,
`node_modules` and binaries are skipped; vendor trees are *not* — copied
code is where the siblings live.

### watch manifest.json

```json
{
  "target": "memory/targets/<prog>/patch-hunter",
  "clone_dir": "clones",
  "only_hosts": ["github.com"],
  "repos": [
    {"url": "https://github.com/owner/repo"},
    {"url": "https://github.com/owner/repo", "path": "/existing/clone"},
    {"path": "/local/repo", "ref": "main"}
  ]
}
```

`target` holds `state.json` (per-repo `tip` + `seen` shas + `last_checked`)
and the append-only `triggers.jsonl`. First run is a baseline — tip recorded,
nothing fires — unless `--lookback N` asks for the last N commits. Without
`--fetch`, watch is fully offline: it polls whatever the local clone has.
With `--fetch`, each `url` host must appear in `only_hosts` or `--only-host`
(exact match, repeatable) — no allowlist, no traffic, same gate as
change-detect. Per-repo failures are recorded in the summary `errors` block,
never fatal.

## Attribution hygiene

A variant find derived from someone else's fix is *your* find on paper and
*theirs* in spirit — programs and triagers increasingly ask. Credit the
source commit/researcher in the report (one line: "found via variant
analysis of <sha/writeup>"). Human-tandem finds count differently in the
ledger: record the seed and the human review, not just the payout.
