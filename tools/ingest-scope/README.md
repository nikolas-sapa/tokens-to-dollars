# ingest-scope

Nightly pull of public, keyless bug-bounty scope feeds into one normalized
program catalog. Python 3.9+, stdlib only.

## Usage

```sh
python3 ingest_scope.py                      # writes ./out
python3 ingest_scope.py --out-dir data/scope
python3 ingest_scope.py --platforms hackerone,immunefi
python3 ingest_scope.py --timeout 10
```

| arg | default | effect |
|---|---|---|
| `--out-dir` | `./out` | output directory, created if missing |
| `--platforms` | all | comma-separated platform filter (skips unlisted feeds and emitted records) |
| `--timeout` | `30` | per-fetch timeout in seconds |

Individual source failures are tolerated: the source is marked `error` in
`index.json`, a warning is logged to stderr, and the run continues.

## Sources

| source | platform label | notes |
|---|---|---|
| arkadiyt/bounty-targets-data | `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, `hackenproof` | per-platform JSON; `hackenproof_data.json` currently 404s upstream (kept for when the feed returns, fails soft) |
| lissy93/bug-bounties API | `independent` | `company`/`slug`/`max_payout`/`safe_harbor`; no platform field upstream, so all records land under `independent` |
| disclose/diodb | `independent` | `program_name`/`policy_url`/`safe_harbor` plus report-channel fields (`contact_email`, `contact_url`, `securitytxt_url`, `pgp_key`, `preferred_languages` → `contact{}`; `disclosure_timeline_days`, `launch_date` → top level) |
| Immunefi public API | `immunefi` | `maxBounty` → `max_payout` USD; `assets[]` → `in_scope` |

Dedupe merges records on `(platform, handle-or-name lowercased)`: scalar fields
fill from whichever record has them, scope lists union on `(target, type)`.
The same real-world program can still appear once per platform (e.g. an
Immunefi program also listed by lissy93 as `independent`) since upstream
sources do not agree on platform identity.

## Outputs

- `programs.json` — all normalized program records (list).
- `programs.tsv` — `platform, name, max_payout, safe_harbor, n_in_scope, url`,
  ranked by `max_payout` descending (nulls last; raw value, currencies not
  converted).
- `index.json` — `generated_at`, `total_programs`, and per-source
  `{source, url, status, n_programs, fetched_at, error?}`.

## Record schema

```json
{
  "platform": "hackerone | bugcrowd | intigriti | yeswehack | hackenproof | immunefi | independent",
  "handle": "verisk_vdp",
  "name": "Verisk VDP",
  "url": "https://hackerone.com/verisk_vdp",
  "max_payout": {"value": 30000, "currency": "USD"},
  "safe_harbor": true,
  "excluded_methods": ["..."],
  "in_scope": [
    {"target": "*.example.com", "type": "WILDCARD",
     "eligible_for_bounty": true, "instruction": "..."}
  ],
  "out_of_scope": [{"target": "...", "type": "...",
                    "eligible_for_bounty": false, "instruction": "..."}],
  "testing_policy_url": "https://...",
  "contact": {
    "email": "security@example.com",
    "url": "https://example.com/report",
    "source": "diodb",
    "securitytxt": "https://example.com/.well-known/security.txt",
    "encryption": "https://example.com/pgp.txt",
    "languages": "en"
  },
  "disclosure_timeline_days": 90,
  "launch_date": "2020-01-01",
  "source": "arkadiyt-hackerone",
  "fetched_at": "2026-01-01T00:00:00+00:00"
}
```

Field notes:

- `max_payout`: `null` when unknown or program is recognition/swag-only.
- `safe_harbor`: `true` when the policy commits to any safe-harbor terms
  (upstream `full`/`partial`/`yes` all map to `true`), `false` for explicit
  `none`/`no`, `null` when not stated.
- `in_scope[].target`: normalized across upstream keys
  (`target`/`endpoint`/`asset_identifier`/`uri`). Immunefi `assets[]` become
  in-scope rows with `eligible_for_bounty: true`.
- `out_of_scope`: same row shape. Immunefi `customOutOfScopeInformation` and
  `customProhibitedActivities` land as `{"target": null, "type": "policy"}`
  rows carrying the raw policy text in `instruction`.
- `testing_policy_url`: the program/policy page for manual RoE review. Always
  read it before testing — this catalog is for triage, not authorization.
- `contact`: report-channel fields matching the scope-parser manifest's
  `contact` block; only populated for diodb-sourced records today
  (`contact.source` = `diodb` when any field is set). `url` is the program's
  web submission/contact page; `securitytxt`/`encryption` are published
  security.txt and PGP-key URLs. Treat as pointers to verify at manifest
  time, not authorization.

## Nightly ingest (GitHub Actions)

```yaml
name: ingest-scope
on:
  schedule: [{ cron: "17 3 * * *" }]
  workflow_dispatch:
permissions:
  contents: write
jobs:
  ingest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python3 tools/ingest-scope/ingest_scope.py --out-dir data/scope
      - name: commit
        run: |
          git config user.name "scope-bot"
          git config user.email "scope-bot@users.noreply.github.com"
          git add data/scope
          git diff --cached --quiet || git commit -m "nightly scope ingest"
          git push
```

For cron on a host: `17 3 * * * cd /path/to/repo && python3 tools/ingest-scope/ingest_scope.py --out-dir data/scope`
