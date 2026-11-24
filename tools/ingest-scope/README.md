# ingest-scope

Nightly pull of public, keyless bug-bounty scope feeds into one normalized
program catalog. Python 3.9+, stdlib only.

## Usage

```sh
python3 ingest_scope.py                      # writes ./out
python3 ingest_scope.py --out-dir data/scope
python3 ingest_scope.py --platforms hackerone,immunefi
python3 ingest_scope.py --platforms independent,bbscope --securitytxt --securitytxt-limit 50
python3 ingest_scope.py --timeout 10
```

| arg | default | effect |
|---|---|---|
| `--out-dir` | `./out` | output directory, created if missing |
| `--platforms` | all | comma-separated platform filter (skips unlisted feeds and emitted records; `bbscope` selects the scope-updates feed) |
| `--timeout` | `30` | per-fetch timeout in seconds |
| `--securitytxt` | off | probe `/.well-known/security.txt` per unique program host; fills `contact{}` and `securitytxt` block, flags lapsed `Expires` |
| `--securitytxt-limit` | `100` | max distinct hosts to probe (alphabetical, deterministic) |
| `--securitytxt-timeout` | `10` | per-host fetch timeout in seconds |
| `--community-file` | `community-programs.json` next to this script | JSON array (or `{"programs": [...]}`) of community-submitted entries; loaded whenever the file exists |
| `--validate-community FILE` | off | schema-check a submission file and exit (no fetching); non-zero exit on any error |

Individual source failures are tolerated: the source is marked `error` in
`index.json`, a warning is logged to stderr, and the run continues.

## Sources

| source | platform label | notes |
|---|---|---|
| arkadiyt/bounty-targets-data | `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`, `hackenproof` | per-platform JSON; `hackenproof_data.json` currently 404s upstream (kept for when the feed returns, fails soft) |
| lissy93/bug-bounties API | `independent` | `company`/`slug`/`max_payout`/`safe_harbor`; no platform field upstream, so all records land under `independent` |
| disclose/diodb | `independent` | `program_name`/`policy_url`/`safe_harbor` plus report-channel fields (`contact_email`, `contact_url`, `securitytxt_url`, `pgp_key`, `preferred_languages` → `contact{}`; `disclosure_timeline_days`, `launch_date` → top level) and program-reality fields (`offers_bounty`, `offers_swag`, `hall_of_fame`, `public_disclosure`, `policy_url_status` → top level); its index entry carries `pay_vs_vdp` = fraction of diodb programs that pay vs VDP-only (~0.18) |
| Immunefi public API | `immunefi` | `maxBounty` → `max_payout` USD; `assets[]` → `in_scope` |
| bbscope /api/v1/updates | `bbscope` | post-ingest pass, not a program feed: writes `scope-updates.jsonl` trigger lines (`{"kind": "scope-change", type, platform, handle, program_url, target, scope_type, category, at}`) for change-detect watches, and stamps `fresh_scope_at` on catalog records whose `url` matches an update's `program_url` |
| `community-programs.json` (committed) | per-entry `platform` field | community-submitted programs (`source: "community"`); each entry schema-validated via `validate_community_entry` — records that fail are warned + skipped. Required fields: `name`, `url`, non-empty `in_scope`, `verification`. Flow in `docs/submitting-programs.md` |

The `--securitytxt` pass fetches `https://<program-host>/.well-known/security.txt`
(RFC 9116) for each unique `testing_policy_url`/`url` host, fail-soft per
host. Parsed `Contact`/`Expires`/`Policy`/`Encryption`/`Preferred-Languages`
land in the record's `securitytxt` block; `Expires` in the past sets
`securitytxt.expired: true` — a dead-program detector (the operator let the
disclosure file lapse). Contact fields fill `contact{}` only where empty
(`contact.source` = `securitytxt` when it supplied them), so diodb data wins
on conflict. Index carries `securitytxt: {hosts_checked, found, expired,
errors}` counts.

Deferred: `lookup.disclose.io` client for asset→contact reverse lookups. The
per-asset API needs a key and adds an egress dependency the nightly job
doesn't need — the diodb `contact_*` fields plus the securitytxt pass cover
the contact-discovery use case for now. Revisit if asset-keyed lookup is
required.

**Dead / stale feeds — do not re-add:** polar.sh (dead Apr-25), federacy
(dead), issuehunt (stale), code4rena/c4 (winding down), hackerhive (dead).

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
- `index.json` — `generated_at`, `total_programs`, per-source
  `{source, url, status, n_programs, fetched_at, error?}` (diodb also
  carries `pay_vs_vdp`; bbscope-updates carries `n_updates`/`programs_flagged`),
  plus `securitytxt` probe counts when `--securitytxt` ran.
- `scope-updates.jsonl` — written only when the bbscope feed succeeds: one
  `scope-change` trigger line per upstream update, consumable by
  `tools/change-detect/detect.py add <program_url>`.

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
  "offers_bounty": true,
  "offers_swag": false,
  "hall_of_fame": true,
  "public_disclosure": "co-ordinated",
  "policy_url_status": "alive",
  "securitytxt": {"url": "https://example.com/.well-known/security.txt",
    "contact": "mailto:security@example.com", "expires": "2027-01-01T00:00:00Z",
    "expired": false, "policy": "https://example.com/vdp",
    "encryption": "https://example.com/pgp.txt", "languages": "en"},
  "fresh_scope_at": "2026-11-23T20:10:06Z",
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
  `contact` block; populated by diodb records (`contact.source` = `diodb`)
  and the `--securitytxt` pass (`contact.source` = `securitytxt` when it
  supplied them). `url` is the program's web submission/contact page;
  `securitytxt`/`encryption` are published security.txt and PGP-key URLs.
  Treat as pointers to verify at manifest time, not authorization.
- `offers_bounty` / `offers_swag` / `hall_of_fame`: diodb program-reality
  flags (`yes`/`partial`/`full` → `true`, `no`/`none`/`false` → `false`,
  unset → `null`; a `hall_of_fame` URL counts as `true`). `offers_bounty`
  is the pay-vs-VDP discriminator — `null`+`max_payout` unknown usually
  means a VDP.
- `public_disclosure`: diodb disclosure stance verbatim (`co-ordinated`,
  `discretionary`, `nda`, ...) or `null`.
- `policy_url_status`: diodb's liveness check on the policy page (`alive`,
  `dead`) — pairs with `securitytxt.expired` for dead-program detection.
- `securitytxt`: parsed `/.well-known/security.txt` block, `null` unless
  `--securitytxt` ran and the host published a file. `expired` is `true`
  when `Expires` has lapsed (dead program), `null` when unparseable.
- `fresh_scope_at`: latest bbscope `program_url`-matching update timestamp,
  `null` when the program had no recent upstream scope change.

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
