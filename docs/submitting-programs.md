# Submitting programs

The program catalog (`tools/ingest-scope`) is feed-driven: arkadiyt, lissy93,
diodb, Immunefi, bbscope. Those feeds cover the listed platforms but miss
independent and self-hosted programs. Community submissions close that gap:
the issue template supplies the record, a maintainer verifies it against the
program's own policy page, and the normalized entry lands in the catalog
alongside feed records.

## Flow

1. File a **Program submission** issue
   (`.github/ISSUE_TEMPLATE/program_submission.yml`) with the fields below.
2. A maintainer verifies the program is real and authorized — the public
   policy page must state that testing is allowed; inference doesn't count.
3. Accepted submissions are appended to
   `tools/ingest-scope/community-programs.json` (the committed community
   feed) as `source: "community"` records, deduped on
   `(platform, handle-or-name)` like every other source. Maintainers run
   `python3 tools/ingest-scope/ingest_scope.py --validate-community
   community-programs.json` before merging — a record that fails schema
   validation does not land.
4. The next `ingest_scope.py` run ranks them into `programs.json` /
   `programs.tsv` the same way as feed data — that catalog is the
   target-selection input the orchestrator reads. If the program also posts
   bounties where `tools/bounty-radar` already listens (Immunefi, algora,
   opire, bbscope, GitHub issue bounties), radar picks those listings up on
   its own — no separate submission needed.

## Format

Match the `tools/ingest-scope` record schema (see that tool's README for
the full field list):

| field | format |
|---|---|
| `platform` | `hackerone` `bugcrowd` `intigriti` `yeswehack` `hackenproof` `immunefi` `independent` |
| `handle` / `name` | platform slug; display name |
| `url` | public program/policy page — also becomes `testing_policy_url` |
| `max_payout` | `{value, currency}` — `null` when unknown or VDP-only, never guessed |
| `safe_harbor` | `true` when the policy commits to safe-harbor terms, `false` for explicit none, `null` when unstated |
| `in_scope` | `{target, type}` rows — `*.example.com WILDCARD`, verbatim from the policy |
| `out_of_scope` | same row shape; policy exclusions count as rows |
| `contact` | `{email|url}` — the report channel, not a person |
| `launch_date` | `YYYY-MM-DD`, only if stated |

## Quality bar

- **Public scope/policy page required.** It is the record's
  `testing_policy_url` — the page agents read before anything touches the
  target. No public policy, no catalog entry.
- **Verifiable contact channel.** An email or submission form the program
  actually publishes.
- **No unverifiable claims.** Payout figures only when the policy or
  platform states them — not blog posts, not leaderboard rumors.
- **Not already covered.** Run
  `python3 tools/ingest-scope/ingest_scope.py --out-dir /tmp/scope` and grep
  `programs.tsv` first. arkadiyt covers the big five platforms and diodb
  covers most independent VDPs — if your program is listed there, the
  catalog already has it.
