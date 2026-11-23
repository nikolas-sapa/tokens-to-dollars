# bounty-radar

Funded-bounty intelligence: aggregates live, money-backed bounties (GitHub
issue bounties, escrow-linked issues, Immunefi programs), filters out scams,
scores how contested each one already is, and ranks them by expected value.
Python 3.9+, stdlib only. Ported from the x402-bounty-radar TS service.

## Usage

```sh
python3 bounty_radar.py                          # all sources -> ./out
python3 bounty_radar.py --sources immunefi       # keyless, most reliable
python3 bounty_radar.py --sources github         # issue-label search only
python3 bounty_radar.py --min-reward 1000 --max-competition 30
python3 bounty_radar.py --out-dir data/radar
```

| arg | default | effect |
|---|---|---|
| `--sources` | `github,github-extras,immunefi` | comma list of adapters to run |
| `--min-reward` | none | keep bounties with `reward_usd >= N` |
| `--max-competition` | none | keep bounties with `competition_score <= N` (0-100) |
| `--include-suspect` | off | keep scam-suspect listings (dropped by default) |
| `--out-dir` | `./out` | output directory, created if missing |
| `--snapshot-dir` | `memory/radar-snapshots/` (repo root) | per-program reward-table snapshots, diffed run-over-run |

Every source fails soft: a dead adapter logs to stderr, is marked `error` in
`index.json`, and the run still writes whatever the other sources returned.

## Sources

| source | endpoint | auth | notes |
|---|---|---|---|
| `github` | `api.github.com/search/issues` | none needed; `GH_TOKEN`/`GITHUB_TOKEN` honored | label search: `💎 Bounty`, `bounty`, `💰 bounty` on open issues |
| `github-extras` | `api.github.com/search/{issues,repositories}` | same | issue bodies linking escrow platforms (`algora.io/bounties`, `polar.sh` => `escrowed`) + `topic:bug-bounty`/`topic:bounty` repos as program-level listings |
| `immunefi` | `immunefi.com/public-api/bounties.json` | none | live programs (paused skipped); `maxBounty` => `reward_usd`; `endDate` => `deadline`; always `escrowed` (funds locked on-platform) |

Unauthenticated GitHub search is ~10 req/min. A full run costs ~7 requests, so
back-to-back runs 403 — the adapters degrade to what succeeded rather than
zero the output. With `GH_TOKEN` set the tool additionally enriches the top
GitHub hits: issue-timeline `linked_prs` counts (max 15 issues) and
`repoBountyHistory` (closed `bounty in:title` issues => `verified-history`
funding, max 10 repos).

## Outputs

- `bounties.jsonl` — one record per line, value-ranked:
  `value_score = reward_usd * (1 - competition_score/100) * trend_weight`,
  ties by `age_days` ascending. Read top-to-bottom.
- `index.json` — `generated_at`, per-source `{source, status, n_drafts,
  error?}`, `total_drafts`, `merged_drafts`, `total_bounties`,
  `snapshot_dir`, `table_changes`, `reward_trends` counts.
- `triggers.jsonl` — one line per program whose reward table changed this
  run (up or down only — new baselines and unchanged tables don't trigger):
  `{"kind": "reward-table-change", "direction", "program", "url",
  "prev": {max_reward, table_hash}, "cur": {...}, "at"}`. Feed a changed
  program's `url` into change-detect to start watching it:
  `python3 tools/change-detect/detect.py --target memory/targets/<slug>/change/ add <url>`

## Record schema

```json
{
  "source": "github | github-extras | immunefi",
  "url": "https://...",
  "title": "...",
  "repo": "owner/name or program name",
  "number": 123,
  "reward_usd": 5000,
  "amount_usd": 5000,
  "max_reward": null,
  "funding": "escrowed | verified-history | claimed | unknown",
  "escrowed": true,
  "competition_score": 25,
  "competition_band": "low | medium | high",
  "competition_signals": {"comments": 3, "linked_prs": 1, "reactions": 4,
    "age_days": 5, "cross_listed": true, "source_notes": ["escrow-link:algora"]},
  "scam_flags": [],
  "trust": "likely_real | suspect_scam",
  "discovered_at": "ISO date the listing appeared upstream (source created_at)",
  "age_days": 5,
  "deadline": null,
  "table_updated_at": "ISO date (immunefi only) or null",
  "reward_trend": "up | down | flat | new",
  "labels": ["..."],
  "comments": 3,
  "cross_listed": true,
  "language": "Solidity",
  "severity": null,
  "value_score": 3750.0
}
```

`funding` ranks proof of money: `escrowed` (funds provably locked on a
platform — Immunefi, algora/polar links) > `verified-history` (this repo has
closed "bounty"-titled issues = paid before; token-gated) > `claimed` (a
dollar amount is asserted but unverified) > `unknown`.

## Competition score (0-100)

How contested the bounty already is — the moat metric. Signals:

| signal | points |
|---|---|
| comments | 4/pt, cap 40 — hunters talking under the bounty |
| linked PRs | 12/pt, cap 36 — someone already shipped an attempt |
| reactions | 2/pt, cap 8 — watcher proxy |
| cross-listed on >1 source | +15 — wider hunter reach |
| source notes (escrow link, invite-only, topic tag) | +2 each, cap 10 |
| fresh (<2 days old) | +8 — swarm hasn't landed yet but will |

`competition_band`: <34 low, <67 medium, else high. `competition_score` feeds
target selection: low competition x high reward = best first hit — that is
exactly what `value_score` sorts by.

## Reward-table snapshots — direction detection

Supply is elastic: programs that cut tables draw ~22% fewer valid reports
(~50% fewer criticals), so the radar diffs each program's reward table
against the previous run and weights the ranking by direction.

Every run, records are grouped per program (slugified `repo`, e.g.
`alchemix-finance-v3`) and a snapshot is written to
`<snapshot-dir>/<program-slug>.json` (default `memory/radar-snapshots/` at
repo root — gitignored local state, same convention as change-detect's
`memory/targets/`):

```json
{"program": "...", "url": "...", "min_reward": 100, "max_reward": 50000,
 "tiers": [100, 1000, 50000], "table_hash": "sha256[:16] over the tier list",
 "table_updated_at": "ISO or null", "reward_trend": "...",
 "first_seen": "...", "last_seen": "..."}
```

The "table" is the distinct set of `amount_usd`/`max_reward` values across
the program's records — for Immunefi that is the program max plus any merged
issue bounties; for GitHub, the issue-level payouts. Snapshotting runs on
deduped records before `--min-reward` filtering, so filtered-out tiers don't
read as cuts.

`reward_trend` per program: `new` (first run / unreadable prior), `down`
(max dropped, tiers removed, or churn below an unchanged cap), `up` (max
raised or tiers added without removals), else `flat`. `table_updated_at`
still carries Immunefi's `updatedDate` as a "something changed" proxy, but
the hash now gives real direction.

Weighting: `value_score` is multiplied by `1.15` for `up` and `0.78` for
`down` (the ~22% supply drop), `1.0` for `flat`/`new`. Trend lands in every
output record and in `index.json`'s `reward_trends` counts; changed tables
also emit trigger lines to `triggers.jsonl` consumable by change-detect.
Caveats: a program missing from a run keeps its last snapshot (no decay), and
GitHub issue-level tables are thin — one closed issue reads as a removed tier.

## Scam filter

Records are dropped unless `--include-suspect`. Flags: repo named like a
canonical project (`kubernetes`, `redis`, `gofiber`, `vitess`, `etcd`, ...)
but owned by a random account (AI-bait clone pattern); issue #1-3 with a
generic `Fix ...`/`🎯`/`[Bug]` bait title on a throwaway repo.

## Cross-source dedupe

Drafts merge when they share a normalized URL, or are the same project with
title-token similarity >= 0.5. Same project = identical normalized repo, a
program name equal to the other side's org owner ("Uniswap" program covers
`uniswap/*` repos), or >=2 shared non-generic name tokens ("the", "defi",
"protocol", "v3" etc. don't count). Merges union escrow status, activity
counts, source notes and scam flags; the richer record keeps display fields.
Merged-from >1 source sets `cross_listed`. Known quirk (faithful to the TS
original): Immunefi "Audit Comp | X" programs share the `audit`/`comp` tokens
and collapse into a few merged records.

Immunefi drafts adopt `owner/name` repo identity from a repo-level
`githubUrl` when present, so a program like `alchemix-finance/v3` merges with
its GitHub issue bounties; org-only URLs are ignored so multi-program orgs
(1inch) don't collapse.
