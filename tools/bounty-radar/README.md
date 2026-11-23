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
  `value_score = reward_usd * (1 - competition_score/100)`, ties by `age_days`
  ascending. Read top-to-bottom.
- `index.json` — `generated_at`, per-source `{source, status, n_drafts,
  error?}`, `total_drafts`, `merged_drafts`, `total_bounties`.

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

## Ranking caveat — reward-table velocity

`value_score` prices reward x competition only; it does **not** see
reward-table velocity (recent raises/cuts to a program's payout table).
Supply is elastic: programs that cut tables draw ~22% fewer valid reports
(~50% fewer criticals) — recently-cut programs should be deprioritized and
recently-raised ones preferred when the direction is known.

Cheap signal shipped here: `table_updated_at` carries Immunefi's
`updatedDate` (null for GitHub sources — issue bounties have no table
concept). A recent timestamp only means *something* on the record changed —
verify the direction on the program page before treating it as a raise or a
cut. No free endpoint exposes per-table diffs; a real velocity signal needs
a snapshot diff against a previous run's `bounties.jsonl`.

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
