# bounty-radar

Funded-bounty intelligence: aggregates live, money-backed bounties (GitHub
issue bounties, escrow-linked issues, Immunefi programs, algora/opire issue
rewards, Sherlock contests, bbscope fresh-scope), filters out scams, scores
how contested each one already is, and ranks them by expected value.
Python 3.9+, stdlib only. Ported from the x402-bounty-radar TS service.

## Usage

```sh
python3 bounty_radar.py                          # all sources -> ./out
python3 bounty_radar.py --sources immunefi       # keyless, most reliable
python3 bounty_radar.py --sources opire,bbscope  # keyless issue rewards + fresh scope
python3 bounty_radar.py --min-reward 1000 --max-competition 30
python3 bounty_radar.py --out-dir data/radar
```

| arg | default | effect |
|---|---|---|
| `--sources` | `github,github-extras,immunefi,algora,opire,sherlock,bbscope` | comma list of adapters to run |
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
| `github-extras` | `api.github.com/search/{issues,repositories}` | same | issue bodies linking escrow platforms (`algora.io/bounties` => `escrowed`) + `topic:bug-bounty`/`topic:bounty` repos as program-level listings |
| `immunefi` | `immunefi.com/public-api/bounties.json` | none | live programs (paused skipped); `maxBounty`/`averageBounty` => `reward_usd`; `endDate` => `deadline`; always `escrowed` (funds locked on-platform); `inviteOnly` => `invite_only` EV boost |
| `algora` | `api.algora.io/v1/bounties`, fallback `algora.io/api/trpc/bounty.list` | none | escrowed issue bounties; REST path now 404s (board pivot) so the tRPC router is the live surface — currently returns an empty items list, kept wired for when it repopulates |
| `opire` | `api.opire.dev/rewards` | none | GitHub issue rewards; `pendingPrice` USD_CENT => `amount_usd`; `tryingUsers` => comments proxy, `claimerUsers` => linked-PR proxy; funding `claimed` (payout promised, not provably escrowed) |
| `sherlock` | `audits.sherlock.xyz/api/contests?page=N` | none | keyless paginated; skips `private` and `FINISHED`/`CANCELLED`/`ARCHIVED`; USDC `prize_pool`/`rewards` => amounts, escrowed; contests <=14d old => `new_scope`; feed currently lists only FINISHED contests, so expect 0 drafts until a live one posts |
| `bbscope` | `bbscope.com/api/v1/updates?page=1` | none | cross-platform scope-change feed (h1/bc/intigriti/ywh); `program_added` updates => drafts; every update's handle+host feeds the `new_scope` matcher for drafts from other sources |

**Dead / stale feeds — do not re-add:** `polar.sh` (dead since Apr-25; the
github-extras issue-body query was removed), `federacy` (dead), `issuehunt`
(stale), `code4rena`/`c4` (winding down), `hackerhive` (dead). If any of
these reappears upstream it needs a fresh adapter, not a re-enable.

Unauthenticated GitHub search is ~10 req/min. A full run costs ~7 requests, so
back-to-back runs 403 — the adapters degrade to what succeeded rather than
zero the output. With `GH_TOKEN` set the tool additionally enriches the top
GitHub hits: issue-timeline `linked_prs` counts (max 15 issues) and
`repoBountyHistory` (closed `bounty in:title` issues => `verified-history`
funding, max 10 repos).

## Outputs

- `bounties.jsonl` — one record per line, value-ranked:
  `value_score = reward_usd * (1 - competition_score/100) *
  product(ev_factors) * trend_weight`, ties by `age_days` ascending.
  `reward_usd` = `amount_usd` if set, else `avg_bounty`, else `max_reward` —
  a real payout mean beats a headline ceiling where a source reports both.
  Read top-to-bottom.
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
  "source": "github | github-extras | immunefi | algora | opire | sherlock | bbscope",
  "url": "https://...",
  "title": "...",
  "repo": "owner/name or program name",
  "number": 123,
  "reward_usd": 5000,
  "amount_usd": 5000,
  "avg_bounty": null,
  "max_reward": null,
  "funding": "escrowed | verified-history | claimed | unknown",
  "escrowed": true,
  "competition_score": 25,
  "competition_band": "low | medium | high",
  "competition_signals": {"comments": 3, "linked_prs": 1, "reactions": 4,
    "age_days": 5, "cross_listed": true, "source_notes": ["escrow-link:algora"],
    "hackers_thanked": null},
  "bounty_velocity": null,
  "invite_only": false,
  "new_scope": true,
  "time_to_bounty_days": null,
  "informative_rate": null,
  "ev_factors": {"new_scope": 1.25},
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
platform — Immunefi, Sherlock USDC pools, algora) > `verified-history` (this
repo has closed "bounty"-titled issues = paid before; token-gated) >
`claimed` (a dollar amount is asserted but unverified — opire rewards,
bbscope listings) > `unknown`.

## Expected-value factors

`value_score` multiplies `reward_usd * (1 - competition_score/100)` by every
applicable factor below (emitted per record as `ev_factors`), then by the
reward-table `trend_weight`. Each factor applies only when the underlying
field exists — today the H1-style program stats (`bounties_paid_90d`,
`reports_90d`, `hackers_thanked`, `time_to_bounty_days`, `informative_rate`)
are populated only by sources that expose them; the rest flow through as
`null` and contribute no factor.

| field | factor | rationale |
|---|---|---|
| `invite_only` | x1.15 | gated hunter pool is thinner than visible signals show |
| `new_scope` | x1.25 | fresh attack surface (bbscope update or contest <=14d); swarm hasn't landed |
| `time_to_bounty_days` | `max(0.5, 1 - days/365)` | slow-paying programs devalue the listing |
| `informative_rate` | `max(0.4, 1 - rate)` (0-1 or 0-100 input) | informative-prone programs burn submissions |
| `bounty_velocity` = `bounties_paid_90d / reports_90d` | `min(1.3, 0.5 + v)` | fraction of reports that actually pay |

`bounty_velocity` is also emitted as a standalone field: a program paying 40%
of recent reports is a different target than one paying 2%.

## Competition score (0-100)

How contested the bounty already is — the moat metric. Signals:

| signal | points |
|---|---|
| comments | 4/pt, cap 40 — hunters talking under the bounty |
| linked PRs | 12/pt, cap 36 — someone already shipped an attempt |
| reactions | 2/pt, cap 8 — watcher proxy |
| cross-listed on >1 source | +15 — wider hunter reach |
| source notes (escrow link, invite-only, topic tag) | +2 each, cap 10 |
| hackers_thanked | 1/25 thanked, cap 12 — a big thanked pool means a crowded program |
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
