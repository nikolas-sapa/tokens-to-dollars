# tools

Local CLI tooling for the skill-pack. Python 3.9+, stdlib only unless a
subdir README says otherwise. Every script fails soft per-source, writes to a
caller-chosen `--out-dir`, and is safe to run on a cron/CI schedule.

## ingest-scope

`ingest-scope/ingest_scope.py` pulls the public, keyless bug-bounty scope
feeds (arkadiyt/bounty-targets-data per-platform JSONs for HackerOne,
Bugcrowd, Intigriti, YesWeHack and HackenProof, the lissy93/bug-bounties API,
disclose/diodb, and the Immunefi public API) and normalizes every program
into one schema: platform, handle, payout ceiling, safe-harbor flag, in/out
of scope target lists, and policy URL. It dedupes on
`(platform, handle-or-name)` and emits `programs.json`, a `programs.tsv`
ranked by max payout, and an `index.json` of per-source fetch status. diodb
records also carry a `contact` block (report email, contact/security.txt and
PGP-key URLs, preferred languages) plus `disclosure_timeline_days` and
`launch_date`, matching the scope-parser manifest's contact fields. Use it
to pick tonight's targets and to seed the scope-parser skill with each
program's machine-readable scope before any agent touches it.

## ingest-knowledge

`ingest-knowledge/ingest_knowledge.py` builds the bug-knowledge corpus used
for RAG and few-shot priming: SecurityTalent/bugskill-ai's public H1 report
dump (rediscovered via the GitHub trees API if the path moves), ajaysenr's
HackerOne disclosed-reports index, xdavidhu's Google VRP writeups CSV,
sayan011's Immunefi writeups list, the Immunefi bugfix-review corpus
(`immunefi-bfr`: `Web3-Security-Library`'s BugFixReviews index enriched
with `bugfix-reviews-pocs`' reward/PoC table), a per-contest index of
code-423n4 `*-findings` repos (`code4rena`: ~376 contests, `n_findings`
counts from rate-limit-gated git-tree calls carried forward across runs),
a bounded slice of trickest/cve writeups
(`--trickest-cap`, default 500 newest), SunWeb3Sec/DeFiHackLabs incident
index rows, per-class aggregate counts from nuclei-templates (one
`nuclei:<class>` record per top-level dir), n132/ARVO's OSS-Fuzz
`metadata.jsonl` index (soft-skips if it ever exceeds 50 MB), and
reddelexc/hackerone-reports' `data.csv` of disclosed H1 reports. Four newer
adapters widen the corpus: `huntr` parses huntr.com's public disclosures
(falling back to the legacy 418sec/huntr repo when the JS page yields
nothing), `solodit` pages the Cyfrin findings API (`SOLODIT_API_KEY`,
~100 req/min upstream limit), `primevul` emits one index record per CVE from
bounded datasets-server row windows (the full shards run ~500 MB+), and
`patchdb` reads a local CVEfixes/MoreFixes sqlite via `--db` and emits one
record per vuln+patch method pair — the func bodies feed
verify_claims/patch-diff work. `--free-corpus` runs every keyless source
(no API key, no local file) in one shot; `--list` prints the source names.
Runs merge into `records.jsonl` incrementally — refreshed sources replace
their rows, untouched/errored sources keep theirs (`--replace` rewrites
from scratch). Output is `records.jsonl` — one
`{source, title, program, weakness, severity, bounty_usd, url, date}` row per
report, best-effort mapped (adapters may add keys like `firm`, `status`,
`n_findings`, `vulnerable_func`) — plus `knowledge-index.json` with per-source
counts. Content is author-owned: mirror internally, never redistribute.

## bounty-radar

`bounty-radar/bounty_radar.py` is the funded-bounty counterpart to
ingest-scope's program catalog: instead of "which programs exist" it answers
"which specific bounties are worth hunting tonight". It pulls GitHub issue
bounties (label search plus escrow-platform links in bodies and bounty-tagged
repos) and the Immunefi public API, dedupes cross-listed records, drops
scam-bait listings, classifies funding proof (escrowed > verified-history >
claimed > unknown), and scores competition 0-100 from comments, linked PRs,
reactions, cross-listing and freshness. Output is `bounties.jsonl` ranked by
`reward_usd * (1 - competition/100)` plus an `index.json` of per-source
health — low-competition x high-reward rows on top. GitHub works
unauthenticated at low rate (honors `GH_TOKEN`); every source fails soft.

## wrap

`wrap/` holds thin CLI adapters around best-in-class open tools —
subfinder, httpx, nuclei, katana, trufflehog, ffuf, dnsx, gau, waybackurls,
arjun, x8, subzy, wafw00f, and naabu-passive (the OSINT `-passive` mode only;
active port scanning stays unwrapped). The rule is
*wrap atomic tools, never reinvent*: each adapter does exactly three things —
translate our normalized input (scope rows, target lists) into the tool's
native flags/config, invoke the binary with sane defaults and hard rate
limits inherited from the program's RoE, and parse stdout back into our JSON
record shape so skills can consume results uniformly. No reimplementing
crawl, fuzz, or scan logic in Python; if a capability exists as a maintained
binary, we shell out and normalize.

## ledger

`ledger/ledger.py` parses `memory/ledger.md` — the append-only spend/payout
table the orchestrator maintains — into the scoreboard: total and per-program
spend, findings/facts/FPs per program and per technique, cost-per-finding,
EV (payout dollars / token dollars), open pipeline, and cost-ceiling
warnings. This is the repo's namesake metric: dollars in, dollars out.

## knowledge-query

`knowledge-query/query.py` searches the `records.jsonl` corpus built by
ingest-knowledge — by program, weakness/CWE, severity, bounty floor, or
keyword — and returns hits ranked by bounty then recency. It is what
`skills/dedupe-check` calls to answer "is this bug already disclosed?"
before a draft is written.

## bootstrap

`bootstrap.py` creates the local state skeleton — `memory/` lessons files,
`engagements.md` index, `ledger.md` with its real table headers, plus
`targets/`, `reports/`, `data/`, `knowledge/` directories. Idempotent; run
it once after cloning so the orchestrator's append paths exist. It also
acts as a doctor: missing recon tools get per-tool install lines (brew on
macOS, `go install` fallback) plus a one-shot `install all:` command, and
missing optional keys (`GITHUB_TOKEN`, `SOLODIT_API_KEY` under `env` in
`~/.config/tokens-to-dollars/config.json` — presence checked, values never
printed) get a `t2d setup` pointer. `--doctor` runs only the checks and
creates nothing, so it is safe any time.
Engagement scratch material (fetched specs, page dumps, downloaded
artifacts) goes to `memory/targets/<program>/work/` — never `/tmp`.

## content-scan

`content-scan/scan.py` is the deterministic pre-planner filter: workers
pipe fetched, attacker-influenced content — HTTP bodies, JS bundles, tool
output, disclosed writeups — through it before the planner ever sees the
bytes. It emits `{"verdict": clean|suspicious|hostile, "hits": [...]}` and
exits 0/1/2, so a hostile page can gate a pipeline outright.

The rule tables are ported from toolfence (8 known-bad signatures,
injection patterns, sensitive-capability regexes, Unicode hygiene) and
grip-browser (anchored role prefixes plus a confusable/zero-width fold
that catches `Ig<ZWSP>nore`-style splitting). `--sanitize` strips
invisibles and wraps matches in `[REDACTED-rule]` markers for content
that must still be reasoned over. See `skills/injection-defense`.

## evidence-store

`evidence-store/store.py` ports clone-attack-security's strict JSON
evidence parser and RunBinding digest-binding into our
`evidence/<finding-id>/` layout: `store.py write <dir>` validates a
manifest (exact key set, sha256 per captured file, finding_id bound to
the dir name) and writes `evidence.json` + a `sha256sum`-format
`evidence.sha256` sidecar — append-once, it refuses to overwrite.
`store.py verify <dir>` re-binds every field and re-hashes every file so
a verifier proves it re-checked the same dir the finder wrote.

`evidence-store/redact.py` ports helm's capture-time redaction: known
secret shapes (Anthropic `sk-ant`, generic `sk-`, GitHub `ghp_`/`gho_`,
JWTs, AWS `AKIA`, PEM private-key blocks, generic Bearer) are replaced
with `[redacted]` *before* any `--max-bytes` truncation, so a token
straddling the cap can't be half-stored. See `skills/evidence`.

## guardian

`guardian/guardian.py` is the second enforcement layer behind `wrap/`:
an independent action-level adjudicator (the XBOW Guardian-model
concept, code-enforced). Where wrap checks the *string* of a command,
guardian takes a structured action object (`{type: http|shell, method,
url, headers, body | argv}`) and returns `allow` / `escalate` / `deny`
(exit 0/2/3) — blind by design, so the agent's stated justification is
never an input. Scope matching delegates to `wrap.py` (one authority);
deny rules cover exfil-shaped headers to non-authorized hosts,
secret-shaped material, denylist, out-of-scope, destructive shell;
escalate covers ambiguous scope, manifest `forbidden_actions`, and
mutating verbs over rate — the deny-porosity rule, nothing unprovable
is silently allowed. Fail-closed everywhere. Wired into
`mcp-server.py run_tool` so every `tools/call` is adjudicated before
dispatch — see `tools/guardian/README.md` § MCP dispatch path.

## fact-verify

`fact-verify/verify_claims.py` is the mechanical grounding gate — verdicts
by grep, not judgment. Default mode parses an exploration-graph facts file
for `[F-n]`/`[FD-n]` nodes, extracts each node's asserted payload(s)
(`payload:`/`quote:` field or inline backtick/quoted spans), and greps the
raw worker trace (`--trace` file or dir): any payload absent emits
`soliloquy` — the claim was never observed. `--verbatim` mode enforces the
BaaRai POE invariant: every `quotes[]` string in a finding's evidence
receipt must appear verbatim in its referenced stored bodies, else the
missing quote is named. JSONL verdicts out; exit 1 on any failure so a
pipeline can gate graph writes and `verified` labels on it. See
`skills/hunt/references/verification.md` § Mechanical grounding.

## audit-log

`audit-log/audit_log.py` is a hash-chained append-only JSONL log — every
intent/fact/finding/dispatch/settle entry binds to the previous hash, with
Merkle checkpoints every 25 entries and payload sidecars for large blobs.
`verify` walks the chain and names the first broken seq; `merkle` re-derives
checkpoint roots. "If it isn't recorded, it didn't happen" as a mechanism.
See `tools/audit-log/README.md`.

## engage-clean

`engage-clean/clean.py` is the one-time-engagement purge: `--program <name>`
distills the target's lessons into `memory/lessons/distilled.md` (program
name and hostnames scrubbed), moves `memory/targets/<program>/`, report
drafts, and graph-archive rows to macOS Trash, and masks the program name
in `engagements.md`/`ledger.md` while keeping the accounting rows. The
audit chain is deliberately untouched — append-only proof of authorized
work. `--keep-lessons`, `--dry-run` supported.

## coverage

`coverage/ledger_store.py` backs `skills/coverage-ledger` with SQLite (WAL,
append-only event rows, derived active-claim view) so the claim protocol is
atomic instead of hand-appended: `claim` is a BEGIN IMMEDIATE check-and-insert
that fails on a live claim and auto-STEALs a stale one, `heartbeat` keeps the
30-minute window (configurable), `release` settles exactly once, `steal`
fences a dead holder and re-claims in one transaction, and fenced workers'
late writes are refused. `status`/`stale` show the derived state; `export
--md` renders the coverage.md table+log for humans. Db: `memory/coverage.db`.

## change-detect

`change-detect/detect.py --target <dir>` is the commit-triggered wave
detector: `add <url> [js|schema|changelog|fingerprint]` registers kind-tagged
watch URLs that move when a target ships; `check` refetches them all —
HEAD-then-GET, 30s timeout, sha256-compare — and reports
baseline/changed/unchanged/error as JSON plus `changes.md`, and appends
`{"kind","url","signal"}` lines to `triggers.jsonl` when a diff shows a real
deploy signal (new endpoint/asset/version/host — a don't-wake gate drops
CSS/media/.map/status-text churn). `poll-ct` dedupes crt.sh cert names into
`new-subdomain` triggers (priority bump on api/staging/admin/dev/beta);
`poll-feed` keyword-gates Atom/RSS changelog entries into `changelog`
triggers. Fetching requires `--only-host` (exact match, repeatable) per
`skills/safety-gates`; redirects off the allowlist are refused. `diff`
prints unified diffs of stored text bodies when `--store-bodies` was used
on the check.

## patch-hunter

`patch-hunter/patch_hunter.py` is diff-seeded variant analysis (Big Sleep /
KNighter / CopyFail): a security fix commit is a hunt seed because the patch
itself names the bug class, the misused API, and the missing guard. `seed
--repo <path|url> --commit <sha|a..b>` parses the diff into `seed.json` —
changed functions, a bounds/null-deref/UAF/overflow/injection/auth
heuristic from patch keywords plus delta shape, and sibling candidates
(same-file, caller-of, api-user, missing-guard). `variants --seed seed.json`
grep-sweeps the repo (no build) for call sites lacking the fix's guard terms
within `--window` lines — `pre-patch-shape` hits are the CopyFail signature.
`watch manifest.json` polls repos for new commits matching
`fix|security|cve|overflow|bounds|auth` and appends `kind:patch-seed` lines
to `triggers.jsonl` (change-detect envelope), feeding the orchestrator.
Offline on local clones by default; `--fetch`/clones need the git host in
`only_hosts`/`--only-host` — no allowlist, no traffic.

## memory-consolidate

`memory-consolidate/consolidate.py --root <repo>` is sleep-time maintenance
for `memory/`: merges near-duplicate lesson lines (Jaccard > 0.8 on token
sets, newest dated entry wins, losers struck and dated), regenerates
`lessons/technique-yield.md` deterministically from `[Y-n]` yield records,
flags contradictions where the same normalized claim is both struck and live
(never auto-resolves), and rebuilds per-target `index.md` plus root
`memory/index.md`. `--dry-run` reports without writing; it never deletes.

## mcp-server

`mcp-server.py` is a hand-rolled stdio JSON-RPC MCP server (stdlib only)
that exposes every repo tool — ingest_scope, ingest_knowledge,
bounty_radar, ledger, knowledge_query, content_scan, wrap, audit_log_append —
as MCP `tools/call` targets by shelling out to the same CLI scripts. Point an
MCP client at it with a `.mcp.json` like:

```json
{
  "mcpServers": {
    "tokens-to-dollars": {
      "command": "python3",
      "args": ["/absolute/path/to/tokens-to-dollars/tools/mcp-server.py"]
    }
  }
}
```

Speaks `initialize`, `tools/list`, `tools/call`, `ping`; tool failures return
`isError` content, protocol failures use JSON-RPC codes.

Every `tools/call` is adjudicated by `guardian/` before dispatch
(`run_tool` → `adjudicate` → bounded subprocess): `allow` executes
normally, `escalate` returns a structured pending-approval result
(`{"status":"escalated","hold":<action_sha256>,...}`) without executing,
`deny` returns `{"status":"denied","rule","class",...}`. Local path
operands are part of the logical argv guardian judges. The manifest of
the engaged program comes from the call's `manifest` arg, `T2D_MANIFEST`,
a `content_scan` `program` context, or a single
`memory/targets/<program>/roe-manifest.*`; a missing adjudicator or
manifest fails closed to escalate, never allow. Verdicts land in the
hash-chained decision log (`memory/audit.jsonl`). See
`tools/guardian/README.md` § MCP dispatch path.

`content_scan` is metadata-first: by default it returns only
`{"verdict","hits":[{"rule","severity","line",...}]}`, not the scanned
file or hit contexts. A content copy is returned only when
`include_content` is true; `sanitize` controls whether that copy is
sanitized. Scanning a file under
`memory/targets/<program>/` requires a matching `program` argument;
paths outside the engagement tree are unaffected by that check.

Child processes run in a new process group. On timeout the server sends
SIGTERM, then SIGKILL, to the whole group and reports if survivors remain.
stdout/stderr capture is bounded to 256 KiB or 2000 lines per stream;
oversized output is an `isError` result with a deterministic truncation
notice, not silent context flood. Model-facing errors redact operator
paths as `$ROOT`/`$HOME`.
