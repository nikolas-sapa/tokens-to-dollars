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
ranked by max payout, and an `index.json` of per-source fetch status. Use it
to pick tonight's targets and to seed the scope-parser skill with each
program's machine-readable scope before any agent touches it.

## ingest-knowledge

`ingest-knowledge/ingest_knowledge.py` builds the bug-knowledge corpus used
for RAG and few-shot priming: SecurityTalent/bugskill-ai's public H1 report
dump (rediscovered via the GitHub trees API if the path moves), ajaysenr's
HackerOne disclosed-reports index, xdavidhu's Google VRP writeups CSV, and
sayan011's Immunefi writeups list. Output is `records.jsonl` — one
`{source, title, program, weakness, severity, bounty_usd, url, date}` row per
report, best-effort mapped — plus `knowledge-index.json` with per-source
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
subfinder, httpx, nuclei, katana, trufflehog, ffuf, and friends. The rule is
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
it once after cloning so the orchestrator's append paths exist.

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

## audit-log

`audit-log/audit_log.py` is a hash-chained append-only JSONL log — every
intent/fact/finding/dispatch/settle entry binds to the previous hash, with
Merkle checkpoints every 25 entries and payload sidecars for large blobs.
`verify` walks the chain and names the first broken seq; `merkle` re-derives
checkpoint roots. "If it isn't recorded, it didn't happen" as a mechanism.
See `tools/audit-log/README.md`.

## mcp-server

`mcp-server.py` is a hand-rolled stdio JSON-RPC MCP server (stdlib only, ~150
lines) that exposes every repo tool — ingest_scope, ingest_knowledge,
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
