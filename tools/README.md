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
