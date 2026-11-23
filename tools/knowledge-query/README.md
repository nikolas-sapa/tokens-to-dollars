# knowledge-query

Fast local search over the disclosed-bug/writeup corpus produced by
`tools/ingest-knowledge` (`records.jsonl`: `source, title, program,
weakness, severity, bounty_usd, url, date`). Python 3.9+, stdlib only.

## Usage

```sh
python3 query.py --file knowledge/records.jsonl --keyword "idor"
python3 query.py --cwe CWE-79 --program acme --limit 10
python3 query.py --severity critical --min-bounty 5000
python3 query.py --keyword "ssrf" --json
```

| arg | default | effect |
|---|---|---|
| `--file` | `knowledge/records.jsonl` | corpus file |
| `--program` | — | program substring, case-insensitive |
| `--cwe` | — | weakness/CWE substring, case-insensitive |
| `--severity` | — | severity substring, case-insensitive |
| `--min-bounty` | — | minimum `bounty_usd` (drops `null`) |
| `--keyword` | — | substring over title/weakness/program/url |
| `--limit` | `20` | max hits |
| `--json` | off | emit `{"count": N, "hits": [...]}` |

Hits are ranked by `bounty_usd` descending, then recency. All filters are
case-insensitive substring matches — "substring" deliberately, so `CWE-79`
matches `CWE-79: XSS` and `idor` matches `IDOR in ...`.

## dedupe-check integration

`skills/dedupe-check` calls this as source 2 (the `knowledge/` corpus):
query by `--cwe` + `--program` from the finding signature, then by
`--keyword` on the endpoint/param pattern. Compare each hit on the four
axes (asset, class, root cause, primitive) before issuing a verdict.
Use `--json` for scripted verdicts — `count` is the hit count the skill
must log even when it is zero.
