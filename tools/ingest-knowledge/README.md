# ingest-knowledge

Fetches public disclosed-bug and writeup corpora into a normalized JSONL for
RAG indexing and few-shot priming (payout-labeled where upstream provides it).
Python 3.9+, stdlib only.

## Usage

```sh
python3 ingest_knowledge.py                    # writes ./out
python3 ingest_knowledge.py --out-dir knowledge/corpus
python3 ingest_knowledge.py --sources bugskill-ai,ajaysenr-h1
python3 ingest_knowledge.py --timeout 10
```

| arg | default | effect |
|---|---|---|
| `--out-dir` | `./out` | output directory, created if missing |
| `--sources` | all | comma-separated source filter |
| `--timeout` | `30` | per-fetch timeout in seconds |

Individual source failures are tolerated: the source is marked `error` in
`knowledge-index.json`, a warning is logged, and remaining sources continue.
If a hardcoded URL 404s, the script rediscovers the payload via the GitHub
git-trees API before giving up.

## Sources

| source | content | discovery |
|---|---|---|
| `bugskill-ai` | ~10k HackerOne public reports (title, CWE, severity, bounty, program) | git-trees API picks the largest `*.json` matching `report\|hacktivity` (currently `hackerone_public_reports.json`, ~14 MB); falls back to `data/reports.json` |
| `ajaysenr-h1` | ~13k HackerOne disclosed-report index rows | `index.json`, with trees-API fallback |
| `xdavidhu-google-vrp` | ~300 Google VRP writeups (`writeups.csv`) | fixed CSV URL |
| `sayan011-immunefi` | ~100 Immunefi/web3 writeups parsed from the README markdown table | fixed URL; bounty strings like `10M`, `1M+50k`, `400 ETH` parsed to `bounty_usd` (non-USD denominations → `null`, `Not Paid` → `0`) |

## Outputs

- `records.jsonl` — one normalized record per line:
  `{source, title, program, weakness, severity, bounty_usd, url, date}`.
  Best-effort field mapping; missing values are `null`. `weakness` holds CWE
  text where upstream provides it.
- `knowledge-index.json` — `generated_at`, `total_records`, and per-source
  `{source, url, status, n_records, file, fetched_at, error?}`.

## Ownership note

These corpora are author-owned compilations of third-party reports and
writeups. Fetch and mirror them inside your own infrastructure for retrieval;
do not redistribute, relicense, or republish `records.jsonl` or derivatives
as your own dataset. Report copyrights live with the original authors and
platforms (HackerOne, Immunefi, individual researchers).
