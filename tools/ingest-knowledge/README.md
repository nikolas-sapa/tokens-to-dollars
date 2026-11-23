# ingest-knowledge

Fetches public disclosed-bug and writeup corpora into a normalized JSONL for
RAG indexing and few-shot priming (payout-labeled where upstream provides it).
Python 3.9+, stdlib only.

## Usage

```sh
python3 ingest_knowledge.py                    # writes ./out
python3 ingest_knowledge.py --out-dir knowledge/corpus
python3 ingest_knowledge.py --sources bugskill-ai,ajaysenr-h1
python3 ingest_knowledge.py --list             # show source names
python3 ingest_knowledge.py --trickest-cap 100
python3 ingest_knowledge.py --sources solodit --solodit-cap 200
python3 ingest_knowledge.py --sources patchdb --db ~/data/CVEfixes.db
python3 ingest_knowledge.py --timeout 10
```

| arg | default | effect |
|---|---|---|
| `--out-dir` | `./out` | output directory, created if missing |
| `--sources` | all | comma-separated source filter |
| `--list` | off | print source names and exit |
| `--trickest-cap` | `500` | max trickest/cve writeup records (newest year dirs first) |
| `--huntr-cap` | `250` | max legacy huntr vulnerability.json fetches (418sec/huntr fallback only) |
| `--solodit-cap` | `500` | max solodit findings (paged API, 50/page) |
| `--primevul-cap` | `2000` | max primevul dataset rows scanned for the CVE index |
| `--db` | none | local CVEfixes/MoreFixes sqlite path; required by `patchdb` |
| `--db-cap` | `5000` | max patchdb vuln+patch pairs emitted |
| `--timeout` | `30` | per-fetch timeout in seconds |

`solodit` needs `SOLODIT_API_KEY` in the environment (generate at
solodit.cyfrin.io -> profile -> API Keys). Without it the source is marked
`error` in the index and skipped. Upstream rate limits are ~100 req/min and
~10k req/day; the adapter sleeps between pages and stays well under both.

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
| `trickest-cve` | bounded subset of trickest/cve markdown writeups (newest `--trickest-cap` files, default 500) | git-trees API: year dirs sorted desc, per-year subtrees until cap; CVE id → `title`/`weakness`, year dir → `date` |
| `defihacklabs` | ~915 SunWeb3Sec/DeFiHackLabs incident index rows | README index `[YYYYMMDD name](link)` rows; `### Lost:` lines land in `title` (`bounty_usd` stays `null` — these are losses, not payouts); PoC `.sol` path → `url` |
| `nuclei-templates` | one aggregate record per top-level template dir (`nuclei:<class>`, ~14 rows) | single recursive git-tree call; `.yaml`/`.yml` counts by top-level dir; warns if the tree is truncated |
| `arvo` | ~10k OSS-Fuzz crash records from n132/ARVO `metadata.jsonl` | lightweight JSONL index used instead of multi-GB `arvo.db`; HEAD-checks size and soft-skips (>50 MB) |
| `reddelexc-h1` | ~15k HackerOne disclosed-report rows (`data.csv`) | fixed CSV URL; columns `program,title,link,upvotes,bounty,vuln_type` |
| `huntr` | huntr.com (Protect AI) AI/ML bug disclosures; record per vuln: title, CWE, repo, `status`, disclosed date | parses `__NEXT_DATA__` embedded JSON on the public `/bounties` page (recursive search for vuln-shaped dicts); if the page yields nothing — the site is JS-rendered and its data shape shifts — falls back to the legacy `418sec/huntr` repo: one git-tree call, then the newest `--huntr-cap` `bounties/**/vulnerability.json` payloads |
| `solodit` | Cyfrin Solodit web3 audit findings; record per finding: protocol, severity (impact), category, `firm` | `POST https://solodit.cyfrin.io/api/v1/solodit/findings` with `X-Cyfrin-API-Key` (env `SOLODIT_API_KEY`); paged, deduped by url/title, `--solodit-cap` bound; response envelope probed under several key names |
| `primevul` | PrimeVul C/C++ vuln+patch dataset, one **index record per CVE**: cve, cwe, project, commits, `n_samples`; carries `vulnerable_func`/`patched_func` when a row supplies both | full shards are ~500 MB+, so rows are paged through the HF datasets-server (`--primevul-cap` bound, splits test->validation->train); falls back to a shard-level index of the `timothee-chauvin/PrimeVul-assets-on-github` mirror |
| `patchdb` | CVEfixes/MoreFixes local sqlite: one record per vuln+patch **method pair** with `cve`, `commit`, `file`, `method`, `vulnerable_func`, `patched_func` | reads `--db` in sqlite read-only mode; expected schema below, fails loudly on missing tables/columns or zero rows |

## Outputs

- `records.jsonl` — one normalized record per line:
  `{source, title, program, weakness, severity, bounty_usd, url, date}`.
  Best-effort field mapping; missing values are `null`. `weakness` holds CWE
  text where upstream provides it. Sources with richer payloads may add extra
  keys on top of the fixed schema — `huntr` adds `status`/`repo`/`cve`,
  `solodit` adds `firm`, `primevul` adds `cve`/`commits`/`n_samples` (and
  function bodies when present), `patchdb` adds
  `cve`/`commit`/`file`/`method`/`vulnerable_func`/`patched_func`.
- `knowledge-index.json` — `generated_at`, `total_records`, and per-source
  `{source, url, status, n_records, file, fetched_at, error?}`.

### patchdb expected schema

`--db` points at a CVEfixes- or MoreFixes-format sqlite database (e.g. the
`CVEfixes.db` / `MoreFixes.db` releases from their respective projects).
Required tables and columns (alternate column names are probed):

```text
cve(cve_id [, published])
fixes(fix_id, cve_id, hash, repo_url)
file_change(file_change_id, fix_id, filename)
method_change(method_change_id, file_change_id, name, before_change, code)
```

`before_change` pairs rows per method: `'True'` is the vulnerable version,
`'False'` the patched one (`1`/`0` also accepted). Only complete pairs are
emitted; unpaired methods are skipped. Missing file, wrong schema, or an
empty join all raise and land as `error` in the index rather than silently
emitting nothing.

## Ownership note

These corpora are author-owned compilations of third-party reports and
writeups. Fetch and mirror them inside your own infrastructure for retrieval;
do not redistribute, relicense, or republish `records.jsonl` or derivatives
as your own dataset. Report copyrights live with the original authors and
platforms (HackerOne, Immunefi, individual researchers).
