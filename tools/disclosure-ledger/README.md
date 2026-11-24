# disclosure-ledger

SHA commitment ledger for our own vulnerability disclosures, after Anthropic's
CVD-ledger pattern. Committing a finding writes its `sha256` plus metadata
(ts, program, short title, optional severity) into a hash-chained JSONL
file -- never the finding body -- so the ledger proves **what we knew and
when** without leaking the report. Python 3.9+, stdlib only.

Default ledger: `memory/disclosure-ledger.jsonl` (override with `--ledger`).

```bash
# commit a finding before disclosure (body from file or stdin via -)
python3 tools/disclosure-ledger/ledger.py commit \
    --program acme --finding reports/acme-idor.md --severity high

python3 tools/disclosure-ledger/ledger.py list            # or --program acme
# seq   hash        ts                       status      title
# 0     sha256:9f…  2026-…Z                  committed   idor on /api/orders

# pre-disclosure proof for pasting into a report: public-safe, body-free
python3 tools/disclosure-ledger/ledger.py publish --seq 0
# {"seq":0,"sha256":"sha256:…","ts":"…Z","program":"acme",
#  "statement":"finding hash committed at …Z"}

# struck-through withdrawal: entry stays, status flips, reason is chained in
python3 tools/disclosure-ledger/ledger.py withdraw --seq 0 \
    --reason "duplicate of report #123456"

python3 tools/disclosure-ledger/ledger.py verify          # exit 0 ok / 1 broken
```

## Why

- **Dispute defense.** If a program later claims "we already knew" or disputes
  the timeline, the chain shows the finding's SHA existed in our ledger at a
  specific timestamp -- before their response.
- **Pre-disclosure proof.** `publish` emits a body-free attestation
  (`{seq, sha256, ts, program}`) that can go into the report itself, letting
  the program verify we committed before any negotiation. Reveal the body
  later; the hash already binds us.
- **Withdrawal transparency.** Mistaken claims get struck through, not
  deleted. `withdraw` appends a `withdrawal` record naming `commit_seq` and a
  reason, so the public record stays complete -- same semantics as
  Anthropic's struck-through ledger entries.

## Format

One JSON object per line:

```json
{"v":1,"seq":0,"ts":"…Z","kind":"commit","data":{"program":"acme","sha256":"sha256:…","bytes":1234,"title":"idor on /api/orders","severity":"high"},"prev_hash":"sha256:…","hash":"sha256:…"}
{"v":1,"seq":1,"ts":"…Z","kind":"withdrawal","data":{"commit_seq":0,"reason":"duplicate of #123456"},"prev_hash":"sha256:…","hash":"sha256:…"}
```

- `hash = sha256( prev_hash_raw_bytes ‖ canonical_json(entry minus hash) )`,
  canonical = `json.dumps(sort_keys=True, separators=(",",":"))`.
- Genesis `prev_hash = sha256("disclosure-ledger-genesis-v1")`.
- `data.sha256` is the digest of the finding body exactly as read (file or
  stdin). The body itself is never written to the ledger.
- `verify` recomputes every link and also rejects withdrawals that target a
  missing or non-commit seq. `list` renders status as `committed` /
  `withdrawn` by scanning for matching `withdrawal` records.

## vs audit-log

`tools/audit-log` records **decisions and events** -- intents dispatched,
facts observed, payouts settled -- the operational trail of the pipeline.
`tools/disclosure-ledger` records **disclosure commitments** -- content-bound
proofs about findings we hold, plus their withdrawals. Audit entries may
embed sidecar payloads; the disclosure ledger never does, because the whole
point is timestamping a hash *without* storing the sensitive body.
