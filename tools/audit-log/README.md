# audit-log

Hash-chained append-only audit log — "if it isn't recorded, it didn't happen"
as a mechanism, not a slogan. Every intent dispatched, fact observed, finding
claimed, and payout settled lands as a JSONL entry bound to the one before it,
so a tampered or dropped record fails verification instead of passing silently.
Python 3.9+, stdlib only.

```bash
# append an entry (kinds: intent|fact|finding|dispatch|settle)
python3 tools/audit-log/audit_log.py append audit.jsonl \
    --kind intent --data '{"program":"acme","worker":"PB-3","est_usd":0.42}'

# large payloads go to a sidecar instead of inline
python3 tools/audit-log/audit_log.py append audit.jsonl \
    --kind finding --data '{"id":"f-017","title":"idor on /api/orders"}' \
    --sidecar evidence/f-017-poc.txt

# walk the chain: seq contiguity, prev_hash continuity, entry hashes,
# checkpoint roots, sidecar digests. First break names the seq. Exit 0/1.
python3 tools/audit-log/audit_log.py verify audit.jsonl
# -> OK n=341 tip=sha256:c4d0… checkpoints=13   or   FAIL seq=88 prev_hash mismatch

# print every checkpoint segment + its recomputed Merkle root
python3 tools/audit-log/audit_log.py merkle audit.jsonl
```

## Format

One JSON object per line:

```json
{"v":1,"seq":41,"ts":"…Z","kind":"finding","data":{…},"prev_hash":"sha256:…","hash":"sha256:…"}
```

- `hash = sha256( prev_hash_raw_bytes ‖ canonical_json(entry minus hash) )`,
  canonical = `json.dumps(sort_keys=True, separators=(",",":"))`.
- Genesis `prev_hash = sha256("eval-audit-genesis-v1")`.
- Every 25 non-checkpoint entries, a `kind:"checkpoint"` entry is appended
  holding the Merkle root over that segment's entry hashes (mini
  Certificate-Transparency, RFC 6962 lineage).
- `--sidecar` copies the file into `payloads/` next to the log; the entry
  stores `sidecar.path` + `sidecar.sha256`, keeping the chain small while any
  payload tamper stays detectable.

## What it proves (and doesn't)

The log proves these events were recorded in this order and nothing was
dropped or rewritten after the fact. It does not prove the claims inside are
true — that's what validators and `verify.sh`-style checks are for. A signed
lie is still a lie.

## Where ed25519 signing slots in

Signing is deliberately omitted (stdlib has no ed25519). To add it later:
`entry["sig"] = ed25519_sign(bytes.fromhex(hash.split(":",1)[1]))` at append
time — sign the entry hash, nothing else. `verify` gains an optional pubkey
arg and re-checks each `sig` alongside the hash recompute; checkpoints get
signed the same way. The hash chain already provides integrity; the signature
adds *attribution* (proof a specific keyholder wrote the line). Drop-in points:
`append()` after `entry["hash"]`, and the per-entry loop in `verify()`.
