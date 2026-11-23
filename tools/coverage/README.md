# coverage

SQLite backing store for the coverage-ledger protocol (`skills/coverage-ledger`) —
the same CLAIM / HEARTBEAT / RELEASE / STEAL semantics a hand-edited
`coverage.md` encodes, but with an atomic claim so two workers cannot hold one
surface. Python 3.9+, stdlib only. WAL mode, one append-only `events` table;
the active-claim view is derived (last event wins), never stored.

```bash
# claim is a single BEGIN IMMEDIATE check-and-insert — fails while a live
# claim exists, auto-STEALs a stale one (> 30 min without holder activity)
python3 tools/coverage/ledger_store.py claim acme "api.acme.com/v1/users/{id}" --worker int-012

# liveness ping inside the heartbeat window; only the holder may write
python3 tools/coverage/ledger_store.py heartbeat acme "api.acme.com/v1/users/{id}" --worker int-012

# exactly-once settle; a second RELEASE errors
python3 tools/coverage/ledger_store.py release acme "api.acme.com/v1/users/{id}" \
    --status exhausted --techniques idor,param-pollution,method-override

# take a dead worker's surface: fences the old holder and claims, one transaction
python3 tools/coverage/ledger_store.py steal acme "acme.com/settings" --worker int-007 --reason "no heartbeat 45m"

# derived state for every surface of a target
python3 tools/coverage/ledger_store.py status acme
python3 tools/coverage/ledger_store.py stale --minutes 45

# JSON dump, or the human coverage.md (table + log) with --md
python3 tools/coverage/ledger_store.py export acme --md
```

## Semantics enforced

- `--root` picks the repo; the db lives at `<root>/memory/coverage.db`.
- `--window-minutes` is the heartbeat window (default 30; program manifest may
  override). A claim with no holder activity inside the window is stale.
- **Fenced workers cannot write.** HEARTBEAT/RELEASE from anyone but the
  current holder is refused. `heartbeat`/`release` default `--worker` to the
  recorded holder, so callers can omit it.
- **STEAL is for the dead, not the slow.** `steal` errors on a live claim; a
  stale claim taken via `claim` records the STEAL event first, so the log
  still shows exactly-once settlement.
- Worker identity: `--worker`, else `$COVERAGE_WORKER`, else the OS user.
- Mutating commands print a JSON result to stdout and exit 1 with
  `error: …` on refusal.

## Export format

`export --md` renders the file format from the skill verbatim:

```markdown
# Coverage — <program>
updated: <UTC> by ledger_store.py

| surface | claimed-by | status | technique tried | notes | AS-node |
|---|---|---|---|---|---|
| api.acme.com/v1/users/{id} | int-012 | in-progress | — | — | — |

## Log
<UTC> int-012 CLAIM api.acme.com/v1/users/{id}
<UTC> int-012 RELEASE api.acme.com/v1/users/{id} status=exhausted techniques=idor,…
<UTC> int-007 STEAL acme.com/settings from int-012 — no heartbeat 45m
```

`notes` and `AS-node` are not modeled by the event table — they render as `—`.
Keep handoff notes in the worker trace or `steal --reason`.
