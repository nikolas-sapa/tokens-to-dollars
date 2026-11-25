#!/usr/bin/env python3
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS budget (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  cap_micro INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
  intent_id        TEXT PRIMARY KEY,
  worst_case_micro INTEGER NOT NULL,
  actual_micro     INTEGER,
  price_in_micro   INTEGER NOT NULL,
  price_out_micro  INTEGER NOT NULL,
  state            TEXT NOT NULL CHECK (state IN ('reserved','settled')),
  created_at       TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  settled_at       TEXT,
  ttl_seconds      INTEGER NOT NULL,
  wrap_micro       INTEGER NOT NULL DEFAULT 0
);
"""


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_micro(dollars):
    """Exact dollars -> integer micro-dollars. NEVER use float() here —
    float drift breaks caps: a cap that rounds the wrong way is worse
    than no cap."""
    return int(Decimal(str(dollars)) * 1_000_000)


def nonneg_decimal(value, name):
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        sys.exit("error: %s must be a finite number >= 0" % name)
    if not d.is_finite() or d < 0:
        sys.exit("error: %s must be a finite number >= 0" % name)
    return d


def nonneg_int(value, name):
    if value < 0:
        sys.exit("error: %s must be >= 0" % name)
    return value


def worst_case_micro(est_in_tokens, max_out_tokens, price_in_micro, price_out_micro):
    """Worst-case hold: (est_in*p_in + max_out*p_out) x 1.1 buffer.

    Prices are integer micro-dollars per 1k tokens; all math integer —
    floats are forbidden anywhere in budget accounting because drift
    breaks caps.
    """
    return (est_in_tokens * price_in_micro
            + max_out_tokens * price_out_micro) * 11 // 10000


def actual_micro(actual_in, actual_out, price_in_micro, price_out_micro):
    """Realized cost at the same rates; no buffer on actuals."""
    return (actual_in * price_in_micro + actual_out * price_out_micro) // 1000


def connect(root):
    db = Path(root) / "memory" / "budget.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db), timeout=10)
    conn.isolation_level = None
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(intents)")}
    if "wrap_micro" not in cols:
        conn.execute(
            "ALTER TABLE intents ADD COLUMN wrap_micro INTEGER NOT NULL DEFAULT 0")
    return conn


def budget_state(conn):
    row = conn.execute("SELECT cap_micro FROM budget WHERE id=1").fetchone()
    cap = row["cap_micro"] if row else None
    settled = conn.execute(
        "SELECT COALESCE(SUM(actual_micro),0) AS s FROM intents WHERE state='settled'"
    ).fetchone()["s"]
    reserved = conn.execute(
        "SELECT COALESCE(SUM(worst_case_micro),0) AS s FROM intents WHERE state='reserved'"
    ).fetchone()["s"]
    wrap_held = conn.execute(
        "SELECT COALESCE(SUM(wrap_micro),0) AS s FROM intents"
    ).fetchone()["s"]
    return cap, settled, reserved, wrap_held


def sweep_expired(conn, now):
    """Release reservations past TTL (crashed workers). Caller holds the
    transaction; returns the freed rows (their wrap-up tranche frees
    with them)."""
    expired = conn.execute(
        "SELECT intent_id, worst_case_micro, wrap_micro FROM intents"
        " WHERE state='reserved' AND expires_at <= ?", (now,)).fetchall()
    conn.execute(
        "DELETE FROM intents WHERE state='reserved' AND expires_at <= ?", (now,))
    return expired


def reserve(conn, intent_id, est_in_tokens, max_out_tokens,
            price_in_micro, price_out_micro, ttl_seconds, reserve_pct=15):
    """Atomically check settled + reserved + wrap_held + worst_case +
    its wrap-up tranche <= cap and record the hold, in one locked
    section. Returns dict(ok=...): ok=True holds the budget, ok=False
    reason='insufficient' changes nothing. Retrying a live intent_id is
    a no-op returning the existing hold.

    Hierarchical budget: each hold pins an extra reserve_pct% (default
    15) as wrap_micro — the wrap-up tranche held back for the
    settlement/report phase. Settle never consumes it; only `sweep`
    releases it, so worker intents can never burn the funds the
    engagement needs to close out."""
    now = datetime.now(timezone.utc)
    conn.execute("BEGIN IMMEDIATE")
    sweep_expired(conn, utcnow())
    existing = conn.execute(
        "SELECT * FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
    if existing:
        conn.execute("COMMIT")
        return {"ok": True, "already_reserved": existing["state"] == "reserved",
                "intent_id": intent_id, "state": existing["state"],
                "worst_case_micro": existing["worst_case_micro"],
                "wrap_micro": existing["wrap_micro"]}
    cap, settled, reserved, wrap_held = budget_state(conn)
    if cap is None:
        conn.execute("ROLLBACK")
        sys.exit("error: no budget cap set — run `reserve.py cap <usd>` first")
    wc = worst_case_micro(est_in_tokens, max_out_tokens,
                          price_in_micro, price_out_micro)
    wrap = wc * int(Decimal(str(reserve_pct)) * 100) // 10000
    if settled + reserved + wrap_held + wc + wrap > cap:
        conn.execute("ROLLBACK")
        return {"ok": False, "reason": "insufficient", "intent_id": intent_id,
                "worst_case_micro": wc, "wrap_micro": wrap, "cap_micro": cap,
                "settled_micro": settled, "reserved_micro": reserved,
                "wrap_held_micro": wrap_held,
                "headroom_micro": cap - settled - reserved - wrap_held}
    conn.execute(
        "INSERT INTO intents (intent_id,worst_case_micro,price_in_micro,price_out_micro,"
        "state,created_at,expires_at,ttl_seconds,wrap_micro)"
        " VALUES (?,?,?,?,'reserved',?,?,?,?)",
        (intent_id, wc, price_in_micro, price_out_micro,
         utcnow(), (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ"),
         ttl_seconds, wrap))
    conn.execute("COMMIT")
    return {"ok": True, "intent_id": intent_id, "worst_case_micro": wc,
            "wrap_micro": wrap, "cap_micro": cap, "settled_micro": settled,
            "reserved_micro": reserved + wc,
            "wrap_held_micro": wrap_held + wrap,
            "headroom_micro": cap - settled - reserved - wrap_held - wc - wrap,
            "ttl_seconds": ttl_seconds}


def settle(conn, intent_id, actual_in, actual_out, price_in_micro=None, price_out_micro=None):
    """Replace the reservation with actual micro cost. Idempotent by
    intent_id: a second settle returns the recorded figure without
    double-counting. Unknown intents (swept holds, crashed workers) still
    record actuals — real spend must land or the cap lies — but need
    explicit prices since no reservation holds them.

    Settle never consumes wrap_micro: the wrap-up tranche stays pinned
    past settlement and is released only by `sweep` — that is what keeps
    the settlement/report phase funded."""
    conn.execute("BEGIN IMMEDIATE")
    row = conn.execute(
        "SELECT * FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
    if row and row["state"] == "settled":
        conn.execute("COMMIT")
        return {"ok": True, "already_settled": True, "intent_id": intent_id,
                "actual_micro": row["actual_micro"]}
    if row:
        p_in, p_out = row["price_in_micro"], row["price_out_micro"]
    elif price_in_micro is None or price_out_micro is None:
        conn.execute("ROLLBACK")
        sys.exit("error: no reservation for %s — pass --price-in/--price-out "
                 "to settle actuals for an unknown intent" % intent_id)
    else:
        p_in, p_out = price_in_micro, price_out_micro
    actual = actual_micro(actual_in, actual_out, p_in, p_out)
    ts = utcnow()
    if row:
        conn.execute(
            "UPDATE intents SET state='settled', actual_micro=?, settled_at=?"
            " WHERE intent_id=?", (actual, ts, intent_id))
    else:
        conn.execute(
            "INSERT INTO intents (intent_id,worst_case_micro,actual_micro,"
            "price_in_micro,price_out_micro,state,created_at,expires_at,"
            "settled_at,ttl_seconds) VALUES (?,?,?,?,?,'settled',?,?,?,0)",
            (intent_id, actual, actual, p_in, p_out, ts, ts, ts))
    conn.execute("COMMIT")
    return {"ok": True, "intent_id": intent_id, "actual_micro": actual,
            "released_micro": (row["worst_case_micro"] - actual) if row else 0,
            "wrap_held_micro": (row["wrap_micro"] or 0) if row else 0}


def do_reserve(conn, a):
    est_in = nonneg_int(a.est_in, "--est-in")
    max_out = nonneg_int(a.max_out, "--max-out")
    p_in = nonneg_decimal(a.price_in, "--price-in")
    p_out = nonneg_decimal(a.price_out, "--price-out")
    reserve_pct = nonneg_decimal(a.reserve_pct, "--reserve-pct")
    out = reserve(conn, a.intent_id, est_in, max_out,
                  to_micro(p_in), to_micro(p_out), a.ttl,
                  reserve_pct)
    print(json.dumps(out))
    return 0 if out["ok"] else 1


def do_settle(conn, a):
    actual_in = nonneg_int(a.actual_in, "--actual-in")
    actual_out = nonneg_int(a.actual_out, "--actual-out")
    p_in = (to_micro(nonneg_decimal(a.price_in, "--price-in"))
            if a.price_in is not None else None)
    p_out = (to_micro(nonneg_decimal(a.price_out, "--price-out"))
             if a.price_out is not None else None)
    print(json.dumps(settle(conn, a.intent_id, actual_in, actual_out, p_in, p_out)))
    return 0


def do_sweep(conn, a):
    """Sweep = wrap-up phase start: TTL-expired holds release AND every
    pinned wrap-up tranche frees back to the pool, funding the
    settlement/report work that follows."""
    conn.execute("BEGIN IMMEDIATE")
    expired = sweep_expired(conn, utcnow())
    freed_wrap = conn.execute(
        "SELECT COALESCE(SUM(wrap_micro),0) AS s FROM intents"
        " WHERE wrap_micro > 0").fetchone()["s"]
    conn.execute("UPDATE intents SET wrap_micro=0 WHERE wrap_micro>0")
    conn.execute("COMMIT")
    print(json.dumps({"ok": True,
                      "swept": [dict(e) for e in expired],
                      "freed_micro": sum(e["worst_case_micro"]
                                         + (e["wrap_micro"] or 0)
                                         for e in expired),
                      "freed_wrap_micro": freed_wrap}))
    return 0


def do_cap(conn, a):
    if a.amount is None:
        row = conn.execute("SELECT cap_micro FROM budget WHERE id=1").fetchone()
        print(json.dumps({"cap_micro": row["cap_micro"] if row else None}))
        return 0
    cap = to_micro(nonneg_decimal(a.amount, "cap amount"))
    conn.execute("BEGIN IMMEDIATE")
    conn.execute(
        "INSERT INTO budget (id,cap_micro) VALUES (1,?)"
        " ON CONFLICT(id) DO UPDATE SET cap_micro=excluded.cap_micro", (cap,))
    conn.execute("COMMIT")
    print(json.dumps({"ok": True, "cap_micro": cap}))
    return 0


def do_status(conn, a):
    cap, settled, reserved, wrap_held = budget_state(conn)
    holds = conn.execute(
        "SELECT intent_id, worst_case_micro, wrap_micro, created_at, expires_at"
        " FROM intents WHERE state='reserved' ORDER BY created_at").fetchall()
    print(json.dumps({
        "cap_micro": cap, "settled_micro": settled, "reserved_micro": reserved,
        "wrap_held_micro": wrap_held,
        "headroom_micro": (cap - settled - reserved - wrap_held)
        if cap is not None else None,
        "open_reservations": [dict(h) for h in holds]}))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Reserve/settle budget holds for token-ledger intents "
                    "(skills/token-ledger). Integer micro-dollars only — "
                    "float drift breaks caps. Prices are USD per 1k tokens.")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]),
                    help="repo root; db lives at <root>/memory/budget.db")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("cap", help="set (or show, no arg) the spend cap in USD")
    p.add_argument("amount", nargs="?", default=None)
    p = sub.add_parser("reserve", help="hold worst-case spend before dispatch; "
                                       "exits 1 on insufficient headroom")
    p.add_argument("intent_id")
    p.add_argument("--est-in", type=int, required=True, help="estimated input tokens")
    p.add_argument("--max-out", type=int, required=True, help="max_completion_tokens cap")
    p.add_argument("--price-in", required=True, help="USD per 1k input tokens")
    p.add_argument("--price-out", required=True, help="USD per 1k output tokens")
    p.add_argument("--ttl", type=int, default=1800,
                   help="seconds before sweep releases the hold (default 1800)")
    p.add_argument("--reserve-pct", type=float, default=15.0,
                   help="percent of the hold pinned as wrap-up reserve "
                        "for the settlement/report phase; settle never "
                        "consumes it, sweep releases it (default 15)")
    p = sub.add_parser("settle", help="replace a hold with actual cost; "
                                      "idempotent per intent-id")
    p.add_argument("intent_id")
    p.add_argument("--actual-in", type=int, required=True)
    p.add_argument("--actual-out", type=int, required=True)
    p.add_argument("--price-in", default=None,
                   help="USD per 1k in — required only for intents with no reservation")
    p.add_argument("--price-out", default=None, help="USD per 1k out")
    p = sub.add_parser("sweep", help="release TTL-expired holds from crashed "
                                     "workers and free all pinned wrap-up "
                                     "reserves (run at wrap-up phase start)")
    p = sub.add_parser("status", help="cap / settled / reserved / open holds as JSON")
    args = ap.parse_args()

    conn = connect(args.root)
    rc = {"cap": do_cap, "reserve": do_reserve, "settle": do_settle,
          "sweep": do_sweep, "status": do_status}[args.cmd](conn, args)
    conn.close()
    return rc


if __name__ == "__main__":
    sys.exit(main())
