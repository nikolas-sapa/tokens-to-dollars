#!/usr/bin/env python3
import argparse
import getpass
import json
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  target     TEXT NOT NULL,
  surface    TEXT NOT NULL,
  worker     TEXT NOT NULL,
  state      TEXT NOT NULL CHECK (state IN ('CLAIM','HEARTBEAT','RELEASE','STEAL')),
  ts         TEXT NOT NULL,
  status     TEXT,
  techniques TEXT,
  reason     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (target, surface, id);
"""
COLS = "id,target,surface,worker,state,ts,status,techniques,reason"


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(ts):
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def default_worker():
    return os.environ.get("COVERAGE_WORKER") or getpass.getuser()


def connect(root):
    db = Path(root) / "memory" / "coverage.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(2):
        conn = None
        try:
            conn = sqlite3.connect(str(db), timeout=10)
            conn.isolation_level = None
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            return conn
        except sqlite3.OperationalError as e:
            if conn is not None:
                conn.close()
            if attempt:
                sys.exit("error: cannot initialize coverage ledger %s: %s" % (db, e))
            time.sleep(0.1)


def rows(conn, where="", params=()):
    cur = conn.execute("SELECT %s FROM events %s ORDER BY id" % (COLS, where), params)
    return [dict(zip(COLS.split(","), r)) for r in cur]


def insert(conn, target, surface, worker, state, status=None, techniques=None, reason=None):
    cur = conn.execute(
        "INSERT INTO events (target,surface,worker,state,ts,status,techniques,reason)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (target, surface, worker, state, utcnow(), status, techniques, reason))
    return {"id": cur.lastrowid, "target": target, "surface": surface, "worker": worker,
            "state": state, "status": status, "techniques": techniques, "reason": reason}


def surface_state(events, window, now=None):
    """Fold a surface's id-ordered events into the derived claim state.

    Last event wins; writes by non-holders are ignored (fenced semantics):
    a HEARTBEAT or RELEASE from anyone but the current holder is a no-op.
    """
    now = now or datetime.now(timezone.utc)
    holder = last_activity = techniques = None
    status = "untouched"
    for ev in events:
        w, st = ev["worker"], ev["state"]
        if st == "CLAIM":
            holder, last_activity, status = w, ev["ts"], "in-progress"
        elif st == "HEARTBEAT" and w == holder:
            last_activity = ev["ts"]
        elif st == "RELEASE" and w == holder:
            status = ev["status"] or "exhausted"
            techniques = ev["techniques"] or techniques
            holder = last_activity = None
        elif st == "STEAL":
            holder = last_activity = None
            status = "untouched"
    stale = bool(holder) and (now - parse_ts(last_activity)) > timedelta(minutes=window)
    return {"holder": holder, "status": status, "techniques": techniques,
            "last_activity": last_activity, "open": bool(holder), "stale": stale}


def state_for(conn, target, surface, window):
    return surface_state(rows(conn, "WHERE target=? AND surface=?", (target, surface)), window)


def do_claim(conn, a):
    worker = a.worker or default_worker()
    conn.execute("BEGIN IMMEDIATE")
    st = state_for(conn, a.target, a.surface, a.window_minutes)
    if st["open"] and not st["stale"]:
        conn.execute("ROLLBACK")
        sys.exit("error: %s is held by %s (last activity %s) — pick another surface or wait out the window"
                 % (a.surface, st["holder"], st["last_activity"]))
    out = {"ok": True}
    if st["open"]:  # stale: markdown semantics settle it through the STEAL path
        out["stole_from"] = st["holder"]
        insert(conn, a.target, a.surface, worker, "STEAL",
               reason="auto: stale claim (> %d min)" % a.window_minutes)
    out["event"] = insert(conn, a.target, a.surface, worker, "CLAIM")
    conn.execute("COMMIT")
    print(json.dumps(out))


def do_heartbeat(conn, a):
    conn.execute("BEGIN IMMEDIATE")
    st = state_for(conn, a.target, a.surface, a.window_minutes)
    if not st["open"]:
        conn.execute("ROLLBACK")
        sys.exit("error: no open claim on %s — nothing to heartbeat" % a.surface)
    # no --worker means "the current caller", never the holder — otherwise
    # the fencing check below can never fire and anyone can heartbeat
    # someone else's claim under their name
    worker = a.worker or default_worker()
    if worker != st["holder"]:
        conn.execute("ROLLBACK")
        sys.exit("error: %s does not hold %s (holder: %s) — fenced workers cannot write"
                 % (worker, a.surface, st["holder"]))
    ev = insert(conn, a.target, a.surface, worker, "HEARTBEAT")
    conn.execute("COMMIT")
    print(json.dumps({"ok": True, "event": ev, "revived_stale": st["stale"]}))


def do_release(conn, a):
    conn.execute("BEGIN IMMEDIATE")
    st = state_for(conn, a.target, a.surface, a.window_minutes)
    if not st["open"]:
        conn.execute("ROLLBACK")
        sys.exit("error: no open claim on %s — exactly-once settle refuses a second RELEASE" % a.surface)
    worker = a.worker or default_worker()  # caller identity, like claim/steal
    if worker != st["holder"]:
        conn.execute("ROLLBACK")
        sys.exit("error: %s does not hold %s (holder: %s) — fenced workers cannot write"
                 % (worker, a.surface, st["holder"]))
    ev = insert(conn, a.target, a.surface, worker, "RELEASE",
                status=a.status or "exhausted", techniques=a.techniques)
    conn.execute("COMMIT")
    print(json.dumps({"ok": True, "event": ev}))


def do_steal(conn, a):
    worker = a.worker or default_worker()
    conn.execute("BEGIN IMMEDIATE")
    st = state_for(conn, a.target, a.surface, a.window_minutes)
    if not st["open"]:
        conn.execute("ROLLBACK")
        sys.exit("error: no open claim on %s — nothing to steal" % a.surface)
    if not st["stale"]:
        conn.execute("ROLLBACK")
        sys.exit("error: claim by %s is live (activity %s) — STEAL is for the dead, not the slow"
                 % (st["holder"], st["last_activity"]))
    s_ev = insert(conn, a.target, a.surface, worker, "STEAL", reason=a.reason)
    c_ev = insert(conn, a.target, a.surface, worker, "CLAIM")
    conn.execute("COMMIT")
    print(json.dumps({"ok": True, "stole_from": st["holder"], "events": [s_ev, c_ev]}))


def surfaces_for(conn, target):
    grouped, order = {}, []
    for ev in rows(conn, "WHERE target=?", (target,)):
        if ev["surface"] not in grouped:
            grouped[ev["surface"]] = []
            order.append(ev["surface"])
        grouped[ev["surface"]].append(ev)
    return grouped, order


def fmt_table(headers, data):
    w = [len(h) for h in headers]
    for r in data:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(str(c)))
    out = ["  ".join(h.ljust(w[i]) for i, h in enumerate(headers)),
           "  ".join("-" * x for x in w)]
    out += ["  ".join(str(c).ljust(w[i]) for i, c in enumerate(r)) for r in data]
    return out


def do_status(conn, a):
    grouped, order = surfaces_for(conn, a.target)
    data, n_open = [], 0
    for s in order:
        st = surface_state(grouped[s], a.window_minutes)
        n_open += 1 if st["open"] else 0
        flags = ",".join(f for f in ("held" if st["open"] else "", "stale" if st["stale"] else "") if f) or "-"
        data.append([s, st["holder"] or "-", st["status"], st["techniques"] or "-",
                     st["last_activity"] or "-", flags])
    print("coverage: %s  (%d surfaces, %d open claims, window %dm)"
          % (a.target, len(order), n_open, a.window_minutes))
    print("\n".join(fmt_table(["surface", "claimed-by", "status", "techniques", "last-activity", "flags"],
                              data or [["-", "-", "-", "-", "-", "-"]])))


def do_stale(conn, a):
    window = a.minutes if a.minutes is not None else a.window_minutes
    grouped, order = {}, []
    for ev in rows(conn):
        key = (ev["target"], ev["surface"])
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(ev)
    data = []
    for (t, s) in order:
        st = surface_state(grouped[(t, s)], window)
        if st["open"] and st["stale"]:
            idle = int((datetime.now(timezone.utc) - parse_ts(st["last_activity"])).total_seconds() // 60)
            data.append([t, s, st["holder"], st["last_activity"], "%dm" % idle])
    print("stale claims (window %dm):" % window)
    print("\n".join(fmt_table(["target", "surface", "holder", "last-activity", "idle"],
                              data or [["-", "-", "-", "-", "-"]])))


def render_md(target, evs, window):
    grouped, order = {}, []
    for ev in evs:
        grouped.setdefault(ev["surface"], []).append(ev)
        if ev["surface"] not in order:
            order.append(ev["surface"])
    out = ["# Coverage — %s" % target,
           "updated: %s by ledger_store.py" % utcnow(), "",
           "| surface | claimed-by | status | technique tried | notes | AS-node |",
           "|---|---|---|---|---|---|"]
    for s in order:
        st = surface_state(grouped[s], window)
        status = st["status"] + (" (stale)" if st["stale"] else "")
        out.append("| %s | %s | %s | %s | — | — |"
                   % (s, st["holder"] or "—", status, st["techniques"] or "—"))
    out += ["", "## Log"]
    holder = {}
    for ev in evs:
        line = "%s %s %s %s" % (ev["ts"], ev["worker"], ev["state"], ev["surface"])
        if ev["state"] == "CLAIM":
            holder[ev["surface"]] = ev["worker"]
        elif ev["state"] == "RELEASE":
            line += " status=%s" % (ev["status"] or "exhausted")
            if ev["techniques"]:
                line += " techniques=%s" % ev["techniques"]
            holder.pop(ev["surface"], None)
        elif ev["state"] == "STEAL":
            line += " from %s" % holder.pop(ev["surface"], "?")
            if ev["reason"]:
                line += " — %s" % ev["reason"]
        out.append(line)
    return "\n".join(out) + "\n"


def do_export(conn, a):
    evs = rows(conn, "WHERE target=?", (a.target,))
    if a.md:
        sys.stdout.write(render_md(a.target, evs, a.window_minutes))
        return
    grouped, order = {}, []
    for ev in evs:
        grouped.setdefault(ev["surface"], []).append(ev)
        if ev["surface"] not in order:
            order.append(ev["surface"])
    print(json.dumps({
        "target": a.target, "window_minutes": a.window_minutes,
        "surfaces": {s: surface_state(grouped[s], a.window_minutes) for s in order},
        "events": evs}, indent=2))


def main():
    ap = argparse.ArgumentParser(
        description="SQLite backing store for the coverage-ledger protocol (skills/coverage-ledger).")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]),
                    help="repo root; db lives at <root>/memory/coverage.db")
    ap.add_argument("--window-minutes", type=int, default=30,
                    help="heartbeat window before a claim goes stale (default 30; manifest may override)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("claim", help="atomically claim a surface (auto-steals a stale holder)")
    p.add_argument("target"); p.add_argument("surface"); p.add_argument("--worker")
    p = sub.add_parser("heartbeat", help="holder liveness ping; revives a stale-but-unstolen claim")
    p.add_argument("target"); p.add_argument("surface"); p.add_argument("--worker")
    p = sub.add_parser("release", help="settle a claim exactly once with final status")
    p.add_argument("target"); p.add_argument("surface"); p.add_argument("--worker")
    p.add_argument("--status", default=None, help="exhausted | finding-found (default exhausted)")
    p.add_argument("--techniques", default=None, help="comma-list of distinct techniques tried")
    p = sub.add_parser("steal", help="fence a dead holder and claim in one transaction")
    p.add_argument("target"); p.add_argument("surface"); p.add_argument("--worker")
    p.add_argument("--reason", default=None)
    p = sub.add_parser("status", help="derived claim state for all surfaces of a target")
    p.add_argument("target")
    p = sub.add_parser("stale", help="list stale open claims across all targets")
    p.add_argument("--minutes", type=int, default=None, help="override --window-minutes")
    p = sub.add_parser("export", help="JSON dump, or the coverage.md format with --md")
    p.add_argument("target"); p.add_argument("--md", action="store_true")
    args = ap.parse_args()

    conn = connect(args.root)
    {"claim": do_claim, "heartbeat": do_heartbeat, "release": do_release, "steal": do_steal,
     "status": do_status, "stale": do_stale, "export": do_export}[args.cmd](conn, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
