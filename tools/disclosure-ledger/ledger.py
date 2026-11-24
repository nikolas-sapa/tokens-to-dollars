#!/usr/bin/env python3
"""SHA commitment ledger for our own disclosures (Anthropic CVD-ledger pattern).

Each `commit` stores sha256(finding_body) + metadata -- never the body -- as a
hash-chained JSONL entry, so the ledger proves what we knew and when without
leaking the finding. `withdraw` appends a withdrawal record that strikes the
target commit (the entry stays, status changes), matching Anthropic's
struck-through disclosure ledger. Stdlib only, Python 3.9+.

Entry chain: hash = sha256( prev_hash_raw_bytes || canonical_json(entry minus
hash) ). Canonical json: json.dumps(sort_keys=True, separators=(",",":")).
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_LEDGER = Path(__file__).resolve().parents[2] / "memory" / "disclosure-ledger.jsonl"
GENESIS = "sha256:" + hashlib.sha256(b"disclosure-ledger-genesis-v1").hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(entry, prev_hash):
    return "sha256:" + hashlib.sha256(
        bytes.fromhex(prev_hash.split(":", 1)[1]) + canon(entry)).hexdigest()


def now_ts():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def read_entries(path):
    entries = []
    if not Path(path).exists():
        return entries, None
    with open(path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except ValueError as e:
                    return None, "line %d: invalid JSON (%s)" % (i, e)
    return entries, None


def append_entry(path, kind, data):
    entries, err = read_entries(path)
    if err:
        sys.exit("error: %s" % err)
    prev = entries[-1]["hash"] if entries else GENESIS
    seq = entries[-1]["seq"] + 1 if entries else 0
    entry = {"v": 1, "seq": seq, "ts": now_ts(), "kind": kind,
             "data": data, "prev_hash": prev}
    entry["hash"] = digest({k: v for k, v in entry.items() if k != "hash"}, prev)
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return entry


def derive_title(body_bytes):
    try:
        text = body_bytes.decode("utf-8", errors="replace")
    except ValueError:
        return "(binary finding)"
    for line in text.splitlines():
        s = line.strip()
        if s:
            s = s.lstrip("#").strip()
            return s[:80] + ("..." if len(s) > 80 else "")
    return "(untitled finding)"


def withdrawn_seqs(entries):
    return {e["data"].get("commit_seq") for e in entries
            if e.get("kind") == "withdrawal"}


def commit(path, program, finding, title, severity):
    if finding == "-":
        body = sys.stdin.buffer.read()
    else:
        src = Path(finding)
        if not src.is_file():
            sys.exit("error: finding not found: %s" % finding)
        body = src.read_bytes()
    if not body:
        sys.exit("error: empty finding body")
    data = {"program": program,
            "sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
            "bytes": len(body),
            "title": title or derive_title(body)}
    if severity:
        data["severity"] = severity
    entry = append_entry(path, "commit", data)
    print(json.dumps(entry))
    return 0


def list_entries(path, program):
    entries, err = read_entries(path)
    if err:
        sys.exit("error: %s" % err)
    struck = withdrawn_seqs(entries)
    rows = [e for e in entries if e.get("kind") == "commit"]
    if program:
        rows = [e for e in rows
                if (e["data"].get("program") or "").lower() == program.lower()]
    if not rows:
        print("no commits%s" % (" for program %s" % program if program else ""))
        return 0
    print("%-4s  %-10s  %-24s  %-10s  %s" % ("seq", "hash", "ts", "status", "title"))
    for e in rows:
        d = e["data"]
        status = "withdrawn" if e["seq"] in struck else "committed"
        print("%-4d  %-10s  %-24s  %-10s  %s"
              % (e["seq"], d.get("sha256", "?")[:16], e.get("ts", "?"),
                 status, d.get("title") or "-"))
    return 0


def withdraw(path, seq, reason):
    entries, err = read_entries(path)
    if err:
        sys.exit("error: %s" % err)
    target = next((e for e in entries if e.get("seq") == seq), None)
    if target is None:
        sys.exit("error: no entry with seq %d" % seq)
    if target.get("kind") != "commit":
        sys.exit("error: seq %d is a %s entry, not a commit" % (seq, target["kind"]))
    if seq in withdrawn_seqs(entries):
        sys.exit("error: seq %d already withdrawn" % seq)
    entry = append_entry(path, "withdrawal",
                         {"commit_seq": seq, "reason": reason})
    print(json.dumps(entry))
    return 0


def verify(path):
    entries, err = read_entries(path)
    if err:
        print("FAIL %s" % err)
        return 1
    if not entries:
        print("FAIL empty ledger")
        return 1
    prev = GENESIS
    commits = set()
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            print("FAIL seq %d: expected seq %d" % (e.get("seq", -1), i))
            return 1
        if e.get("prev_hash") != prev:
            print("FAIL seq %d: prev_hash mismatch" % i)
            return 1
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("hash") != digest(body, e["prev_hash"]):
            print("FAIL seq %d: entry hash mismatch" % i)
            return 1
        if e.get("kind") == "commit":
            commits.add(i)
        elif e.get("kind") == "withdrawal":
            tgt = (e.get("data") or {}).get("commit_seq")
            if tgt not in commits:
                print("FAIL seq %d: withdrawal targets non-commit %s" % (i, tgt))
                return 1
        else:
            print("FAIL seq %d: unknown kind %r" % (i, e.get("kind")))
            return 1
        prev = e["hash"]
    n_wd = sum(1 for e in entries if e.get("kind") == "withdrawal")
    print("OK n=%d tip=%s commits=%d withdrawn=%d"
          % (len(entries), entries[-1]["hash"][:19], len(commits), n_wd))
    return 0


def publish(path, seq):
    entries, err = read_entries(path)
    if err:
        sys.exit("error: %s" % err)
    target = next((e for e in entries if e.get("seq") == seq), None)
    if target is None:
        sys.exit("error: no entry with seq %d" % seq)
    if target.get("kind") != "commit":
        sys.exit("error: seq %d is a %s entry, not a commit" % (seq, target["kind"]))
    d = target["data"]
    att = {"seq": seq, "sha256": d["sha256"], "ts": target["ts"],
           "program": d["program"],
           "statement": "finding hash committed at %s" % target["ts"]}
    if seq in withdrawn_seqs(entries):
        att["status"] = "withdrawn"
    print(json.dumps(att))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER),
                    help="ledger path (default %(default)s)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("commit", help="commit a finding body hash + metadata")
    c.add_argument("--program", required=True, help="program handle/name")
    c.add_argument("--finding", required=True,
                   help="finding/report file path, or - for stdin")
    c.add_argument("--title", default=None, help="short title (default: derived)")
    c.add_argument("--severity", default=None, help="severity label")
    l = sub.add_parser("list", help="print ledger entries")
    l.add_argument("--program", default=None, help="filter to one program")
    w = sub.add_parser("withdraw", help="mark a commit withdrawn (struck-through)")
    w.add_argument("--seq", type=int, required=True, help="commit entry seq")
    w.add_argument("--reason", required=True, help="withdrawal reason")
    v = sub.add_parser("verify", help="walk the chain, exit 0 ok / 1 broken")
    p = sub.add_parser("publish", help="emit a public-safe attestation line")
    p.add_argument("--seq", type=int, required=True, help="commit entry seq")
    args = ap.parse_args()

    if args.cmd == "commit":
        return commit(args.ledger, args.program, args.finding,
                      args.title, args.severity)
    if args.cmd == "list":
        return list_entries(args.ledger, args.program)
    if args.cmd == "withdraw":
        return withdraw(args.ledger, args.seq, args.reason)
    if args.cmd == "verify":
        return verify(args.ledger)
    if args.cmd == "publish":
        return publish(args.ledger, args.seq)
    return 2


if __name__ == "__main__":
    sys.exit(main())
