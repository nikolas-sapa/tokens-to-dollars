#!/usr/bin/env python3
"""Hash-chained append-only audit log. If it isn't recorded, it didn't happen.

Entry chain: hash = sha256( prev_hash_raw_bytes || canonical_json(entry minus hash) ).
Canonical json: json.dumps(sort_keys=True, separators=(",",":")). Every
CHECKPOINT_EVERY non-checkpoint entries a kind:"checkpoint" entry is appended
carrying the Merkle root of that segment's entry hashes. Large payloads go to
sidecar files under payloads/ next to the log; the entry stores their sha256
so tampering with either half is detectable. Stdlib only.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

CHECKPOINT_EVERY = 25
KINDS = ("intent", "fact", "finding", "dispatch", "settle")
GENESIS = "sha256:" + hashlib.sha256(b"eval-audit-genesis-v1").hexdigest()


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def digest(entry, prev_hash):
    return "sha256:" + hashlib.sha256(
        bytes.fromhex(prev_hash.split(":", 1)[1]) + canon(entry)).hexdigest()


def merkle_root(hex_hashes):
    level = [bytes.fromhex(h.split(":", 1)[1]) for h in hex_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return "sha256:" + (level[0].hex() if level else hashlib.sha256(b"").hexdigest())


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


def payloads_dir(path):
    return Path(path).resolve().parent / "payloads"


def append(path, kind, data, sidecar):
    entries, err = read_entries(path)
    if err:
        sys.exit("error: %s" % err)
    prev = entries[-1]["hash"] if entries else GENESIS
    seq = entries[-1]["seq"] + 1 if entries else 0
    entry = {"v": 1, "seq": seq, "ts": now_ts(), "kind": kind}
    if sidecar:
        src = Path(sidecar)
        if not src.is_file():
            sys.exit("error: sidecar not found: %s" % sidecar)
        blob = src.read_bytes()
        pdir = payloads_dir(path)
        pdir.mkdir(parents=True, exist_ok=True)
        name = "%06d-%s%s" % (seq, hashlib.sha256(blob).hexdigest()[:12], src.suffix)
        (pdir / name).write_bytes(blob)
        entry["sidecar"] = {"path": "payloads/%s" % name,
                            "sha256": "sha256:" + hashlib.sha256(blob).hexdigest(),
                            "bytes": len(blob)}
    if data is not None:
        entry["data"] = data
    if not sidecar and data is None:
        entry["data"] = {}
    entry["prev_hash"] = prev
    entry["hash"] = digest({k: v for k, v in entry.items() if k != "hash"}, prev)

    seg = [e["hash"] for e in entries if e["kind"] != "checkpoint"] + [entry["hash"]]
    lines = [entry]
    if len(seg) % CHECKPOINT_EVERY == 0:
        root = merkle_root(seg[-CHECKPOINT_EVERY:])
        cp = {"v": 1, "seq": seq + 1, "ts": now_ts(), "kind": "checkpoint",
              "data": {"root": root, "segment": [seq - CHECKPOINT_EVERY + 1, seq],
                       "count": CHECKPOINT_EVERY},
              "prev_hash": entry["hash"]}
        cp["hash"] = digest(cp, cp["prev_hash"])
        lines.append(cp)

    with open(path, "a", encoding="utf-8") as f:
        for e in lines:
            f.write(json.dumps(e, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())
    for e in lines:
        print(json.dumps(e))


def verify(path, quiet=False):
    entries, err = read_entries(path)
    if err:
        return False, err
    if not entries:
        return False, "empty log"
    pdir = payloads_dir(path)
    prev = GENESIS
    checkpoints = 0
    for i, e in enumerate(entries):
        if e.get("seq") != i:
            return False, "seq %d: expected seq %d" % (e.get("seq", -1), i)
        if e.get("prev_hash") != prev:
            return False, "seq %d: prev_hash mismatch" % i
        body = {k: v for k, v in e.items() if k != "hash"}
        if e.get("hash") != digest(body, e["prev_hash"]):
            return False, "seq %d: entry hash mismatch" % i
        sc = e.get("sidecar")
        if sc:
            f = pdir / Path(sc["path"]).name
            if not f.is_file():
                return False, "seq %d: sidecar missing %s" % (i, sc["path"])
            if "sha256:" + hashlib.sha256(f.read_bytes()).hexdigest() != sc["sha256"]:
                return False, "seq %d: sidecar hash mismatch %s" % (i, sc["path"])
        if e.get("kind") == "checkpoint":
            checkpoints += 1
            d = e.get("data") or {}
            lo, hi = (d.get("segment") or [None, None])
            if lo is None or hi is None or lo < 0 or hi >= i:
                return False, "seq %d: bad checkpoint segment" % i
            seg = [entries[j]["hash"] for j in range(lo, hi + 1)
                   if entries[j].get("kind") != "checkpoint"]
            if len(seg) != d.get("count") or merkle_root(seg) != d.get("root"):
                return False, "seq %d: checkpoint root mismatch" % i
        prev = e["hash"]
    if not quiet:
        print("OK n=%d tip=%s checkpoints=%d"
              % (len(entries), entries[-1]["hash"][:19], checkpoints))
    return True, None


def merkle(path):
    entries, err = read_entries(path)
    if err:
        sys.exit("FAIL %s" % err)
    cps = [e for e in entries if e.get("kind") == "checkpoint"]
    bad = 0
    for e in cps:
        d = e["data"]
        lo, hi = d["segment"]
        seg = [x["hash"] for x in entries[lo:hi + 1] if x.get("kind") != "checkpoint"]
        root = merkle_root(seg)
        ok = root == d["root"] and len(seg) == d["count"]
        bad += not ok
        print("seq=%d segment=[%d,%d] root=%s %s"
              % (e["seq"], lo, hi, root, "OK" if ok else "BAD"))
    if cps:
        print("latest root: %s" % cps[-1]["data"]["root"])
    else:
        print("no checkpoints (< %d entries)" % CHECKPOINT_EVERY)
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("append", help="append an entry")
    a.add_argument("log", help="log .jsonl path")
    a.add_argument("--kind", required=True, choices=KINDS)
    a.add_argument("--data", default=None, help="JSON payload")
    a.add_argument("--sidecar", default=None, help="file to store as payload sidecar")
    v = sub.add_parser("verify", help="walk the chain, report first break or OK")
    v.add_argument("log")
    m = sub.add_parser("merkle", help="print + re-verify checkpoint roots")
    m.add_argument("log")
    args = ap.parse_args()

    if args.cmd == "append":
        data = None
        if args.data is not None:
            try:
                data = json.loads(args.data)
            except ValueError as e:
                sys.exit("error: --data is not JSON: %s" % e)
        append(args.log, args.kind, data, args.sidecar)
        return 0
    if args.cmd == "verify":
        ok, why = verify(args.log)
        if not ok:
            print("FAIL %s" % why)
            return 1
        return 0
    if args.cmd == "merkle":
        return merkle(args.log)
    return 2


if __name__ == "__main__":
    sys.exit(main())
