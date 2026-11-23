#!/usr/bin/env python3
"""Corpus flagger: annotate ingested records with injection-scan verdicts.

Ingest tools write attacker-controlled text (issue titles, program
instruction fields, writeup titles) into JSONL/JSON that hunting agents
later read. This annotates every record in place with "_untrusted"/
"_scan"/"_scan_hits", and moves hostile records to a quarantine file.
Handles .jsonl (one object/line) and .json (array or {key: [records]}).
Python 3.9+, stdlib only.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan import scan_text, verdict  # noqa: E402

FIELDS = ("title", "weakness", "instruction", "program", "name",
          "description", "url")
LIST_FIELDS = ("labels", "scam_reasons")


def texts_of(rec):
    for k in FIELDS:
        v = rec.get(k)
        if isinstance(v, str):
            yield v
    for k in LIST_FIELDS:
        for v in rec.get(k) or []:
            if isinstance(v, str):
                yield v
    for e in rec.get("out_of_scope") or []:
        if isinstance(e, dict) and isinstance(e.get("instruction"), str):
            yield e["instruction"]


def annotate(rec):
    hits = []
    for t in texts_of(rec):
        hits += scan_text(t)["hits"]
    v = verdict(hits)
    rec["_untrusted"] = True
    rec["_scan"] = v
    if v != "clean":
        rec["_scan_hits"] = list(dict.fromkeys(h["rule"] for h in hits))
    return v


def flag_records(records, quarantine, counts):
    kept = []
    for r in records:
        if not isinstance(r, dict):
            kept.append(r)
            continue
        v = annotate(r)
        counts[v] += 1
        if v == "hostile":
            quarantine.append(r)
        else:
            kept.append(r)
    return kept


def flag_jsonl(src, dst, quarantine, counts):
    out = []
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            out.append(line)  # unparseable: keep verbatim, not a record
            continue
        if not isinstance(obj, dict):
            out.append(line)
            continue
        v = annotate(obj)
        counts[v] += 1
        if v == "hostile":
            quarantine.append(obj)
        else:
            out.append(json.dumps(obj, ensure_ascii=False))
    dst.write_text("\n".join(out) + ("\n" if out else ""))


def flag_json(src, dst, quarantine, counts):
    data = json.loads(src.read_text(encoding="utf-8"))
    if isinstance(data, list):
        data = flag_records(data, quarantine, counts)
    elif isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list):
                data[k] = flag_records(v, quarantine, counts)
    dst.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def main():
    ap = argparse.ArgumentParser(
        description="Annotate corpus records with content-scan verdicts; "
                    "hostile records move to <file>.quarantine.jsonl.")
    ap.add_argument("--file", default=None, help="annotate this file in place")
    ap.add_argument("--in", dest="in_path", default=None, help="input path")
    ap.add_argument("--out", dest="out_path", default=None, help="output path")
    args = ap.parse_args()

    if args.file:
        src = dst = Path(args.file)
    elif args.in_path and args.out_path:
        src, dst = Path(args.in_path), Path(args.out_path)
    else:
        ap.error("use --file PATH or --in A --out B")

    quarantine = []
    counts = {"clean": 0, "suspicious": 0, "hostile": 0}
    if str(src).endswith(".jsonl"):
        flag_jsonl(src, dst, quarantine, counts)
    else:
        flag_json(src, dst, quarantine, counts)

    qpath = str(dst) + ".quarantine.jsonl"
    if quarantine:
        with open(qpath, "a") as f:
            for r in quarantine:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")

    total = sum(counts.values())
    print("flagged %d records: %d clean, %d suspicious, %d hostile -> %s"
          % (total, counts["clean"], counts["suspicious"],
             counts["hostile"], qpath if quarantine else "(none)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
