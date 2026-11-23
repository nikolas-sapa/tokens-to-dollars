#!/usr/bin/env python3
"""Mechanical fact verification — grounds claims in raw traces, not judgment.

Default mode: parse a facts markdown file for [F-n]/[FD-n] nodes, extract
each node's asserted payload(s) — a `payload:`/`quote:` field or inline
backtick/quoted spans — and grep the raw worker trace. Any payload absent
verbatim => verdict "soliloquy" (claim not grounded in observed output).

--verbatim mode (BaaRai POE invariant): scan finding/receipt files for JSON
objects carrying quotes[] plus body/file refs; every quote must appear
verbatim in a referenced stored body, else the missing quote is named.

Python 3.9+, stdlib only. Emits JSONL verdicts; exit 1 on any failure.
"""
import argparse
import json
import re
import sys
from pathlib import Path

NODE_RE = re.compile(r"\[(FD?-\d+)\]")
FIELD_RE = re.compile(r"(?:payload|quote)\s*[:=]\s*(`[^`]+`|\"[^\"\n]+\"|'[^'\n]+'|[^—\n]+)", re.I)
SPAN_RE = re.compile(r"`([^`\n]+)`|\"([^\"\n]+)\"|'([^'\n]+)'")


def read_text(path):
    return Path(path).read_text(encoding="utf-8", errors="replace")


def trace_corpus(path):
    p = Path(path)
    if p.is_dir():
        return "\n".join(read_text(f) for f in sorted(p.rglob("*"))
                         if f.is_file() and not f.name.startswith("."))
    return read_text(p)


def payloads(line):
    m = FIELD_RE.search(line)
    if m:
        return [m.group(1).strip("`'\" \t")]
    return [s for tup in SPAN_RE.findall(line) for s in tup if s.strip()]


def verify_facts(path, corpus):
    out = []
    for line in read_text(path).splitlines():
        m = NODE_RE.search(line)
        if not m or not line.lstrip().startswith("-"):
            continue
        pl = [p for p in payloads(line) if p]
        if not pl:
            out.append({"node": m.group(1), "verdict": "no-payload"})
            continue
        missing = [p for p in pl if p not in corpus]
        rec = {"node": m.group(1), "payloads": len(pl)}
        if missing:
            rec.update(verdict="soliloquy", missing=missing)
        else:
            rec["verdict"] = "grounded"
        out.append(rec)
    return out


def json_objects(text):
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, list) else [obj]
    except ValueError:
        pass
    objs, depth, start, instr, esc = [], 0, -1, False, False
    for i, ch in enumerate(text):
        if instr:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                instr = False
            continue
        if ch == '"':
            instr = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    objs.append(json.loads(text[start:i + 1]))
                except ValueError:
                    pass
    return objs


def receipt_quotes(receipt):
    out = []
    for q in receipt.get("quotes") or []:
        if isinstance(q, str):
            out.append(q)
        elif isinstance(q, dict):
            out.append(q.get("quote") or q.get("text") or "")
    return [q for q in out if q]


def receipt_bodies(receipt, base):
    refs = [receipt.get(k) for k in ("body", "file", "path", "body_file")]
    refs += [a.get("path") for a in receipt.get("artifacts") or []
             if isinstance(a, dict)]
    out = []
    for r in [r for r in refs if isinstance(r, str)]:
        p = Path(r) if Path(r).is_absolute() else (base / r)
        if not p.is_file():
            p = Path(r)
        if p.is_file():
            out.append((r, read_text(p)))
    return out


def verify_verbatim(path):
    files = sorted([f for f in path.rglob("*")
                    if f.suffix in (".md", ".json")]) if path.is_dir() else [path]
    out = []
    for f in files:
        for i, rec in enumerate(o for o in json_objects(read_text(f))
                                if isinstance(o, dict) and o.get("quotes")):
            bodies = receipt_bodies(rec, f.parent)
            quotes = receipt_quotes(rec)
            missing = [q for q in quotes if all(q not in b for _, b in bodies)]
            out.append({"file": f.name, "receipt": rec.get("findingId", i),
                        "quotes": len(quotes),
                        "bodies": [r for r, _ in bodies],
                        "verdict": "missing-quote" if missing else "poe-verified",
                        **({"missing": missing} if missing else {})})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--facts", required=True,
                    help="facts markdown (or finding/receipt files with --verbatim)")
    ap.add_argument("--trace", help="worker trace file or directory")
    ap.add_argument("--verbatim", action="store_true",
                    help="POE mode: receipt quotes[] vs referenced bodies")
    ap.add_argument("--summary", action="store_true",
                    help="print verdict counts to stderr")
    a = ap.parse_args()
    if a.verbatim:
        verdicts = verify_verbatim(Path(a.facts))
        ok = "poe-verified"
    else:
        if not a.trace:
            ap.error("--trace required unless --verbatim")
        verdicts = verify_facts(Path(a.facts), trace_corpus(a.trace))
        ok = "grounded"
    for v in verdicts:
        print(json.dumps(v, ensure_ascii=False))
    if a.summary:
        counts = {}
        for v in verdicts:
            counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
        print("summary: " + json.dumps(counts, sort_keys=True), file=sys.stderr)
    sys.exit(1 if any(v["verdict"] != ok for v in verdicts) else 0)


if __name__ == "__main__":
    main()
