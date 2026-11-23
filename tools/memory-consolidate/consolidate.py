#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
NODE_RE = re.compile(r"\[([A-Z]{1,4}-\d+)\]")
Y_RE = re.compile(r"\[Y-\d+\].*?→\s*(?:technique\s*)?\(?([A-Za-z0-9_.\-]+)\)?\s*→\s*outcome:\s*([A-Za-z\-]+)")
SPENT_RE = re.compile(r"intents spent:\s*(\d+)")
YIELD_HEAD = """# lessons/technique-yield - yield ledger: playbook ids and check categories, ranked
# Regenerated deterministically by tools/memory-consolidate/consolidate.py from [Y-n] records.
# Anything under a `## manual notes` heading below survives regeneration.

| technique | records | finding | fact-only | FP | blocked | intents spent |
|---|---|---|---|---|---|---|
"""
OUTCOMES = ("finding", "fact-only", "FP", "blocked")


def lesson_files(root):
    mem = Path(root) / "memory"
    files = sorted((mem / "lessons").glob("*.md")) if (mem / "lessons").is_dir() else []
    tdir = mem / "targets"
    if tdir.is_dir():
        files += sorted(tdir.glob("*/lessons.md"))
    return files


def tokens(text):
    t = re.sub(r"~~", " ", text)
    t = DATE_RE.sub(" ", t)
    t = NODE_RE.sub(" ", t)
    return set(re.findall(r"[a-z0-9]+", t.lower()))


def norm_key(tok):
    return " ".join(sorted(tok))


def jaccard(a, b):
    u = a | b
    return len(a & b) / len(u) if u else 0.0


def line_date(text):
    m = DATE_RE.search(text)
    return m.group(0) if m else ""


def one_liner(text):
    for ln in text.splitlines():
        s = ln.strip()
        if s.startswith("# "):
            return s[2:].strip()[:80]
    for ln in text.splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            return s[:80]
    return "-"


def merge_file(path, today):
    """Strike near-duplicate live bullet lines (Jaccard > 0.8); newest dated wins,
    latest file position breaks ties. Struck lines are history — never re-touched."""
    lines = path.read_text().splitlines()
    live = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s.startswith("- ") or "~~" in s:
            continue
        tok = tokens(s)
        if len(tok) >= 3:
            live.append({"i": i, "tok": tok, "date": line_date(s)})
    parent = list(range(len(live)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for x in range(len(live)):
        for y in range(x + 1, len(live)):
            if jaccard(live[x]["tok"], live[y]["tok"]) > 0.8:
                parent[find(x)] = find(y)
    clusters = defaultdict(list)
    for i, it in enumerate(live):
        clusters[find(i)].append(it)
    struck = []
    for cl in clusters.values():
        if len(cl) < 2:
            continue
        winner = max(cl, key=lambda it: (it["date"], it["i"]))
        for it in cl:
            if it is winner:
                continue
            orig = lines[it["i"]]
            body = orig.lstrip()[2:].strip()
            lines[it["i"]] = "- ~~%s~~ (merged: duplicate, %s)" % (body, today)
            struck.append(orig.strip())
    return "\n".join(lines) + "\n", struck


def contradictions(files):
    claims = {}
    for p in files:
        for n, ln in enumerate(p.read_text().splitlines(), 1):
            s = ln.strip()
            if not s.startswith("- "):
                continue
            tok = tokens(s)
            if len(tok) < 3:
                continue
            rec = claims.setdefault(norm_key(tok), {"live": [], "struck": []})
            rec["struck" if "~~" in s else "live"].append("%s:%d" % (p, n))
    return [{"claim": k, "live": v["live"], "struck": v["struck"]}
            for k, v in sorted(claims.items()) if v["live"] and v["struck"]]


def yield_table(files):
    agg = defaultdict(lambda: {"records": 0, "spent": 0})
    for p in files:
        for ln in p.read_text().splitlines():
            m = Y_RE.search(ln)
            if not m:
                continue
            rec = agg[m.group(1)]
            rec["records"] += 1
            rec[m.group(2)] = rec.get(m.group(2), 0) + 1
            sm = SPENT_RE.search(ln)
            if sm:
                rec["spent"] += int(sm.group(1))
    return dict(agg)


def render_yield(agg, old_text=None):
    out = [YIELD_HEAD.rstrip("\n")]
    order = sorted(agg, key=lambda t: (-agg[t].get("finding", 0), -agg[t]["records"], t))
    for t in order:
        a = agg[t]
        out.append("| %s | %d | %d | %d | %d | %d | %d |"
                   % (t, a["records"], a.get("finding", 0), a.get("fact-only", 0),
                      a.get("FP", 0), a.get("blocked", 0), a["spent"]))
    if not order:
        out.append("| — | 0 | 0 | 0 | 0 | 0 | 0 |")
    if old_text:
        lines = old_text.splitlines()
        for i, ln in enumerate(lines):
            if ln.strip().lower() == "## manual notes":
                out += [""] + lines[i:]
                break
    return "\n".join(out) + "\n"


def target_index(tdir):
    data, all_nodes, latest = [], set(), ""
    for p in sorted(tdir.glob("*.md")):
        if p.name == "index.md":
            continue
        text = p.read_text()
        nodes = sorted(set(NODE_RE.findall(text)))
        dates = DATE_RE.findall(text)
        d = max(dates) if dates else "-"
        latest = max(latest, d)
        all_nodes.update(nodes)
        data.append([p.name, ", ".join(nodes) or "-", d, one_liner(text)])
    out = ["# index — %s" % tdir.name,
           "# regenerated by tools/memory-consolidate/consolidate.py", "",
           "| file | nodes | latest-date | one-liner |", "|---|---|---|---|"]
    out += ["| %s | %s | %s | %s |" % tuple(r) for r in data] or ["| - | - | - | - |"]
    return "\n".join(out) + "\n", len(all_nodes), latest or "-"


def root_index(mem, per_target):
    out = ["# memory index",
           "# regenerated by tools/memory-consolidate/consolidate.py — do not hand-edit rows",
           "", "## lessons"]
    ldir = mem / "lessons"
    if ldir.is_dir():
        out += ["- %s — %s" % (p.name, one_liner(p.read_text())) for p in sorted(ldir.glob("*.md"))]
    out += ["", "## targets", "", "| target | files | nodes | latest-activity | index |",
            "|---|---|---|---|---|"]
    for t, (n_files, n_nodes, latest) in sorted(per_target.items()):
        out.append("| %s | %d | %d | %s | targets/%s/index.md |" % (t, n_files, n_nodes, latest, t))
    if not per_target:
        out.append("| - | 0 | 0 | - | - |")
    return "\n".join(out) + "\n"


def write_if_changed(path, content, dry_run):
    path = Path(path)
    if path.is_file() and path.read_text() == content:
        return "unchanged"
    if not dry_run:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return "would-write" if dry_run else "written"


def main():
    ap = argparse.ArgumentParser(
        description="Sleep-time maintenance for memory/: dedupe lessons, recompute "
                    "technique yield, flag struck-vs-live contradictions, rebuild indexes.")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]), help="repo root")
    ap.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    args = ap.parse_args()
    mem = Path(args.root) / "memory"
    files = lesson_files(args.root)
    today = date.today().isoformat()
    report = {"root": str(args.root), "dry_run": args.dry_run,
              "scanned": [str(f) for f in files], "merged": {}, "writes": {}}

    for p in files:
        new_text, struck = merge_file(p, today)
        if struck:
            report["merged"][str(p)] = struck
            report["writes"][str(p)] = write_if_changed(p, new_text, args.dry_run)

    agg = yield_table(files)
    ypath = mem / "lessons" / "technique-yield.md"
    old = ypath.read_text() if ypath.is_file() else None
    report["writes"][str(ypath)] = write_if_changed(ypath, render_yield(agg, old), args.dry_run)
    report["technique_yield"] = agg

    report["contradictions"] = contradictions(files)

    per_target = {}
    tdir = mem / "targets"
    if tdir.is_dir():
        for d in sorted(p for p in tdir.iterdir() if p.is_dir()):
            content, n_nodes, latest = target_index(d)
            n_files = len([p for p in d.glob("*.md") if p.name != "index.md"])
            per_target[d.name] = (n_files, n_nodes, latest)
            report["writes"][str(d / "index.md")] = write_if_changed(d / "index.md", content, args.dry_run)
    report["writes"][str(mem / "index.md")] = write_if_changed(
        mem / "index.md", root_index(mem, per_target), args.dry_run)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
