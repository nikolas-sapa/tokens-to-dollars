#!/usr/bin/env python3
import argparse
import json
import math
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path

DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
NODE_RE = re.compile(r"\[([A-Z]{1,4}-\d+)\]")
Y_RE = re.compile(r"\[Y-\d+\].*?→\s*(?:technique\s*)?\(?([A-Za-z0-9_.\-]+)\)?\s*→\s*outcome:\s*([A-Za-z\-]+)")
SPENT_RE = re.compile(r"intents spent:\s*(\d+)")
CTX_RE = re.compile(r"\bctx:\s*([A-Za-z0-9_.\-]+)")
PRIOR_ALPHA, PRIOR_BETA = 0.5, 9.5
HALF_LIFE_DAYS = 180.0
LCB90_Z = 1.645
YIELD_HEAD = """# lessons/technique-yield - yield ledger: (technique, ctx) scored by decayed Beta-Bernoulli posterior
# Regenerated deterministically by tools/memory-consolidate/consolidate.py from [Y-n] records.
# LCB90 = posterior mean - 1.645*std, prior Beta(0.5, 9.5), decay half-life 180d. Sorted by LCB90.
# Anything under a `## manual notes` heading below survives regeneration.

| technique | ctx | LCB90 | mean | records | finding | fact-only | FP | blocked | intents spent |
|---|---|---|---|---|---|---|---|---|---|
"""
OUTCOMES = ("finding", "fact-only", "FP", "blocked")

# Bounded index rendering: a section never grows past its cap, and a
# truncated list always carries its TOTAL count — "not shown" must never
# read as "doesn't exist" to the planner. facts/findings/intents/hints
# are the proven bounds; files/lessons/targets ride the same scale.
SECTION_CAPS = {"facts": 20, "findings": 10, "intents": 30, "hints": 6,
                "files": 20, "lessons": 20, "targets": 30}


def bounded(rows, cap):
    """Emit at most `cap` rows; on truncation append a total-count marker."""
    if len(rows) <= cap:
        return rows
    return rows[:cap] + ["# ... %d more not shown — %d total"
                         % (len(rows) - cap, len(rows))]


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


def yield_table(files, today):
    """Aggregate [Y-n] records per (technique, ctx): outcome counts, intents
    spent, and decay-weighted hits/trials. A blocked intent never ran the
    technique, so it counts toward cost but not as a posterior trial."""
    agg = {}
    for p in files:
        for ln in p.read_text().splitlines():
            m = Y_RE.search(ln)
            if not m:
                continue
            cm = CTX_RE.search(ln)
            key = (m.group(1), cm.group(1) if cm else "general")
            rec = agg.setdefault(key, {"records": 0, "spent": 0, "h": 0.0, "m": 0.0})
            rec["records"] += 1
            outcome = m.group(2)
            rec[outcome] = rec.get(outcome, 0) + 1
            sm = SPENT_RE.search(ln)
            if sm:
                rec["spent"] += int(sm.group(1))
            if outcome == "blocked":
                continue
            d = line_date(ln)
            age = max((today - date.fromisoformat(d)).days, 0) if d else 0
            w = 2 ** (-age / HALF_LIFE_DAYS)
            rec["h" if outcome == "finding" else "m"] += w
    return agg


def score_rows(agg):
    """Beta posterior over decayed counts; score = mean - 1.645*std (LCB90)."""
    rows = []
    for (tech, ctx), a in agg.items():
        alpha, beta = PRIOR_ALPHA + a["h"], PRIOR_BETA + a["m"]
        mean = alpha / (alpha + beta)
        std = math.sqrt(alpha * beta / ((alpha + beta) ** 2 * (alpha + beta + 1)))
        row = dict(a)
        row.update({"technique": tech, "ctx": ctx,
                    "mean": mean, "LCB90": mean - LCB90_Z * std})
        rows.append(row)
    rows.sort(key=lambda r: (-r["LCB90"], r["technique"], r["ctx"]))
    return rows


def render_yield(rows, old_text=None):
    out = [YIELD_HEAD.rstrip("\n")]
    for r in rows:
        out.append("| %s | %s | %.3f | %.3f | %d | %d | %d | %d | %d | %d |"
                   % (r["technique"], r["ctx"], r["LCB90"], r["mean"], r["records"],
                      r.get("finding", 0), r.get("fact-only", 0), r.get("FP", 0),
                      r.get("blocked", 0), r["spent"]))
    if not rows:
        out.append("| — | - | - | - | 0 | 0 | 0 | 0 | 0 | 0 |")
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
    rows = ["| %s | %s | %s | %s |" % tuple(r) for r in data]
    out += bounded(rows, SECTION_CAPS["files"]) or ["| - | - | - | - |"]
    return "\n".join(out) + "\n", len(all_nodes), latest or "-"


def root_index(mem, per_target):
    out = ["# memory index",
           "# regenerated by tools/memory-consolidate/consolidate.py — do not hand-edit rows",
           "", "## lessons"]
    ldir = mem / "lessons"
    if ldir.is_dir():
        out += bounded(["- %s — %s" % (p.name, one_liner(p.read_text()))
                        for p in sorted(ldir.glob("*.md"))],
                       SECTION_CAPS["lessons"])
    out += ["", "## targets", "", "| target | files | nodes | latest-activity | index |",
            "|---|---|---|---|---|"]
    rows = ["| %s | %d | %d | %s | targets/%s/index.md |" % (t, n_files, n_nodes, latest, t)
            for t, (n_files, n_nodes, latest) in sorted(per_target.items())]
    out += bounded(rows, SECTION_CAPS["targets"]) or ["| - | 0 | 0 | - | - |"]
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

    agg = yield_table(files, date.today())
    rows = score_rows(agg)
    ypath = mem / "lessons" / "technique-yield.md"
    old = ypath.read_text() if ypath.is_file() else None
    report["writes"][str(ypath)] = write_if_changed(ypath, render_yield(rows, old), args.dry_run)
    report["technique_yield"] = [
        {k: round(v, 4) if isinstance(v, float) else v for k, v in r.items()}
        for r in rows]

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
