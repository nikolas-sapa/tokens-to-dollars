#!/usr/bin/env python3
import argparse
import csv
import io
import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

log = logging.getLogger("ingest_knowledge")
UA = "tokens-to-dollars-ingest/0.1 (+https://github.com/tokens-to-dollars)"

BS_REPO = "SecurityTalent/bugskill-ai"
BS_TREE = "https://api.github.com/repos/%s/git/trees/main?recursive=1" % BS_REPO
BS_RAW = "https://raw.githubusercontent.com/%s/main/%%s" % BS_REPO
BS_FALLBACKS = ["data/reports.json", "hackerone_public_reports.json"]

AJAYSENR = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/index.json"
AJAYSENR_TREE = "https://api.github.com/repos/ajaysenr/HackerOne-Disclosed-Reports/git/trees/main?recursive=1"
XDAVIDHU = "https://raw.githubusercontent.com/xdavidhu/awesome-google-vrp-writeups/master/writeups.csv"
SAYAN011 = "https://raw.githubusercontent.com/sayan011/Immunefi-bug-bounty-writeups-list/master/README.md"


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_json(url, timeout):
    return json.loads(fetch(url, timeout).decode("utf-8", "replace"))


def clean(s):
    if s is None:
        return None
    s = re.sub(r"\s+", " ", str(s)).strip()
    return s or None


def parse_usd(s):
    if s is None:
        return None
    if isinstance(s, (int, float)):
        return int(s) if float(s) == int(s) else float(s)
    t = str(s).strip()
    if not t:
        return None
    if re.search(r"not paid|unpaid|no bounty|n/a", t, re.I):
        return 0
    residual = re.sub(r"(?i)usd|dollars?", "", t)
    residual = re.sub(r"[\d\s.,~+$kKmMxX*<>?=()'/-]", "", residual)
    if residual:
        return None  # non-USD denomination (ETH, points, etc.)
    total = 0.0
    for m in re.finditer(r"([\d.,]+)\s*([kKmM]?)", t):
        try:
            v = float(m.group(1).replace(",", ""))
        except ValueError:
            continue
        total += v * {"k": 1e3, "m": 1e6}.get(m.group(2).lower(), 1.0)
    if not total:
        return None
    return int(total) if total == int(total) else total


def rec(source, title=None, program=None, weakness=None, severity=None,
        bounty_usd=None, url=None, date=None):
    return {"source": source, "title": clean(title), "program": clean(program),
            "weakness": clean(weakness), "severity": clean(severity),
            "bounty_usd": bounty_usd, "url": clean(url), "date": clean(date)}


def bugskill_url(timeout):
    try:
        tree = fetch_json(BS_TREE, timeout)
        blobs = [t for t in tree.get("tree", [])
                 if t.get("type") == "blob" and t["path"].endswith(".json")]
        ranked = sorted(blobs, key=lambda t: t.get("size") or 0, reverse=True)
        for b in ranked:
            if re.search(r"report|hacktivity", b["path"], re.I):
                return BS_RAW % b["path"]
        if ranked:
            return BS_RAW % ranked[0]["path"]
    except Exception as e:
        log.warning("bugskill-ai tree discovery failed: %s", e)
    return None


def norm_bugskill(data):
    reports = data.get("reports") if isinstance(data, dict) else data
    out = []
    for r in reports or []:
        if not isinstance(r, dict):
            continue
        a = r.get("attributes") or r
        rel = r.get("relationships") or {}
        prog = (((rel.get("program") or {}).get("data") or {}).get("attributes")) or {}
        out.append(rec("bugskill-ai",
                       title=a.get("title"),
                       program=prog.get("name") or prog.get("handle"),
                       weakness=a.get("cwe") or a.get("weakness"),
                       severity=a.get("severity_rating") or a.get("severity"),
                       bounty_usd=parse_usd(a.get("total_awarded_amount") or a.get("bounty")),
                       url=a.get("url"),
                       date=a.get("submitted_at") or a.get("disclosed_at") or a.get("reported_at")))
    return out


def norm_ajaysenr(data):
    out = []
    for r in data or []:
        if not isinstance(r, dict):
            continue
        out.append(rec("ajaysenr-h1",
                       title=r.get("title"),
                       program=r.get("program") or r.get("program_handle"),
                       weakness=r.get("weakness"),
                       severity=r.get("severity"),
                       bounty_usd=parse_usd(r.get("bounty")),
                       url=r.get("url"),
                       date=r.get("reported_at") or r.get("disclosed_at")))
    return out


def norm_xdavidhu(text):
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        out.append(rec("xdavidhu-google-vrp",
                       title=row.get("title"),
                       program="Google VRP",
                       bounty_usd=parse_usd(row.get("bounty")),
                       url=row.get("url"),
                       date=row.get("date") if row.get("date") not in ("?", "") else None))
    return out


MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def norm_sayan011(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        cols = [c.strip() for c in line.strip("|").split("|")]
        if len(cols) < 3 or set(cols[0]) <= set("-: ") or cols[0].lower().startswith("bounty"):
            continue
        m = MD_LINK.search(cols[2])
        title, url = (m.group(1), m.group(2)) if m else (cols[2], None)
        out.append(rec("sayan011-immunefi",
                       title=title,
                       program=title,
                       severity=cols[1] if cols[1] not in ("-", "") else None,
                       bounty_usd=parse_usd(cols[0]),
                       url=url))
    return out


def source_bugskill(timeout):
    url = bugskill_url(timeout)
    urls = [url] if url else []
    urls += [BS_RAW % p for p in BS_FALLBACKS]
    last = None
    for u in dict.fromkeys(urls):
        try:
            return u, norm_bugskill(fetch_json(u, timeout))
        except Exception as e:
            last = e
            log.warning("bugskill-ai %s failed: %s", u, e)
    raise last or RuntimeError("no bugskill-ai source reachable")


def source_ajaysenr(timeout):
    try:
        return AJAYSENR, norm_ajaysenr(fetch_json(AJAYSENR, timeout))
    except Exception as e:
        log.warning("ajaysenr index.json failed (%s), trying tree discovery", e)
    tree = fetch_json(AJAYSENR_TREE, timeout)
    blobs = [t["path"] for t in tree.get("tree", [])
             if t.get("type") == "blob" and t["path"].endswith(".json")]
    pick = sorted(blobs, key=lambda p: (0 if "index" in p.lower() else 1, p))
    if not pick:
        raise RuntimeError("no json found in ajaysenr tree")
    url = "https://raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/%s" % pick[0]
    return url, norm_ajaysenr(fetch_json(url, timeout))


def source_xdavidhu(timeout):
    return XDAVIDHU, norm_xdavidhu(fetch(XDAVIDHU, timeout).decode("utf-8", "replace"))


def source_sayan011(timeout):
    return SAYAN011, norm_sayan011(fetch(SAYAN011, timeout).decode("utf-8", "replace"))


SOURCES = [
    ("bugskill-ai", source_bugskill),
    ("ajaysenr-h1", source_ajaysenr),
    ("xdavidhu-google-vrp", source_xdavidhu),
    ("sayan011-immunefi", source_sayan011),
]


def main():
    ap = argparse.ArgumentParser(description="Ingest disclosed-bug/writeup corpora for RAG and few-shot priming.")
    ap.add_argument("--out-dir", default="./out", help="output directory (default ./out)")
    ap.add_argument("--sources", default=None, help="comma-separated source filter")
    ap.add_argument("--timeout", type=float, default=30, help="per-fetch timeout seconds (default 30)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    want = {s.strip() for s in args.sources.split(",")} if args.sources else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    index = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "file": "records.jsonl", "sources": []}
    total = 0
    with open(out_dir / "records.jsonl", "w") as f:
        for name, fn in SOURCES:
            if want and name not in want:
                continue
            entry = {"source": name, "status": "ok", "n_records": 0,
                     "file": "records.jsonl"}
            try:
                url, recs = fn(args.timeout)
                for r in recs:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
                entry.update(url=url, n_records=len(recs),
                             fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
                total += len(recs)
                log.info("%s: %d records", name, len(recs))
            except Exception as e:
                entry["status"] = "error"
                entry["error"] = "%s: %s" % (type(e).__name__, e)
                log.warning("%s failed: %s", name, e)
            index["sources"].append(entry)
    index["total_records"] = total
    (out_dir / "knowledge-index.json").write_text(json.dumps(index, indent=2) + "\n")
    log.info("wrote %d records to %s", total, out_dir / "records.jsonl")

    flagger = Path(__file__).resolve().parent.parent / "content-scan" / "flag_corpus.py"
    try:
        r = subprocess.run([sys.executable, str(flagger), "--file",
                            str(out_dir / "records.jsonl")],
                           capture_output=True, text=True)
        if r.returncode:
            log.warning("content-scan flagging failed: %s",
                        (r.stderr or r.stdout).strip())
        else:
            log.info("content-scan: %s", r.stdout.strip())
    except Exception as e:
        log.warning("content-scan flagging failed: %s", e)
    return 0


if __name__ == "__main__":
    sys.exit(main())
