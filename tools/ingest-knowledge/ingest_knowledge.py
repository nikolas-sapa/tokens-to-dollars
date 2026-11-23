#!/usr/bin/env python3
import argparse
import csv
import io
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
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

TRICKEST_REPO = "trickest/cve"
TRICKEST_TREE = "https://api.github.com/repos/%s/git/trees/%%s" % TRICKEST_REPO
TRICKEST_BLOB = "https://github.com/%s/blob/main/%%s" % TRICKEST_REPO
TRICKEST_MAX_FILES = 500  # bounded subset of the newest year dirs

DEFIHACK = "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md"
DEFIHACK_REPO = "https://github.com/SunWeb3Sec/DeFiHackLabs"

NUCLEI_TREE = "https://api.github.com/repos/projectdiscovery/nuclei-templates/git/trees/main?recursive=1"
NUCLEI_DIR = "https://github.com/projectdiscovery/nuclei-templates/tree/main/%s"

ARVO_META = "https://raw.githubusercontent.com/n132/ARVO/main/arvo/NewTracker/metadata.jsonl"
ARVO_MAX_BYTES = 50 * 1024 * 1024  # skip rather than pull a multi-GB arvo.db

# reddelexc/hackerone-reports republishes HackerOne report metadata scraped from
# H1 hacktivity; the repo carries no explicit redistribution license, so treat it
# like the other corpora: author-owned, mirror internally, never republish.
H1REPORTS = "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv"

HUNTR_PAGE = "https://huntr.com/bounties"
HUNTR_BOUNTY = "https://huntr.com/bounties/%s"
# pre-Protect-AI huntr disclosures live as per-bounty vulnerability.json files
# in the legacy 418sec/huntr repo; used as fallback when huntr.com markup yields
# no records (site is JS-rendered and its embedded data shape changes often)
HUNTR_418_TREE = "https://api.github.com/repos/418sec/huntr/git/trees/master?recursive=1"
HUNTR_418_RAW = "https://raw.githubusercontent.com/418sec/huntr/master/%s"
HUNTR_MAX_FILES = 250  # bounded subset of legacy vulnerability.json payloads

# Cyfrin Solodit findings API: single POST /findings endpoint, key header
# X-Cyfrin-API-Key, rate limits ~100 req/min and ~10k req/day per docs.
SOLODIT_API = "https://solodit.cyfrin.io/api/v1/solodit/findings"
SOLODIT_PAGE_SIZE = 50
SOLODIT_MAX_RECORDS = 500
SOLODIT_PAGE_DELAY = 0.7  # seconds between pages; keeps us well under 100 req/min
SOLODIT_KEY_ENV = "SOLODIT_API_KEY"

# PrimeVul full jsonl shards run ~500MB+; fetch bounded row windows through the
# HF datasets-server instead and emit one index record per CVE. If the rows API
# is unavailable, fall back to a shard-level index of a github assets mirror.
PRIMEVUL_ROWS = ("https://datasets-server.huggingface.co/rows"
                 "?dataset=%s&config=%s&split=%s&offset=%d&length=%d")
PRIMEVUL_DATASETS = ["DLVulDet/PrimeVul", "colin/PrimeVul"]
PRIMEVUL_SPLITS = [("default", "test"), ("default", "validation"), ("default", "train")]
PRIMEVUL_PAGE = 100
PRIMEVUL_MAX_ROWS = 2000
PRIMEVUL_TREE = ("https://api.github.com/repos/timothee-chauvin/"
                 "PrimeVul-assets-on-github/git/trees/main?recursive=1")
PRIMEVUL_BLOB = ("https://github.com/timothee-chauvin/"
                 "PrimeVul-assets-on-github/blob/main/%s")

PATCHDB_PATH = None   # --db; local CVEfixes/MoreFixes sqlite file
PATCHDB_MAX_RECORDS = 5000


def fetch(url, timeout):
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_json(url, timeout):
    return json.loads(fetch(url, timeout).decode("utf-8", "replace"))


def content_size(url, timeout):
    try:
        req = Request(url, headers={"User-Agent": UA}, method="HEAD")
        with urlopen(req, timeout=timeout) as resp:
            return int(resp.headers.get("Content-Length") or 0)
    except Exception:
        return 0


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
        bounty_usd=None, url=None, date=None, extra=None):
    r = {"source": source, "title": clean(title), "program": clean(program),
         "weakness": clean(weakness), "severity": clean(severity),
         "bounty_usd": bounty_usd, "url": clean(url), "date": clean(date)}
    if extra:
        r.update({k: v for k, v in extra.items() if v is not None})
    return r


def first(d, *keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None


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


CVE_FILE = re.compile(r"(CVE-\d{4}-\d+)\.md$", re.I)


def source_trickest(timeout):
    root = fetch_json(TRICKEST_TREE % "main", timeout)
    years = sorted((t for t in root.get("tree", [])
                    if t.get("type") == "tree" and re.fullmatch(r"\d{4}", t["path"])),
                   key=lambda t: t["path"], reverse=True)
    picked = []
    for y in years:
        if len(picked) >= TRICKEST_MAX_FILES:
            break
        sub = fetch_json(TRICKEST_TREE % ("%s?recursive=1" % y["sha"]), timeout)
        cves = sorted((t["path"] for t in sub.get("tree", [])
                       if t.get("type") == "blob" and CVE_FILE.search(t["path"])),
                      reverse=True)
        picked += [(y["path"], p) for p in cves]
    picked = picked[:TRICKEST_MAX_FILES]
    out = []
    for year, path in picked:
        cve = CVE_FILE.search(path).group(1).upper()
        out.append(rec("trickest-cve", title=cve, weakness=cve,
                       url=TRICKEST_BLOB % ("%s/%s" % (year, path)), date=year))
    return TRICKEST_TREE % "main", out


DHL_INDEX = re.compile(r"^\[(20\d{6})\s+([^\]]+)\]\(([^)\s]+)\)")
DHL_HEAD = re.compile(r"^#{2,4}\s*(20\d{6})\s+(.+?)\s+-\s")
DHL_LOST = re.compile(r"^#{2,4}\s*Lost:\s*(.+?)\s*$", re.I)
DHL_POC = re.compile(r"\]\((src/test/[^)\s]+)\)")


def norm_defihacklabs(text):
    extra = {}
    cur = None
    for line in text.splitlines():
        h = DHL_HEAD.match(line)
        if h:
            cur = (h.group(1), h.group(2).strip().lower())
            extra[cur] = {}
            continue
        if not cur:
            continue
        l = DHL_LOST.match(line)
        if l:
            extra[cur]["lost"] = l.group(1)
        elif "poc" not in extra[cur]:
            m = DHL_POC.search(line)
            if m:
                extra[cur]["poc"] = m.group(1)
    out = []
    for line in text.splitlines():
        m = DHL_INDEX.match(line.strip())
        if not m:
            continue
        date, name, href = m.groups()
        e = extra.get((date, name.strip().lower())) or {}
        if e.get("poc"):
            url = "%s/blob/main/%s" % (DEFIHACK_REPO, e["poc"])
        elif href.startswith("http"):
            url = href
        elif href.startswith("#"):
            url = "%s/blob/main/README.md%s" % (DEFIHACK_REPO, href)
        else:
            url = "%s/blob/main/%s" % (DEFIHACK_REPO, href)
        amt = e.get("lost")
        amt = re.split(r"[.;]\s", amt)[0][:80] if amt else None
        title = "%s — lost %s" % (name, amt) if amt else name
        out.append(rec("defihacklabs", title=title, program=name, url=url,
                       date="%s-%s-%s" % (date[:4], date[4:6], date[6:])))
    return out


def source_defihacklabs(timeout):
    return DEFIHACK, norm_defihacklabs(fetch(DEFIHACK, timeout).decode("utf-8", "replace"))


CF_DIR = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")  # bidi/zero-width format chars seen upstream


def source_nuclei(timeout):
    tree = fetch_json(NUCLEI_TREE, timeout)
    if tree.get("truncated"):
        log.warning("nuclei-templates tree truncated; class counts are partial")
    classes = {}
    for t in tree.get("tree", []):
        if (t.get("type") != "blob" or "/" not in t["path"]
                or t["path"].startswith(".")
                or not t["path"].endswith((".yaml", ".yml"))):
            continue
        top = CF_DIR.sub("", t["path"].split("/", 1)[0])
        classes[top] = classes.get(top, 0) + 1
    out = [rec("nuclei-templates",
               title="nuclei:%s (%d templates)" % (k, n),
               weakness=k, url=NUCLEI_DIR % k)
           for k, n in sorted(classes.items())]
    return NUCLEI_TREE, out


def source_arvo(timeout):
    size = content_size(ARVO_META, timeout)
    if size and size > ARVO_MAX_BYTES:
        log.warning("arvo index grew to %d bytes (>50MB); skipping", size)
        return ARVO_META, []
    out = []
    for line in fetch(ARVO_META, timeout).decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        out.append(rec("arvo",
                       title="%s: %s" % (d.get("project") or "?", d.get("crash_type") or "crash"),
                       program=d.get("project"),
                       weakness=d.get("crash_type"),
                       severity=d.get("severity"),
                       url="https://issues.oss-fuzz.com/issues/%s" % d["localId"]
                           if d.get("localId") else None))
    return ARVO_META, out


def norm_h1reports(text):
    out = []
    for row in csv.DictReader(io.StringIO(text)):
        link = (row.get("link") or "").strip()
        if link and not link.startswith("http"):
            link = "https://" + link
        out.append(rec("reddelexc-h1",
                       title=row.get("title"),
                       program=row.get("program"),
                       weakness=row.get("vuln_type"),
                       bounty_usd=parse_usd(row.get("bounty")),
                       url=link or None))
    return out


def source_h1reports(timeout):
    return H1REPORTS, norm_h1reports(fetch(H1REPORTS, timeout).decode("utf-8", "replace"))


NEXT_DATA = re.compile(
    r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', re.S)


def deep_find_bounties(node):
    """Yield dicts that look like huntr vuln entries inside arbitrary JSON."""
    if isinstance(node, dict):
        keys = set(node)
        if ("title" in keys or "vulnerability_title" in keys) and (
                keys & {"slug", "bounty_id", "vulnerability_id", "cwe", "status"}):
            yield node
        for v in node.values():
            yield from deep_find_bounties(v)
    elif isinstance(node, list):
        for v in node:
            yield from deep_find_bounties(v)


def norm_huntr_item(d):
    slug = first(d, "slug", "bounty_id", "vulnerability_id", "id")
    cwe = first(d, "cwe", "weakness", "vulnerability_type")
    if isinstance(cwe, list):
        cwe = ", ".join(str(c) for c in cwe)
    elif isinstance(cwe, dict):
        cwe = first(cwe, "id", "name", "title")
    repo = first(d, "repository", "repo", "package", "project")
    if isinstance(repo, dict):
        repo = first(repo, "name", "url", "full_name")
    url = d.get("url")
    if not url and slug:
        url = HUNTR_BOUNTY % slug
    return rec("huntr",
               title=first(d, "title", "vulnerability_title", "name"),
               program=repo,
               weakness=cwe,
               severity=first(d, "severity", "cvss_severity", "impact"),
               url=url,
               date=first(d, "disclosed_at", "disclosure_date", "published_at",
                          "created_at"),
               extra={"status": first(d, "status", "state"),
                      "repo": repo})


def norm_huntr_nextdata(html):
    m = NEXT_DATA.search(html)
    if not m:
        return []
    try:
        data = json.loads(m.group(1))
    except ValueError:
        return []
    seen, out = set(), []
    for d in deep_find_bounties(data):
        key = json.dumps(d, sort_keys=True)[:400]
        if key in seen:
            continue
        seen.add(key)
        r = norm_huntr_item(d)
        if r["title"]:
            out.append(r)
    return out


def norm_huntr_418(d):
    """Legacy 418sec/huntr vulnerability.json entry."""
    def flat(dd):
        out = {}
        for k, v in (dd or {}).items():
            if isinstance(v, dict):
                out.update(v)
            else:
                out[k] = v
        return out
    d = flat(d)
    vuln = first(d, "Vulnerability", "vulnerability")
    if isinstance(vuln, dict):
        d = {**flat(vuln), **d}
    pkg = first(d, "PackageName", "package_name", "Name", "package")
    reg = first(d, "PackageRegistry", "package_registry", "Registry")
    repo = "%s/%s" % (reg, pkg) if reg and pkg else pkg
    cve = first(d, "CVE", "cve", "CVEID", "cve_id")
    if isinstance(cve, list):
        cve = ", ".join(cve)
    slug = first(d, "ID", "id", "BountyID")
    return rec("huntr",
               title=first(d, "Title", "title", "Summary") or cve,
               program=repo,
               weakness=first(d, "CWE", "cwe", "CWEs"),
               url="https://huntr.com/bounties/%s" % slug if slug else None,
               date=first(d, "DisclosureDate", "disclosed", "PublishDate",
                          "Created"),
               extra={"cve": cve, "repo": repo,
                      "status": first(d, "Status", "status")})


def source_huntr(timeout):
    try:
        html = fetch(HUNTR_PAGE, timeout).decode("utf-8", "replace")
        out = norm_huntr_nextdata(html)
        if out:
            return HUNTR_PAGE, out
        log.warning("huntr.com page yielded no __NEXT_DATA__ records; "
                    "falling back to 418sec/huntr mirror")
    except Exception as e:
        log.warning("huntr.com fetch failed (%s); falling back to 418sec/huntr", e)
    tree = fetch_json(HUNTR_418_TREE, timeout)
    paths = sorted(t["path"] for t in tree.get("tree", [])
                   if t.get("type") == "blob"
                   and t["path"].endswith("vulnerability.json"))
    picked = paths[:HUNTR_MAX_FILES]
    if not picked:
        raise RuntimeError("no vulnerability.json files in 418sec/huntr tree")
    out = []
    for p in picked:
        try:
            d = fetch_json(HUNTR_418_RAW % p, timeout)
            out.append(norm_huntr_418(d))
        except Exception as e:
            log.warning("huntr legacy %s failed: %s", p, e)
    return HUNTR_418_TREE, out


def solodit_post(body, api_key, timeout):
    req = Request(SOLODIT_API, data=json.dumps(body).encode(),
                  headers={"User-Agent": UA, "Content-Type": "application/json",
                           "X-Cyfrin-API-Key": api_key},
                  method="POST")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def solodit_findings(data):
    """Pull the findings list out of a response whose envelope may vary."""
    if isinstance(data, list):
        return data, None
    if not isinstance(data, dict):
        return [], None
    total = first(data, "total", "total_count", "count")
    meta = data.get("metadata") or data.get("meta")
    if total is None and isinstance(meta, dict):
        total = first(meta, "total", "totalCount", "count")
    for k in ("findings", "data", "results", "items", "vulnerabilities"):
        v = data.get(k)
        if isinstance(v, list):
            return v, total
        if isinstance(v, dict):
            for k2 in ("findings", "results", "items"):
                if isinstance(v.get(k2), list):
                    return v[k2], total or first(v, "total", "totalCount")
    return [], total


def norm_solodit(d):
    firm = first(d, "firm", "audit_firm", "auditor", "company")
    if isinstance(firm, dict):
        firm = first(firm, "name", "label", "value")
    if isinstance(firm, list):
        firm = ", ".join(str(f) for f in firm)
    proto = first(d, "protocol", "protocol_name", "project", "contest")
    if isinstance(proto, dict):
        proto = first(proto, "name", "title", "value")
    url = first(d, "url", "link", "report_link", "pdf_link")
    fid = first(d, "id", "slug")
    if not url and fid:
        url = "https://solodit.cyfrin.io/issues/%s" % fid
    return rec("solodit",
               title=first(d, "title", "finding_title", "name", "issue_title"),
               program=proto,
               weakness=first(d, "category", "vulnerability_type", "finding_type",
                              "issue_type"),
               severity=first(d, "impact", "severity", "risk"),
               url=url,
               date=first(d, "date", "report_date", "published_at", "created_at"),
               extra={"firm": firm})


def source_solodit(timeout):
    api_key = os.environ.get(SOLODIT_KEY_ENV)
    if not api_key:
        raise RuntimeError("%s not set; get a key at solodit.cyfrin.io "
                           "(profile -> API Keys)" % SOLODIT_KEY_ENV)
    out, seen, page = [], set(), 1
    while len(out) < SOLODIT_MAX_RECORDS:
        body = {"page": page, "pageSize": SOLODIT_PAGE_SIZE,
                "filters": {"sortField": "Quality", "sortDirection": "Desc"}}
        findings, total = solodit_findings(solodit_post(body, api_key, timeout))
        if not findings:
            break
        for d in findings:
            if not isinstance(d, dict):
                continue
            r = norm_solodit(d)
            key = r["url"] or r["title"]
            if key and key not in seen:
                seen.add(key)
                out.append(r)
        if total and page * SOLODIT_PAGE_SIZE >= int(total):
            break
        page += 1
        time.sleep(SOLODIT_PAGE_DELAY)
    return SOLODIT_API, out[:SOLODIT_MAX_RECORDS]


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def primevul_cve(row):
    cve = first(row, "cve", "cve_id", "CVE")
    if cve and CVE_RE.search(str(cve)):
        return CVE_RE.search(str(cve)).group(0).upper()
    return None


def norm_primevul_index(cve, rows):
    cwes, projects, commits = set(), set(), set()
    vuln_func = patch_func = None
    for r in rows:
        c = first(r, "cwe", "cwe_id", "CWE")
        if isinstance(c, list):
            cwes.update(str(x) for x in c)
        elif c:
            cwes.add(str(c))
        p = first(r, "project", "repo", "repository")
        if p:
            projects.add(str(p))
        cm = first(r, "commit", "commit_id", "fix_commit", "hash")
        if cm:
            commits.add(str(cm))
        v = first(r, "vulnerable_func", "func_before", "vul_func", "func_vul")
        f = first(r, "patched_func", "func_after", "fix_func", "func_fixed")
        if v and f and not (vuln_func and patch_func):
            vuln_func, patch_func = v, f
        elif r.get("target") in (1, "1", True) and not vuln_func:
            vuln_func = first(r, "func", "function", "code")
    proj = sorted(projects)
    return rec("primevul",
               title="%s (%d sample%s)" % (cve, len(rows),
                                           "" if len(rows) == 1 else "s"),
               program=", ".join(proj[:3]),
               weakness=", ".join(sorted(cwes)) or None,
               url="https://nvd.nist.gov/vuln/detail/%s" % cve,
               extra={"cve": cve, "commits": sorted(commits)[:5],
                      "n_samples": len(rows),
                      "vulnerable_func": vuln_func,
                      "patched_func": patch_func})


def source_primevul(timeout):
    by_cve = {}
    rows_left = PRIMEVUL_MAX_ROWS
    for ds in PRIMEVUL_DATASETS:
        for config, split in PRIMEVUL_SPLITS:
            offset = 0
            while rows_left > 0:
                n = min(PRIMEVUL_PAGE, rows_left)
                url = PRIMEVUL_ROWS % (ds, config, split, offset, n)
                try:
                    data = fetch_json(url, timeout)
                except Exception as e:
                    log.warning("primevul rows %s/%s@%d failed: %s",
                                ds, split, offset, e)
                    break
                rows = [r.get("row", r) for r in data.get("rows", [])]
                if not rows:
                    break
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    cve = primevul_cve(row)
                    if cve:
                        by_cve.setdefault(cve, []).append(row)
                got = len(rows)
                rows_left -= got
                if got < n:
                    break
                offset += got
        if by_cve:
            break  # first dataset that yields rows wins
    if not by_cve:
        log.warning("primevul rows API yielded nothing; "
                    "falling back to shard-level index")
        tree = fetch_json(PRIMEVUL_TREE, timeout)
        out = [rec("primevul",
                   title="primevul shard %s" % t["path"],
                   weakness="C/C++ vuln+patch pairs",
                   url=PRIMEVUL_BLOB % t["path"],
                   extra={"bytes": t.get("size")})
               for t in tree.get("tree", [])
               if t.get("type") == "blob" and t["path"].endswith(".jsonl")]
        if out:
            return PRIMEVUL_TREE, out
        raise RuntimeError("primevul: rows API and github index both empty")
    out = [norm_primevul_index(cve, rows)
           for cve, rows in sorted(by_cve.items())]
    return PRIMEVUL_ROWS % ("|".join(PRIMEVUL_DATASETS), "default", "*", 0, 0), out


# Expected sqlite schema (CVEfixes / MoreFixes layout; column names probed,
# alternate names listed first win):
#   cve(cve_id, published?/published_date?/date?)
#   fixes(fix_id, cve_id, hash, repo_url)
#   file_change(file_change_id, fix_id, filename)
#   method_change(method_change_id, file_change_id, name, before_change, code)
# before_change is 'True'/'False' text in CVEfixes; '1'/'0' tolerated.

def db_columns(conn, table):
    return {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}


def pick_col(cols, *names):
    for n in names:
        if n in cols:
            return n
    return None


def source_patchdb(timeout):
    if not PATCHDB_PATH:
        raise RuntimeError("patchdb requires --db PATH "
                           "(local CVEfixes/MoreFixes sqlite file)")
    if not Path(PATCHDB_PATH).is_file():
        raise FileNotFoundError("patchdb sqlite file not found: %s" % PATCHDB_PATH)
    conn = sqlite3.connect("file:%s?mode=ro" % PATCHDB_PATH, uri=True)
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        required = {"cve", "fixes", "file_change", "method_change"}
        missing = required - tables
        if missing:
            raise RuntimeError(
                "patchdb schema mismatch: missing table(s) %s in %s "
                "(expected CVEfixes/MoreFixes layout: cve, fixes, "
                "file_change, method_change; found: %s)"
                % (", ".join(sorted(missing)), PATCHDB_PATH,
                   ", ".join(sorted(tables))))
        fc, mc = db_columns(conn, "fixes"), db_columns(conn, "file_change")
        me, cv = db_columns(conn, "method_change"), db_columns(conn, "cve")
        f_id = pick_col(fc, "fix_id", "id")
        f_cve = pick_col(fc, "cve_id", "cve")
        f_hash = pick_col(fc, "hash", "commit", "commit_hash")
        f_repo = pick_col(fc, "repo_url", "repository", "repo")
        ch_id = pick_col(mc, "file_change_id", "id")
        ch_fix = pick_col(mc, "fix_id", "commit_hash", "hash")
        ch_file = pick_col(mc, "filename", "file", "path")
        m_id = pick_col(me, "method_change_id", "id")
        m_file = pick_col(me, "file_change_id", "file_id")
        m_name = pick_col(me, "name", "method_name", "signature")
        m_before = pick_col(me, "before_change", "before", "is_before")
        m_code = pick_col(me, "code", "method_code", "body", "source")
        c_id = pick_col(cv, "cve_id", "id", "cve")
        c_date = pick_col(cv, "published", "published_date", "date")
        missing_cols = [n for n, c in
                        (("fixes.fix_id", f_id), ("fixes.cve_id", f_cve),
                         ("file_change.file_change_id", ch_id),
                         ("file_change.fix_id", ch_fix),
                         ("method_change.file_change_id", m_file),
                         ("method_change.before_change", m_before),
                         ("method_change.code", m_code))
                        if c is None]
        if missing_cols:
            raise RuntimeError("patchdb schema mismatch: missing column(s) %s"
                               % ", ".join(missing_cols))
        q = ("SELECT f.%s, f.%s, f.%s, f.%s, ch.%s, m.%s, m.%s, m.%s, m.%s, "
             "cv.%s FROM fixes f "
             "JOIN file_change ch ON ch.%s = f.%s "
             "JOIN method_change m ON m.%s = ch.%s "
             "LEFT JOIN cve cv ON cv.%s = f.%s"
             % (f_cve, f_hash or "NULL", f_repo or "NULL", f_id,
                ch_file or "NULL", m_name or "NULL", m_before or "NULL",
                m_code, m_id,
                c_date or "NULL",
                ch_fix, f_id, m_file, ch_id,
                c_id or "NULL", f_cve))
        q = q.replace("f.NULL", "NULL").replace("ch.NULL", "NULL")
        q = q.replace("m.NULL", "NULL").replace("cv.NULL", "NULL")
        pairs = {}
        for (cve_id, commit, repo, _fix, fname, mname, before, code,
             _mid, cve_date) in conn.execute(q):
            key = (cve_id, commit, fname, mname)
            d = pairs.setdefault(key, {"repo": repo, "date": cve_date})
            if str(before).lower() in ("true", "1", "yes"):
                d["vuln"] = code
            elif str(before).lower() in ("false", "0", "no"):
                d["patch"] = code
            if len(pairs) > PATCHDB_MAX_RECORDS * 3:
                break
        if not pairs:
            raise RuntimeError("patchdb query returned 0 method rows in %s"
                               % PATCHDB_PATH)
        out = []
        for (cve_id, commit, fname, mname), d in sorted(pairs.items()):
            if not (d.get("vuln") and d.get("patch")):
                continue  # only emit complete vuln+patch pairs
            url = None
            if repo and commit and "github.com" in str(repo):
                url = "%s/commit/%s" % (str(repo).rstrip("/"), commit)
            out.append(rec("patchdb",
                           title="%s %s" % (cve_id, mname or fname or "?"),
                           program=d["repo"],
                           weakness=cve_id,
                           url=url,
                           date=d["date"],
                           extra={"cve": cve_id, "commit": commit,
                                  "file": fname, "method": mname,
                                  "vulnerable_func": d["vuln"],
                                  "patched_func": d["patch"]}))
            if len(out) >= PATCHDB_MAX_RECORDS:
                break
        return "file://%s" % PATCHDB_PATH, out
    finally:
        conn.close()


SOURCES = [
    ("bugskill-ai", source_bugskill),
    ("ajaysenr-h1", source_ajaysenr),
    ("xdavidhu-google-vrp", source_xdavidhu),
    ("sayan011-immunefi", source_sayan011),
    ("trickest-cve", source_trickest),
    ("defihacklabs", source_defihacklabs),
    ("nuclei-templates", source_nuclei),
    ("arvo", source_arvo),
    ("reddelexc-h1", source_h1reports),
    ("huntr", source_huntr),
    ("solodit", source_solodit),
    ("primevul", source_primevul),
    ("patchdb", source_patchdb),
]


def main():
    global TRICKEST_MAX_FILES, HUNTR_MAX_FILES, SOLODIT_MAX_RECORDS
    global PRIMEVUL_MAX_ROWS, PATCHDB_PATH, PATCHDB_MAX_RECORDS
    names = ", ".join(n for n, _ in SOURCES)
    ap = argparse.ArgumentParser(description="Ingest disclosed-bug/writeup corpora for RAG and few-shot priming.")
    ap.add_argument("--out-dir", default="./out", help="output directory (default ./out)")
    ap.add_argument("--sources", default=None,
                    help="comma-separated source filter (one or more of: %s)" % names)
    ap.add_argument("--list", action="store_true", help="list source names and exit")
    ap.add_argument("--trickest-cap", type=int, default=TRICKEST_MAX_FILES,
                    help="max trickest/cve writeup records (default %d)" % TRICKEST_MAX_FILES)
    ap.add_argument("--huntr-cap", type=int, default=HUNTR_MAX_FILES,
                    help="max legacy huntr vulnerability.json fetches when the "
                         "418sec/huntr fallback is used (default %d)" % HUNTR_MAX_FILES)
    ap.add_argument("--solodit-cap", type=int, default=SOLODIT_MAX_RECORDS,
                    help="max solodit findings fetched via paged API "
                         "(default %d)" % SOLODIT_MAX_RECORDS)
    ap.add_argument("--primevul-cap", type=int, default=PRIMEVUL_MAX_ROWS,
                    help="max primevul dataset rows scanned for CVE index "
                         "records (default %d)" % PRIMEVUL_MAX_ROWS)
    ap.add_argument("--db", default=None,
                    help="local CVEfixes/MoreFixes sqlite path for the patchdb "
                         "source")
    ap.add_argument("--db-cap", type=int, default=PATCHDB_MAX_RECORDS,
                    help="max patchdb vuln+patch pairs emitted "
                         "(default %d)" % PATCHDB_MAX_RECORDS)
    ap.add_argument("--timeout", type=float, default=30, help="per-fetch timeout seconds (default 30)")
    args = ap.parse_args()

    if args.list:
        for name, _ in SOURCES:
            print(name)
        return 0

    TRICKEST_MAX_FILES = args.trickest_cap
    HUNTR_MAX_FILES = args.huntr_cap
    SOLODIT_MAX_RECORDS = args.solodit_cap
    PRIMEVUL_MAX_ROWS = args.primevul_cap
    PATCHDB_PATH = args.db
    PATCHDB_MAX_RECORDS = args.db_cap

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
