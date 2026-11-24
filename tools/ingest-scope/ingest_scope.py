#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

log = logging.getLogger("ingest_scope")
UA = "tokens-to-dollars-ingest/0.2 (+https://github.com/tokens-to-dollars)"

ARKADIYT = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/%s_data.json"
SOURCES = [
    ("arkadiyt-hackerone",  "hackerone",   ARKADIYT % "hackerone",  "arkadiyt"),
    ("arkadiyt-bugcrowd",   "bugcrowd",    ARKADIYT % "bugcrowd",   "arkadiyt"),
    ("arkadiyt-intigriti",  "intigriti",   ARKADIYT % "intigriti",  "arkadiyt"),
    ("arkadiyt-yeswehack",  "yeswehack",   ARKADIYT % "yeswehack",  "arkadiyt"),
    ("arkadiyt-hackenproof", "hackenproof", ARKADIYT % "hackenproof", "arkadiyt"),
    ("lissy93",             "independent", "https://bug-bounties.as93.net/api/programs.json", "lissy93"),
    ("diodb",               "independent", "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json", "diodb"),
    ("immunefi",            "immunefi",    "https://immunefi.com/public-api/bounties.json", "immunefi"),
]

BBSCOPE_UPDATES = "https://bbscope.com/api/v1/updates"
SECTXT_PATH = "/.well-known/security.txt"

SH = {"full": True, "yes": True, "partial": True, "true": True,
      "none": False, "no": False, "false": False}


def sh_bool(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return SH.get(v.strip().lower())
    return None


def payout(v, currency="USD"):
    if v is None:
        return None
    if isinstance(v, dict):
        currency = v.get("currency") or currency
        v = v.get("value")
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    return {"value": int(v) if v == int(v) else v, "currency": currency}


def first(d, *keys):
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return None


def srow(row):
    return {
        "target": first(row, "target", "endpoint", "asset_identifier", "uri", "name"),
        "type": first(row, "type", "asset_type"),
        "eligible_for_bounty": row.get("eligible_for_bounty"),
        "instruction": first(row, "instruction", "description"),
    }


def base(platform, source, ts):
    return {
        "platform": platform,
        "handle": None,
        "name": None,
        "url": None,
        "max_payout": None,
        "safe_harbor": None,
        "excluded_methods": [],
        "in_scope": [],
        "out_of_scope": [],
        "testing_policy_url": None,
        "contact": {"email": None, "url": None, "source": None,
                    "securitytxt": None, "encryption": None,
                    "languages": None},
        "disclosure_timeline_days": None,
        "launch_date": None,
        "offers_bounty": None,
        "offers_swag": None,
        "hall_of_fame": None,
        "public_disclosure": None,
        "policy_url_status": None,
        "securitytxt": None,
        "fresh_scope_at": None,
        "source": source,
        "fetched_at": ts,
    }


def slug_from(url):
    if not url:
        return None
    return url.rstrip("/").rsplit("/", 1)[-1] or None


def norm_arkadiyt(platform, data, ts, source):
    out = []
    for p in data or []:
        if not isinstance(p, dict):
            continue
        r = base(platform, source, ts)
        r["name"] = (p.get("name") or "").strip() or None
        r["handle"] = first(p, "handle", "id", "company_handle") or slug_from(p.get("url"))
        r["handle"] = str(r["handle"]) if r["handle"] else None
        r["url"] = p.get("url")
        if platform == "yeswehack" and not r["url"] and p.get("id"):
            r["url"] = "https://yeswehack.com/programs/%s" % p["id"]
        cur = "EUR" if platform == "yeswehack" else "USD"
        r["max_payout"] = payout(p.get("max_bounty"), cur) or payout(p.get("max_payout"), cur)
        r["safe_harbor"] = sh_bool(p.get("safe_harbor"))
        tgt = p.get("targets") or {}
        r["in_scope"] = [srow(t) for t in tgt.get("in_scope") or [] if isinstance(t, dict)]
        r["out_of_scope"] = [srow(t) for t in tgt.get("out_of_scope") or [] if isinstance(t, dict)]
        r["testing_policy_url"] = r["url"]
        out.append(r)
    return out


def norm_lissy93(platform, data, ts, source):
    progs = data.get("programs") if isinstance(data, dict) else data
    out = []
    for p in progs or []:
        if not isinstance(p, dict):
            continue
        r = base(platform, source, ts)
        r["name"] = (p.get("company") or p.get("name") or "").strip() or None
        r["handle"] = p.get("slug")
        r["url"] = p.get("url")
        r["max_payout"] = payout(p.get("max_payout"), p.get("currency") or "USD")
        r["safe_harbor"] = sh_bool(p.get("safe_harbor"))
        r["in_scope"] = [{"target": d, "type": "domain", "eligible_for_bounty": None,
                          "instruction": None}
                         for d in p.get("domains") or [] if isinstance(d, str)]
        r["testing_policy_url"] = r["url"]
        out.append(r)
    return out


DIODB_CONTACT = {"email": "contact_email", "url": "contact_url",
                 "securitytxt": "securitytxt_url", "encryption": "pgp_key",
                 "languages": "preferred_languages"}


def norm_diodb(platform, data, ts, source):
    out = []
    for p in data or []:
        if not isinstance(p, dict):
            continue
        r = base(platform, source, ts)
        r["name"] = (p.get("program_name") or "").strip() or None
        r["url"] = p.get("policy_url")
        r["handle"] = slug_from(r["url"])
        r["safe_harbor"] = sh_bool(p.get("safe_harbor"))
        r["testing_policy_url"] = r["url"]
        for k, src in DIODB_CONTACT.items():
            v = p.get(src)
            r["contact"][k] = (v.strip() or None) if isinstance(v, str) else (v or None)
        if any(r["contact"].values()):
            r["contact"]["source"] = "diodb"
        r["disclosure_timeline_days"] = p.get("disclosure_timeline_days") or None
        v = p.get("launch_date")
        r["launch_date"] = v.strip() or None if isinstance(v, str) else (v or None)
        r["offers_bounty"] = sh_bool(p.get("offers_bounty"))
        r["offers_swag"] = sh_bool(p.get("offers_swag"))
        hof = p.get("hall_of_fame")
        r["hall_of_fame"] = (True if isinstance(hof, str)
                             and hof.strip().lower().startswith("http")
                             else sh_bool(hof))
        v = p.get("public_disclosure")
        r["public_disclosure"] = (v.strip().lower() or None) if isinstance(v, str) else None
        v = p.get("policy_url_status")
        r["policy_url_status"] = (v.strip().lower() or None) if isinstance(v, str) else None
        out.append(r)
    return out


def norm_immunefi(platform, data, ts, source):
    out = []
    for p in data or []:
        if not isinstance(p, dict):
            continue
        r = base(platform, source, ts)
        slug = p.get("slug") or p.get("id")
        r["name"] = p.get("project")
        r["handle"] = str(slug) if slug else None
        r["url"] = "https://immunefi.com/bounties/%s/" % slug if slug else p.get("websiteUrl")
        r["max_payout"] = payout(p.get("maxBounty"), "USD")
        assets = [a for a in p.get("assets") or [] if isinstance(a, dict)]
        r["safe_harbor"] = True if any(a.get("isSafeHarbor") for a in assets) else None
        r["in_scope"] = [{"target": a.get("url"), "type": a.get("type"),
                          "eligible_for_bounty": True,
                          "instruction": a.get("description") or None}
                         for a in assets]
        for key in ("customOutOfScopeInformation", "customProhibitedActivities"):
            txt = p.get(key)
            if isinstance(txt, str) and txt.strip():
                r["out_of_scope"].append({"target": None, "type": "policy",
                                          "eligible_for_bounty": False,
                                          "instruction": txt})
        r["testing_policy_url"] = r["url"]
        out.append(r)
    return out


NORMALIZERS = {
    "arkadiyt": norm_arkadiyt,
    "lissy93": norm_lissy93,
    "diodb": norm_diodb,
    "immunefi": norm_immunefi,
}


def fetch_json(url, timeout):
    req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def dedupe_key(r):
    ident = (r.get("handle") or r.get("name") or "").strip().lower()
    if not ident:
        ident = (r.get("url") or "").strip().lower().rstrip("/")
    return (r.get("platform"), ident or id(r))


def merge(a, b):
    for k in ("handle", "name", "url", "max_payout", "safe_harbor",
              "testing_policy_url", "disclosure_timeline_days", "launch_date",
              "offers_bounty", "offers_swag", "hall_of_fame",
              "public_disclosure", "policy_url_status", "securitytxt",
              "fresh_scope_at"):
        if a.get(k) in (None, "", []):
            a[k] = b.get(k)
    ca = a.get("contact") or {}
    for k, v in (b.get("contact") or {}).items():
        if ca.get(k) in (None, "") and v not in (None, ""):
            ca[k] = v
    a["contact"] = ca
    a["excluded_methods"] = sorted(set((a.get("excluded_methods") or [])
                                       + (b.get("excluded_methods") or [])))
    for k in ("in_scope", "out_of_scope"):
        seen = {(r.get("target"), r.get("type")) for r in a.get(k) or []}
        for r in b.get(k) or []:
            sk = (r.get("target"), r.get("type"))
            if sk not in seen:
                seen.add(sk)
                a.setdefault(k, []).append(r)
    a["source"] = "+".join(dict.fromkeys(a["source"].split("+") + b["source"].split("+")))
    return a


# --- security.txt (RFC 9116) -------------------------------------------------
# Opt-in pass over unique program hosts. Expires in the past = liveness flag:
# the operator let the file lapse, a dead-program signal. Fills contact{}
# fields only where still empty so diodb/policy data wins on conflict.

def fetch_text(url, timeout):
    req = Request(url, headers={"User-Agent": UA, "Accept": "text/plain,*/*"})
    with urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def parse_securitytxt(text):
    out = {"contacts": [], "expires": None, "policy": [], "encryption": [],
           "languages": None, "acknowledgments": []}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "contact":
            out["contacts"].append(v)
        elif k == "expires":
            out["expires"] = v
        elif k == "policy":
            out["policy"].append(v)
        elif k == "encryption":
            out["encryption"].append(v)
        elif k == "preferred-languages":
            out["languages"] = v
        elif k in ("acknowledgments", "acknowledgements"):
            out["acknowledgments"].append(v)
    return out


def sectxt_expired(iso):
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return t < datetime.now(timezone.utc)


def url_host(u):
    if not u:
        return ""
    return urlparse(u if "//" in u else "//" + u).netloc.split(":")[0].lower()


def enrich_securitytxt(recs, limit, timeout):
    hosts = {}
    for r in recs:
        host = url_host(r.get("testing_policy_url") or r.get("url"))
        if host:
            hosts.setdefault(host, []).append(r)
    stats = {"hosts_checked": 0, "found": 0, "expired": 0, "errors": 0}
    for host, members in sorted(hosts.items())[:limit]:
        surl = "https://%s%s" % (host, SECTXT_PATH)
        stats["hosts_checked"] += 1
        try:
            parsed = parse_securitytxt(fetch_text(surl, timeout))
        except Exception as e:
            stats["errors"] += 1
            log.info("securitytxt %s: %s", host, e)
            continue
        if not any(parsed.values()):
            continue
        stats["found"] += 1
        exp = sectxt_expired(parsed["expires"]) if parsed["expires"] else None
        if exp:
            stats["expired"] += 1
        for r in members:
            mail = next((c for c in parsed["contacts"]
                         if c.lower().startswith("mailto:")), None)
            web = next((c for c in parsed["contacts"]
                        if c.lower().startswith("http")), None)
            r["securitytxt"] = {
                "url": surl,
                "contact": parsed["contacts"][0] if parsed["contacts"] else None,
                "expires": parsed["expires"], "expired": exp,
                "policy": parsed["policy"][0] if parsed["policy"] else None,
                "encryption": (parsed["encryption"][0]
                               if parsed["encryption"] else None),
                "languages": parsed["languages"]}
            c = r["contact"]
            if mail and not c.get("email"):
                c["email"] = mail[7:]
            if web and not c.get("url"):
                c["url"] = web
            if parsed["encryption"] and not c.get("encryption"):
                c["encryption"] = parsed["encryption"][0]
            if parsed["languages"] and not c.get("languages"):
                c["languages"] = parsed["languages"]
            if not c.get("securitytxt"):
                c["securitytxt"] = surl
            if not c.get("source"):
                c["source"] = "securitytxt"
    return stats


# --- bbscope fresh-scope feed ------------------------------------------------
# Cross-platform scope-change firehose. Emitted as scope-updates.jsonl trigger
# lines consumable by change-detect (`detect.py add <program_url>`); programs
# whose program_url matches get fresh_scope_at stamped on their record.

def fetch_scope_updates(url, timeout):
    data = fetch_json(url, timeout)
    return (data.get("updates") or []) if isinstance(data, dict) else []


def main():
    ap = argparse.ArgumentParser(description="Ingest public bug-bounty scope feeds into a normalized program catalog.")
    ap.add_argument("--out-dir", default="./out", help="output directory (default ./out)")
    ap.add_argument("--platforms", default=None,
                    help="comma-separated platform filter, e.g. hackerone,immunefi")
    ap.add_argument("--timeout", type=float, default=30, help="per-fetch timeout seconds (default 30)")
    ap.add_argument("--securitytxt", action="store_true",
                    help="probe /.well-known/security.txt per unique program "
                         "host; fills contact{} and flags lapsed Expires")
    ap.add_argument("--securitytxt-limit", type=int, default=100,
                    help="max distinct hosts to probe (default 100)")
    ap.add_argument("--securitytxt-timeout", type=float, default=10,
                    help="per-host fetch timeout seconds (default 10)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    want = {p.strip().lower() for p in args.platforms.split(",")} if args.platforms else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    programs = {}
    index = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "sources": []}
    for name, platform, url, kind in SOURCES:
        if want and platform not in want:
            continue
        entry = {"source": name, "url": url, "status": "ok", "n_programs": 0}
        try:
            data = fetch_json(url, args.timeout)
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            recs = NORMALIZERS[kind](platform, data, ts, name)
            for r in recs:
                k = dedupe_key(r)
                programs[k] = merge(programs[k], r) if k in programs else r
            entry["n_programs"] = len(recs)
            entry["fetched_at"] = ts
            if kind == "diodb" and recs:
                n_pay = sum(1 for r in recs if r.get("offers_bounty"))
                entry["pay_vs_vdp"] = {
                    "offers_bounty": n_pay,
                    "vdp_only": len(recs) - n_pay,
                    "bounty_fraction": round(n_pay / len(recs), 3)}
            log.info("%s: %d programs", name, len(recs))
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = "%s: %s" % (type(e).__name__, e)
            log.warning("%s fetch failed: %s", name, e)
        index["sources"].append(entry)

    recs = list(programs.values())
    if want:
        recs = [r for r in recs if r["platform"] in want]

    if not want or "bbscope" in want:
        entry = {"source": "bbscope-updates", "url": BBSCOPE_UPDATES,
                 "status": "ok"}
        try:
            updates = fetch_scope_updates(BBSCOPE_UPDATES, args.timeout)
            latest = {}
            lines = []
            for u in updates:
                purl = u.get("program_url")
                ts = u.get("timestamp")
                lines.append({"kind": "scope-change", "type": u.get("type"),
                              "platform": u.get("platform"),
                              "handle": u.get("handle"), "program_url": purl,
                              "target": u.get("target"),
                              "scope_type": u.get("scope_type"),
                              "category": u.get("category"), "at": ts})
                key = (purl or "").lower().rstrip("/")
                if key and (latest.get(key) or "") < (ts or ""):
                    latest[key] = ts
            n_fresh = 0
            for r in recs:
                key = (r.get("url") or "").lower().rstrip("/")
                if key in latest:
                    r["fresh_scope_at"] = latest[key]
                    n_fresh += 1
            with open(out_dir / "scope-updates.jsonl", "w") as f:
                for l in lines:
                    f.write(json.dumps(l, ensure_ascii=False) + "\n")
            entry["n_updates"] = len(lines)
            entry["programs_flagged"] = n_fresh
            log.info("bbscope-updates: %d scope changes, %d programs flagged",
                     len(lines), n_fresh)
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = "%s: %s" % (type(e).__name__, e)
            log.warning("bbscope-updates fetch failed: %s", e)
        index["sources"].append(entry)

    if args.securitytxt:
        index["securitytxt"] = enrich_securitytxt(
            recs, args.securitytxt_limit, args.securitytxt_timeout)
        log.info("securitytxt: %s", index["securitytxt"])

    index["total_programs"] = len(recs)

    (out_dir / "programs.json").write_text(json.dumps(recs, indent=2, ensure_ascii=False) + "\n")

    def sort_key(r):
        mp = r.get("max_payout") or {}
        return -(mp.get("value") or 0)

    def clean(v):
        return str(v).replace("\t", " ").replace("\n", " ") if v is not None else ""

    with open(out_dir / "programs.tsv", "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["platform", "name", "max_payout", "safe_harbor", "n_in_scope", "url"])
        for r in sorted(recs, key=sort_key):
            mp = r.get("max_payout")
            mp_s = "%s %s" % (mp["value"], mp["currency"]) if mp else ""
            sh = {True: "true", False: "false"}.get(r.get("safe_harbor"), "")
            w.writerow([clean(r["platform"]), clean(r["name"]), mp_s, sh,
                        len(r.get("in_scope") or []), clean(r["url"])])

    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")
    n_err = sum(1 for s in index["sources"] if s["status"] != "ok")
    log.info("wrote %d programs to %s (%d source(s) failed)", len(recs), out_dir, n_err)

    flagger = Path(__file__).resolve().parent.parent / "content-scan" / "flag_corpus.py"
    try:
        r = subprocess.run([sys.executable, str(flagger), "--file",
                            str(out_dir / "programs.json")],
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
