#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import logging
import re
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, \
    urlopen

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
SECTXT_MAX_REDIRECTS = 3
SECTXT_MAX_BYTES = 64 * 1024

# security.txt probes run on hosts named by untrusted third-party feeds —
# the probe must be a public-FQDN, public-IP target or the pass becomes an
# SSRF primitive into intranets/link-local/metadata services.
FQDN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LOCAL_TLDS = {"local", "localhost", "internal", "lan", "corp", "home",
              "localdomain", "invalid", "test", "example", "arpa"}

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


COMMUNITY_FIELDS = {
    "handle", "name", "url", "max_payout", "safe_harbor",
    "in_scope", "out_of_scope", "contact", "launch_date",
    "offers_bounty", "testing_policy_url", "platform",
    "verification", "issue_ref",
}
COMMUNITY_PLATFORMS = {
    "hackerone", "bugcrowd", "intigriti", "yeswehack", "hackenproof",
    "immunefi", "sherlock", "cantina", "independent", "self-hosted",
    "email", "other",
}


def _scope_rows(v):
    rows = []
    for t in v or []:
        if isinstance(t, str):
            rows.append({"target": t, "type": None,
                         "eligible_for_bounty": None, "instruction": None})
        elif isinstance(t, dict):
            rows.append(srow(t))
    return rows


def validate_community_entry(p, idx=None):
    """Return list of error strings for one community submission."""
    tag = "entry[%s]" % (idx if idx is not None else "?")
    errs = []
    if not isinstance(p, dict):
        return ["%s: not an object" % tag]
    extra = set(p) - COMMUNITY_FIELDS
    if extra:
        errs.append("%s: unknown fields %s" % (tag, sorted(extra)))
    name = (p.get("name") or "").strip() if isinstance(p.get("name"), str) else ""
    if not name:
        errs.append("%s: name required" % tag)
    url = p.get("url")
    if not (isinstance(url, str)
            and url.startswith(("https://", "http://"))):
        errs.append("%s: url must be http(s)" % tag)
    plat = (p.get("platform") or "independent")
    if plat not in COMMUNITY_PLATFORMS:
        errs.append("%s: platform %r not in %s"
                    % (tag, plat, sorted(COMMUNITY_PLATFORMS)))
    if not (isinstance(p.get("in_scope"), list) and p["in_scope"]):
        errs.append("%s: in_scope must be a non-empty list" % tag)
    for k in ("in_scope", "out_of_scope"):
        for t in p.get(k) or []:
            if not (isinstance(t, str)
                    or (isinstance(t, dict) and t.get("target"))):
                errs.append("%s: bad %s entry %r" % (tag, k, t))
    mp = p.get("max_payout")
    if mp is not None and not (
            isinstance(mp, (int, float))
            or (isinstance(mp, dict) and mp.get("value") is not None)):
        errs.append("%s: max_payout must be number or {value,currency}" % tag)
    if sh_bool(p.get("safe_harbor")) is None and p.get("safe_harbor") is not None:
        errs.append("%s: safe_harbor must be yes/no/partial/true/false" % tag)
    c = p.get("contact")
    if c is not None and not isinstance(c, dict):
        errs.append("%s: contact must be an object" % tag)
    if not isinstance(p.get("verification"), str) or not p["verification"].strip():
        errs.append("%s: verification text required (source/proof it's real)" % tag)
    return errs


def norm_community(platform, data, ts, source):
    progs = data.get("programs") if isinstance(data, dict) else data
    out = []
    for i, p in enumerate(progs or []):
        errs = validate_community_entry(p, i)
        if errs:
            for e in errs:
                log.warning("community: %s", e)
            continue
        plat = p.get("platform") or platform
        r = base(plat, source, ts)
        r["name"] = p["name"].strip()
        r["handle"] = p.get("handle")
        r["url"] = p["url"]
        r["max_payout"] = payout(p.get("max_payout"),
                                 (p.get("max_payout") or {}).get("currency")
                                 if isinstance(p.get("max_payout"), dict) else "USD")
        r["safe_harbor"] = sh_bool(p.get("safe_harbor"))
        r["in_scope"] = _scope_rows(p.get("in_scope"))
        r["out_of_scope"] = _scope_rows(p.get("out_of_scope"))
        r["testing_policy_url"] = p.get("testing_policy_url") or r["url"]
        c = p.get("contact") or {}
        for k in ("email", "url"):
            if isinstance(c.get(k), str) and c[k].strip():
                r["contact"][k] = c[k].strip()
        if any(r["contact"].values()):
            r["contact"]["source"] = "community"
        r["launch_date"] = p.get("launch_date") or None
        r["offers_bounty"] = sh_bool(p.get("offers_bounty"))
        if r["offers_bounty"] is None:
            r["offers_bounty"] = bool(r["max_payout"])
        r["policy_url_status"] = "community-verified"
        r["securitytxt"] = {"verification": p["verification"].strip(),
                            "issue_ref": p.get("issue_ref")}
        out.append(r)
    return out


NORMALIZERS = {
    "arkadiyt": norm_arkadiyt,
    "lissy93": norm_lissy93,
    "diodb": norm_diodb,
    "immunefi": norm_immunefi,
    "community": norm_community,
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

def fetch_text(url, timeout, opener=None, cap=None):
    req = Request(url, headers={"User-Agent": UA, "Accept": "text/plain,*/*"})
    open_ = opener.open if opener is not None else urlopen
    with open_(req, timeout=timeout) as resp:
        return resp.read(cap).decode("utf-8", "replace")


def public_host(host):
    """A host the security.txt pass may probe: dotted FQDN with a real
    TLD (no IP literals, userinfo smuggles, mDNS/local suffixes) that
    resolves to globally routable addresses only — a feed-named host
    resolving to 10.x/169.254/::1 is an intranet probe, not a program.
    Residual: DNS is re-checked at fetch time, so a fast-rebind between
    this check and urlopen is still possible (TTL-pinning needs a
    resolver-aware fetch — noted for the architecture pass)."""
    h = (host or "").lower().rstrip(".")
    if not FQDN_RE.match(h) or h.rsplit(".", 1)[-1] in LOCAL_TLDS:
        return False
    try:
        infos = socket.getaddrinfo(h, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for fam, _, _, _, sa in infos:
        try:
            ip = ipaddress.ip_address(sa[0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return bool(infos)


class SecTxtRedirect(HTTPRedirectHandler):
    """Redirect cap for the security.txt probe: at most
    SECTXT_MAX_REDIRECTS hops, each target still a public host on the
    same site (apex <-> subdomain). Anything else is an error, not a
    chase — a feed entry redirecting to an intranet is the SSRF this
    pass must not perform."""

    def __init__(self, orig):
        self.orig = (orig or "").lower().rstrip(".")
        self.hops = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops += 1
        h = (urlparse(newurl).hostname or "").lower().rstrip(".")
        if self.hops > SECTXT_MAX_REDIRECTS or not (
                public_host(h)
                and (h == self.orig or h.endswith("." + self.orig)
                     or self.orig.endswith("." + h))):
            raise HTTPError(newurl, code,
                            "securitytxt redirect refused: %s" % h,
                            headers, fp)
        return super().redirect_request(req, fp, code, msg, headers,
                                        newurl)


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
    stats = {"hosts_checked": 0, "found": 0, "expired": 0, "errors": 0,
             "skipped": 0}
    for host, members in sorted(hosts.items())[:limit]:
        if not public_host(host):
            stats["skipped"] += 1
            log.info("securitytxt skip non-public host %r", host)
            continue
        surl = "https://%s%s" % (host, SECTXT_PATH)
        opener = build_opener(SecTxtRedirect(host))
        stats["hosts_checked"] += 1
        try:
            parsed = parse_securitytxt(
                fetch_text(surl, timeout, opener, SECTXT_MAX_BYTES))
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
                    help="comma-separated platform or source-name filter, "
                         "e.g. hackerone,diodb,arkadiyt,immunefi")
    ap.add_argument("--timeout", type=float, default=30, help="per-fetch timeout seconds (default 30)")
    ap.add_argument("--securitytxt", action="store_true",
                    help="probe /.well-known/security.txt per unique program "
                         "host; fills contact{} and flags lapsed Expires")
    ap.add_argument("--securitytxt-limit", type=int, default=100,
                    help="max distinct hosts to probe (default 100)")
    ap.add_argument("--securitytxt-timeout", type=float, default=10,
                    help="per-host fetch timeout seconds (default 10)")
    ap.add_argument("--community-file", default=None,
                    help="JSON file of community-submitted program entries "
                         "(default: community-programs.json next to this script)")
    ap.add_argument("--validate-community", metavar="FILE",
                    help="validate a community-submission JSON file and exit "
                         "(no fetching)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)

    if args.validate_community:
        try:
            data = json.loads(Path(args.validate_community).read_text())
        except Exception as e:
            print("invalid JSON: %s" % e)
            return 1
        progs = data.get("programs") if isinstance(data, dict) else data
        if not isinstance(progs, list):
            print("expected a JSON array (or {\"programs\": [...]})")
            return 1
        errs = []
        for i, p in enumerate(progs):
            errs.extend(validate_community_entry(p, i))
        for e in errs:
            print(e)
        print("%d entries, %d errors" % (len(progs), len(errs)))
        return 1 if errs else 0

    want = {p.strip().lower() for p in args.platforms.split(",")} if args.platforms else None
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    programs = {}
    index = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "sources": []}
    for name, platform, url, kind in SOURCES:
        if (want and platform not in want and name not in want
                and kind not in want):
            continue
        entry = {"source": name, "url": url, "status": "ok", "n_programs": 0}
        try:
            data = fetch_json(url, args.timeout)
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            recs = NORMALIZERS[kind](platform, data, ts, name)
            keys = set()
            for r in recs:
                k = dedupe_key(r)
                keys.add(k)
                programs[k] = merge(programs[k], r) if k in programs else r
            if len(recs) - len(keys) > max(10, len(recs) // 20):
                log.warning("%s: %d of %d records shared a dedupe key; "
                            "merge key may be too loose",
                            name, len(recs) - len(keys), len(recs))
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

    community_file = Path(args.community_file) if args.community_file else (
        Path(__file__).resolve().parent / "community-programs.json")
    if community_file.exists():
        entry = {"source": "community",
                 "url": "file://%s" % community_file,
                 "status": "ok", "n_programs": 0}
        try:
            data = json.loads(community_file.read_text())
            ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
            crecs = norm_community("independent", data, ts, "community")
            for r in crecs:
                if want and r["platform"] not in want and "community" not in want:
                    continue
                k = dedupe_key(r)
                programs[k] = merge(programs[k], r) if k in programs else r
            entry["n_programs"] = len(crecs)
            entry["fetched_at"] = ts
            log.info("community: %d programs", len(crecs))
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = "%s: %s" % (type(e).__name__, e)
            log.warning("community ingest failed: %s", e)
        index["sources"].append(entry)

    recs = list(programs.values())
    if want:
        recs = [r for r in recs
                if r["platform"] in want
                or any(s == w or s.startswith(w + "-")
                       for w in want
                       for s in (r.get("source") or "").split("+"))]

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
