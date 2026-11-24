#!/usr/bin/env python3
import argparse
import csv
import hashlib
import json
import logging
import math
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen

log = logging.getLogger("bounty_radar")
UA = "tokens-to-dollars-bounty-radar/0.2 (+https://github.com/tokens-to-dollars)"
GH = "https://api.github.com"
IMMUNEFI_URL = "https://immunefi.com/public-api/bounties.json"
ALGORA_URL = "https://api.algora.io/v1/bounties"
ALGORA_TRPC = "https://algora.io/api/trpc/bounty.list"
OPIRE_URL = "https://api.opire.dev/rewards"
SHERLOCK_URL = "https://audits.sherlock.xyz/api/contests"
BBSCOPE_URL = "https://bbscope.com/api/v1/updates"
SHERLOCK_MAX_PAGES = 50
SHERLOCK_DEAD = {"FINISHED", "CANCELLED", "ARCHIVED"}
GH_TIMEOUT = 15
PER_PAGE = 40

FAMOUS = {
    "cockroachdb": ["cockroachdb"], "tikv": ["tikv"], "casbin": ["casbin"],
    "apache-pulsar": ["apache"], "apache-apisix": ["apache"],
    "pulsar": ["apache"], "apisix": ["apache"],
    "gofiber": ["gofiber"], "gofiber-fiber": ["gofiber"], "fiber": ["gofiber"],
    "kubernetes": ["kubernetes"], "prometheus": ["prometheus"],
    "grafana": ["grafana"], "redis": ["redis"], "postgres": ["postgres"],
    "vitess": ["vitessio"], "etcd": ["etcd-io"],
}

GH_LABELS = ["💎 Bounty", "bounty", "💰 bounty"]
# polar.sh query removed: the platform has been dead since Apr-25, so the
# issue-body search only surfaced stale links. federacy/issuehunt/c4/
# hackerhive are likewise dead-or-winding-down and are not queried at all.
ESCROW_QUERIES = [
    ('"algora.io/bounties" in:body state:open type:issue', "escrow-link:algora"),
]
TOPIC_QUERIES = [("bug-bounty", "topic:bug-bounty"), ("bounty", "topic:bounty")]

STOP = {
    "the", "a", "an", "of", "for", "and", "in", "on", "to", "bug", "bounty",
    "program", "fix", "issue", "sdk", "core", "app", "api", "protocol",
    "protocols", "defi", "dao", "finance", "labs", "lab", "chain", "contract",
    "contracts", "swap", "token", "tokens", "network", "foundation", "web",
    "v1", "v2", "v3", "v4", "v5", "xyz", "io", "com", "org", "dev", "hq",
    "inc", "pay", "money",
}


def gh_token():
    return os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")


def fetch_json(url, timeout, headers=None):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = Request(url, headers=h)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def gh_headers(accept="application/vnd.github+json"):
    h = {"Accept": accept, "User-Agent": UA}
    tok = gh_token()
    if tok:
        h["Authorization"] = "Bearer %s" % tok
    return h


def search_issues(q, per_page=PER_PAGE):
    url = "%s/search/issues?q=%s&sort=created&order=desc&per_page=%d" % (
        GH, quote(q), per_page)
    try:
        return fetch_json(url, GH_TIMEOUT, gh_headers()).get("items") or []
    except Exception as e:
        code = getattr(getattr(e, "fp", None), "status", None) or getattr(e, "code", None)
        if code == 403:
            raise RuntimeError("GitHub rate limit hit -- set GH_TOKEN") from e
        raise


def search_repos(q, per_page=PER_PAGE):
    url = "%s/search/repositories?q=%s&sort=updated&order=desc&per_page=%d" % (
        GH, quote(q), per_page)
    try:
        return fetch_json(url, GH_TIMEOUT, gh_headers()).get("items") or []
    except Exception as e:
        if getattr(e, "code", None) == 403:
            raise RuntimeError("GitHub rate limit hit -- set GH_TOKEN") from e
        raise


def parse_amount(title, labels):
    m = re.search(r"\$\s?(\d[\d,]*(?:\.\d+)?)\s*(k)?\b",
                  " ".join([title] + labels), re.I)
    if not m:
        return None
    n = float(m.group(1).replace(",", "")) * (1000 if m.group(2) else 1)
    return int(n) if n == int(n) else n


def num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return int(f) if f == int(f) else f


def detect_scam(repo, number, title):
    reasons = []
    owner, _, name = repo.partition("/")
    allowed = FAMOUS.get(name.lower())
    if allowed and owner.lower() not in allowed:
        reasons.append('repo named "%s" but owner "%s" is not the canonical org'
                       % (name, owner))
    if number is not None and number <= 3 and re.match(
            r"(\s*🎯|\s*\[Bug\]|\s*Fix\s)", title, re.I):
        reasons.append("low issue number + generic 'Fix ...' bait title")
    if re.match(r"\s*🎯", title):
        reasons.append("bait-style title")
    return reasons


def days_since(iso):
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return max(0, round((datetime.now(timezone.utc) - t).total_seconds() / 86400))


def first_field(d, *keys):
    for k in keys:
        v = (d or {}).get(k)
        if v not in (None, ""):
            return v
    return None


def iso_from_epoch(v):
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v > 1e12:
        v /= 1000
    return datetime.fromtimestamp(v, timezone.utc).isoformat(timespec="seconds")


def cents_or_amount(v, unit):
    n = num(v)
    if n is None:
        return None
    return round(n / 100, 2) if "CENT" in str(unit or "").upper() else n


# EV fields shared by every draft: program-stat signals (H1-style stats only
# exist on some sources; scoring uses each only when present) plus the
# invite_only / new_scope boosts from the wave-11 EV research.
def ev_draft(source):
    return {
        "repo": "", "number": None, "title": "", "url": "",
        "created_at": None, "comments": 0, "labels": [],
        "amount_usd": None, "max_reward": None, "avg_bounty": None,
        "source": source, "escrowed": False, "deadline": None,
        "table_updated_at": None, "severity": None, "language": None,
        "bounties_paid_90d": None, "reports_90d": None,
        "hackers_thanked": None, "time_to_bounty_days": None,
        "informative_rate": None, "invite_only": False, "new_scope": False,
        "signals": {"linked_prs": 0, "reactions": 0, "source_notes": []},
        "funding_hint": None, "trust": "likely_real", "scam_reasons": [],
        "cross_listed": False,
    }


# --- GitHub drafts -----------------------------------------------------------

def gh_issue_to_draft(it, source="github", note=None, escrowed=False):
    repo = "/".join(it.get("repository_url", "").split("/")[-2:])
    labels = [l.get("name") for l in it.get("labels") or [] if l.get("name")]
    reasons = detect_scam(repo, it.get("number"), it.get("title") or "")
    notes = [note] if note else []
    d = ev_draft(source)
    d.update({
        "repo": repo, "number": it.get("number"),
        "title": it.get("title") or "", "url": it.get("html_url") or "",
        "created_at": it.get("created_at"), "comments": it.get("comments") or 0,
        "labels": labels, "amount_usd": parse_amount(it.get("title") or "", labels),
        "escrowed": escrowed,
        "funding_hint": "escrowed" if escrowed else None,
        "trust": "suspect_scam" if reasons else "likely_real",
        "scam_reasons": reasons,
    })
    d["signals"]["reactions"] = (it.get("reactions") or {}).get("total_count") or 0
    d["signals"]["source_notes"] = notes
    return d


def gh_repo_to_draft(r, note):
    d = ev_draft("github-extras")
    d.update({
        "repo": r.get("full_name") or "",
        "title": r.get("description") or "%s (bug-bounty tagged repo)" % r.get("full_name"),
        "url": r.get("html_url") or "", "created_at": r.get("pushed_at"),
        "labels": r.get("topics") or [],
    })
    d["signals"]["source_notes"] = [note]
    return d


def fetch_github_labels():
    seen, drafts, errs = set(), [], 0
    for lbl in GH_LABELS:
        try:
            items = search_issues('label:"%s" state:open type:issue' % lbl)
        except Exception as e:
            errs += 1
            log.warning("github label query failed (%s): %s", lbl, e)
            continue
        for it in items:
            url = it.get("html_url")
            if url and url not in seen:
                seen.add(url)
                drafts.append(gh_issue_to_draft(it))
    if errs == len(GH_LABELS):
        raise RuntimeError("all GitHub label queries failed (rate limit?)")
    return drafts


def fetch_github_extras():
    by_url = {}
    for q, note in ESCROW_QUERIES:
        try:
            items = search_issues(q)
        except Exception as e:
            log.warning("github-extras query failed (%s): %s", note, e)
            continue
        for it in items:
            url = it.get("html_url")
            if not url:
                continue
            if url in by_url:
                ex = by_url[url]
                notes = ex["signals"]["source_notes"]
                if note not in notes:
                    notes.append(note)
                ex["escrowed"] = True
                ex["funding_hint"] = "escrowed"
                continue
            by_url[url] = gh_issue_to_draft(it, "github-extras", note, escrowed=True)
    for topic, note in TOPIC_QUERIES:
        try:
            for r in search_repos("topic:%s" % topic):
                url = r.get("html_url")
                if url and url not in by_url:
                    by_url[url] = gh_repo_to_draft(r, note)
        except Exception as e:
            log.warning("github-extras repo query failed (%s): %s", note, e)
    return list(by_url.values())


def enrich_linked_prs(drafts, max_issues=15):
    if not gh_token():
        return
    issues = [d for d in drafts
              if d["source"].startswith("github") and d["number"] is not None][:max_issues]
    for d in issues:
        try:
            url = "%s/repos/%s/issues/%s/timeline?per_page=100" % (GH, d["repo"], d["number"])
            events = fetch_json(url, GH_TIMEOUT,
                                gh_headers("application/vnd.github.mockingbird-preview+json"))
            prs = [e for e in events if isinstance(e, dict)
                   and e.get("event") in ("cross-referenced", "referenced")
                   and (((e.get("source") or {}).get("issue") or {}).get("pull_request")
                        or e.get("pull_request"))]
            d["signals"]["linked_prs"] = max(d["signals"]["linked_prs"], len(prs))
        except Exception:
            pass


def repo_bounty_history(repo):
    try:
        data = fetch_json("%s/search/issues?q=%s&per_page=1" % (
            GH, quote("repo:%s state:closed type:issue bounty in:title" % repo)),
            GH_TIMEOUT, gh_headers())
        return (data.get("total_count") or 0) > 0
    except Exception:
        return False  # fail-open: leave funding at "claimed"


# --- Immunefi ----------------------------------------------------------------

# Repo-level githubUrl ("github.com/owner/repo[...]") gives the draft a real
# repo identity so dedupe can merge it with GitHub issue hits. Org-only URLs
# ("github.com/1inch") are ignored: several programs per org would collapse
# into one record.
def gh_repo_from_url(url):
    m = re.match(r"https?://(?:www\.)?github\.com/([^/?#]+)/([^/?#]+)", url or "")
    if not m:
        return None
    return "%s/%s" % (m.group(1), m.group(2))


def fetch_immunefi():
    data = fetch_json(IMMUNEFI_URL, 30)
    drafts = []
    for p in data or []:
        if not isinstance(p, dict) or p.get("isPaused") or p.get("pausedAt"):
            continue
        project = p.get("project") or p.get("slug")
        if not project:
            continue
        tags = []
        for key in ("language", "ecosystem", "programType", "productType"):
            tags += [t for t in p.get(key) or [] if isinstance(t, str)]
        notes = ["invite-only"] if p.get("inviteOnly") else []
        slug = p.get("slug")
        url = "https://immunefi.com/bounties/%s/" % slug if slug else p.get("websiteUrl")
        lang = p.get("language") or []
        d = ev_draft("immunefi")
        d.update({
            "repo": gh_repo_from_url(p.get("githubUrl")) or project,
            "title": "%s -- Immunefi bug bounty" % project,
            "url": url or "", "created_at": p.get("launchDate") or p.get("updatedDate"),
            "labels": sorted(set(tags)),
            "amount_usd": num(p.get("maxBounty")),
            "max_reward": num(p.get("maxBounty")),
            "avg_bounty": num(p.get("averageBounty")) or num(p.get("avgBounty")),
            "escrowed": True,
            "deadline": p.get("endDate"),
            "table_updated_at": p.get("updatedDate"),  # proxy: record changed -> table may have moved
            "language": lang[0] if lang else None,
            "invite_only": bool(p.get("inviteOnly")),
            "funding_hint": "escrowed",
        })
        d["signals"]["source_notes"] = notes
        drafts.append(d)
    return drafts


# --- Keyless escrow / contest platforms --------------------------------------

def algora_items(data):
    if isinstance(data, dict):
        return data.get("items") or data.get("bounties") or []
    if isinstance(data, list):
        for el in data:
            j = (((el or {}).get("result") or {}).get("data") or {}).get("json")
            if isinstance(j, dict):
                return j.get("items") or []
        return data
    return []


def algora_amount(it):
    reward = it.get("reward")
    if isinstance(reward, dict):
        fmt = reward.get("formatted")
        if isinstance(fmt, str):
            m = re.search(r"([\d,]+(?:\.\d+)?)", fmt)
            if m:
                return num(m.group(1).replace(",", ""))
        return cents_or_amount(reward.get("amount"), reward.get("unit"))
    for k in ("reward_cents", "amount", "bounty_amount"):
        if it.get(k) is not None:
            unit = "CENT" if k == "reward_cents" else it.get("unit")
            return cents_or_amount(it.get(k), unit)
    return None


# Algora's documented REST path (api.algora.io/v1/bounties) now redirects and
# 404s — the live public surface is its tRPC router, same call @algora/sdk
# makes. Try REST first, fall back to tRPC; either may legitimately return []
# (the public board has been thin since the payout pivot).
def fetch_algora():
    try:
        items = algora_items(fetch_json(
            "%s?status=active&limit=50" % ALGORA_URL, 20))
    except Exception as e:
        log.info("algora REST endpoint failed (%s); trying tRPC router", e)
        inp = quote('{"0":{"json":{"limit":50}}}')
        items = algora_items(fetch_json(
            "%s?batch=1&input=%s" % (ALGORA_TRPC, inp), 20))
    drafts = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        task = it.get("task") if isinstance(it.get("task"), dict) else it
        url = (first_field(task, "url", "html_url", "github_url", "issue_url")
               or it.get("url") or "")
        if not url:
            continue
        org = (first_field(it.get("org") or {}, "handle", "name")
               or first_field(it.get("organization") or {}, "handle", "name")
               or it.get("org"))
        created = first_field(it, "created_at", "createdAt", "created")
        d = ev_draft("algora")
        d.update({
            "repo": gh_repo_from_url(url) or (str(org) if org else url),
            "number": task.get("number"),
            "title": task.get("title") or it.get("title") or "",
            "url": url,
            "created_at": (created if isinstance(created, str)
                           else iso_from_epoch(created)),
            "amount_usd": algora_amount(it),
            "escrowed": True, "funding_hint": "escrowed",
        })
        d["signals"]["source_notes"] = ["algora-bounty"]
        drafts.append(d)
    return drafts


# Opire rewards are promised rather than provably pre-funded -> funding stays
# "claimed", not "escrowed". Competition mapping: tryingUsers (hunters who
# said they're working it) -> comments proxy; claimerUsers (claimed, i.e.
# an attempt in flight) -> linked_prs proxy.
def fetch_opire():
    data = fetch_json(OPIRE_URL, 20)
    items = data if isinstance(data, list) else (data or {}).get("rewards") or []
    drafts = []
    for it in items:
        if not isinstance(it, dict):
            continue
        url = it.get("url") or ""
        if not url:
            continue
        price = it.get("pendingPrice") or {}
        org = (it.get("organization") or {}).get("name")
        project = it.get("project") or {}
        langs = it.get("programmingLanguages") or []
        d = ev_draft("opire")
        d.update({
            "repo": (gh_repo_from_url(project.get("url") or url)
                     or (str(org) if org else url)),
            "title": it.get("title") or "",
            "url": url,
            "created_at": iso_from_epoch(it.get("createdAt")),
            "comments": len(it.get("tryingUsers") or []),
            "amount_usd": cents_or_amount(price.get("value"), price.get("unit")),
            "language": langs[0] if langs else None,
            "funding_hint": "claimed",
        })
        d["signals"]["linked_prs"] = len(it.get("claimerUsers") or [])
        d["signals"]["source_notes"] = ["opire-reward"]
        drafts.append(d)
    return drafts


# Keyless paginated contest feed ({page, next_page, items}). Prize pools are
# USDC staked up front -> escrowed. A contest that started within 14 days is
# fresh scope -> new_scope EV boost.
def fetch_sherlock():
    drafts = []
    for page in range(1, SHERLOCK_MAX_PAGES + 1):
        data = fetch_json("%s?page=%d" % (SHERLOCK_URL, page), 20)
        items = data.get("items") or []
        for c in items:
            if not isinstance(c, dict):
                continue
            if c.get("private") or c.get("status") in SHERLOCK_DEAD:
                continue
            pool = num(c.get("prize_pool")) or num(c.get("rewards"))
            started = iso_from_epoch(c.get("starts_at"))
            d = ev_draft("sherlock")
            d.update({
                "repo": c.get("title") or "sherlock-contest-%s" % c.get("id"),
                "title": "%s -- Sherlock contest" % c.get("title"),
                "url": "https://audits.sherlock.xyz/contests/%s" % c.get("id"),
                "created_at": started,
                "amount_usd": num(c.get("rewards")) or pool,
                "max_reward": pool,
                "labels": [t for t in (c.get("type_label"), c.get("token")) if t],
                "deadline": iso_from_epoch(c.get("ends_at")),
                "escrowed": True, "funding_hint": "escrowed",
                "new_scope": (days_since(started) or 999) <= 14,
            })
            d["signals"]["source_notes"] = [
                "sherlock-contest:%s" % (c.get("status") or "?").lower()]
            drafts.append(d)
        if not data.get("next_page"):
            break
    return drafts


# bbscope /api/v1/updates = cross-platform scope-change feed (h1/bc/intigriti/
# ywh). program_added entries become draft listings; every update's handle +
# program_url host lands in _BBSCOPE_FRESH so drafts already found via other
# sources get the new_scope boost when their program just changed scope.
_BBSCOPE_FRESH = set()


def fetch_bbscope():
    global _BBSCOPE_FRESH
    _BBSCOPE_FRESH = set()
    data = fetch_json("%s?page=1" % BBSCOPE_URL, 20)
    drafts = []
    for u in data.get("updates") or []:
        if not isinstance(u, dict):
            continue
        host = urlparse(u.get("program_url") or "").netloc.lower()
        for key in (u.get("handle"), host or None):
            if key:
                _BBSCOPE_FRESH.add(str(key).lower())
        if u.get("type") != "program_added" or not u.get("program_url"):
            continue
        d = ev_draft("bbscope")
        d.update({
            "repo": u.get("handle") or u["program_url"],
            "title": "%s -- new program on %s" % (u.get("handle"), u.get("platform")),
            "url": u["program_url"],
            "created_at": u.get("timestamp"),
            "new_scope": True,
            "funding_hint": "claimed",
        })
        d["signals"]["source_notes"] = ["bbscope:%s" % u.get("platform")]
        drafts.append(d)
    return drafts


def mark_fresh_scope(kept):
    if not _BBSCOPE_FRESH:
        return
    for d in kept:
        if d.get("new_scope"):
            continue
        host = urlparse(d.get("url") or "").netloc.lower()
        _, name, _has = repo_parts(d)
        hit = (host in _BBSCOPE_FRESH
               or norm(name) in _BBSCOPE_FRESH
               or norm(d.get("repo")) in _BBSCOPE_FRESH
               or bool(tokens(name) & _BBSCOPE_FRESH))
        if hit:
            d["new_scope"] = True
            d["signals"]["source_notes"].append("fresh-scope:bbscope")


SOURCES = {
    "github": fetch_github_labels,
    "github-extras": fetch_github_extras,
    "immunefi": fetch_immunefi,
    "algora": fetch_algora,
    "opire": fetch_opire,
    "sherlock": fetch_sherlock,
    "bbscope": fetch_bbscope,
}

# --- Dedupe + cross-listing (registry.ts port) -------------------------------

def tokens(s):
    return {t for t in re.split(r"[^a-z0-9]+", (s or "").lower())
            if len(t) > 1 and t not in STOP}


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def repo_parts(d):
    p = (d.get("repo") or "").split("/", 1)
    if len(p) > 1:
        return p[0], p[1], True
    return "", p[0], False


def same_project(a, b, a_tok, b_tok):
    if norm(a.get("repo")) == norm(b.get("repo")):
        return True
    a_o, a_n, a_has = repo_parts(a)
    b_o, b_n, b_has = repo_parts(b)
    if a_has and norm(a_o) == norm(b_n):
        return True
    if b_has and norm(b_o) == norm(a_n):
        return True
    return len(a_tok & b_tok) >= 2


def title_similarity(ta, tb):
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / max(len(ta), len(tb))


def norm_url(u):
    return (u or "").lower().rstrip("/")


def richness(d):
    return ((d.get("amount_usd") is not None) * 4
            + (d.get("max_reward") is not None) * 3
            + (d.get("avg_bounty") is not None) * 2
            + bool(d.get("deadline")) * 2
            + (d.get("number") is not None)
            + min(d.get("comments") or 0, 2))


def merge_fields(keep, lose):
    keep["escrowed"] = keep.get("escrowed") or lose.get("escrowed")
    keep["comments"] = max(keep["comments"], lose["comments"])
    keep["labels"] = sorted(set(keep["labels"]) | set(lose["labels"]))
    keep["scam_reasons"] = sorted(set(keep["scam_reasons"]) | set(lose["scam_reasons"]))
    keep["invite_only"] = keep.get("invite_only") or lose.get("invite_only")
    keep["new_scope"] = keep.get("new_scope") or lose.get("new_scope")
    if lose.get("trust") == "suspect_scam":
        keep["trust"] = "suspect_scam"
    if keep.get("funding_hint") != "escrowed" and lose.get("funding_hint"):
        keep["funding_hint"] = lose["funding_hint"]
    for k in ("deadline", "amount_usd", "max_reward", "avg_bounty", "severity",
              "created_at", "number", "language", "table_updated_at",
              "bounties_paid_90d", "reports_90d", "hackers_thanked",
              "time_to_bounty_days", "informative_rate"):
        if keep.get(k) is None:
            keep[k] = lose.get(k)
    ks, ls = keep["signals"], lose["signals"]
    ks["linked_prs"] = max(ks["linked_prs"], ls["linked_prs"])
    ks["reactions"] = max(ks["reactions"], ls["reactions"])
    ks["source_notes"] = sorted(set(ks["source_notes"]) | set(ls["source_notes"]))


def dedupe_and_flag(drafts):
    valid = [d for d in drafts if isinstance(d.get("url"), str) and d["url"]]
    toks = {}
    for d in valid:
        _, name, _has = repo_parts(d)
        toks[id(d)] = {"name": tokens(name), "title": tokens(d.get("title") or "")}

    def same_bounty(a, b):
        if norm_url(a["url"]) == norm_url(b["url"]):
            return True
        ta, tb = toks[id(a)], toks[id(b)]
        return (same_project(a, b, ta["name"], tb["name"])
                and title_similarity(ta["title"], tb["title"]) >= 0.5)

    merged, merged_from, url_idx = [], {}, {}
    for d in valid:
        u = norm_url(d["url"])
        idx = url_idx.get(u)
        if idx is None:
            idx = next((i for i, m in enumerate(merged) if same_bounty(m, d)), -1)
        if idx == -1:
            merged.append(d)
            merged_from[id(d)] = {d["source"]}
            url_idx[u] = len(merged) - 1
        else:
            prev = merged[idx]
            keep = prev if richness(prev) >= richness(d) else d
            lose = d if keep is prev else prev
            srcs = merged_from.pop(id(prev), {prev["source"]})
            srcs |= merged_from.get(id(d), {d["source"]})
            merge_fields(keep, lose)
            merged[idx] = keep
            merged_from[id(keep)] = srcs
            # title/project-merged drafts never got an exact-url entry —
            # register the incoming url too (and repoint it after a
            # richness swap) or a later draft with this url misses the slot
            url_idx[u] = idx
    for i, m in enumerate(merged):
        srcs = merged_from.get(id(m), {m["source"]})
        if len(srcs) > 1:
            continue
        for j, other in enumerate(merged):
            if i == j:
                continue
            o_srcs = merged_from.get(id(other), {other["source"]})
            if (o_srcs - srcs and same_project(
                    m, other, toks[id(m)]["name"], toks[id(other)]["name"])):
                srcs |= o_srcs
        merged_from[id(m)] = srcs
    for d in merged:
        d["cross_listed"] = len(merged_from.get(id(d), {d["source"]})) > 1
    return merged


# --- Scoring (scoring.ts port + wave-11 EV deltas) ---------------------------
# comments -> up to 40 (4/pt); linked_prs -> up to 36 (12/pr);
# reactions -> up to 8 (2/pt); cross_listed +15; source_notes +2 each cap 10;
# hackers_thanked -> up to 12 (1/25 thanked: big thanked pools = crowded
# hunting ground); freshness <2d +8.

def score_competition(comments, linked_prs, reactions, age_days,
                      cross_listed, source_notes, hackers_thanked=None):
    score = (min(comments * 4, 40) + min(linked_prs * 12, 36)
             + min(reactions * 2, 8) + (15 if cross_listed else 0)
             + min(len(source_notes) * 2, 10)
             + min((hackers_thanked or 0) / 25, 12))
    if age_days is not None and age_days < 2:
        score += 8
    score = max(0, min(100, round(score)))
    band = "high" if score >= 67 else "medium" if score >= 34 else "low"
    return score, band


def classify_funding(d, repo_has_history):
    if d["escrowed"] or d.get("funding_hint") == "escrowed":
        return "escrowed"
    if repo_has_history or d.get("funding_hint") == "verified-history":
        return "verified-history"
    if d.get("amount_usd") is not None or d.get("max_reward") is not None \
            or d.get("funding_hint") == "claimed":
        return "claimed"
    return "unknown"


# EV multipliers (wave-11 radar research). Applied to value_score only when
# the underlying field exists; factors are emitted per record for audit.
#   invite_only x1.15     gated pool -> thinner competition than score shows
#   new_scope   x1.25     fresh attack surface; hunters haven't landed yet
#   time_to_bounty        slow-paying program -> up to 0.5x decay over 365d
#   informative_rate      report-closes-as-informative fraction -> 1-rate, floored 0.4
#   bounty_velocity       paid_90d/reports_90d -> 0.5+v capped 1.3 (pays or starves)
def bounty_velocity_of(d):
    paid, reps = d.get("bounties_paid_90d"), d.get("reports_90d")
    if paid is None or not reps:
        return None
    return round(paid / reps, 3)


def ev_factors(d, velocity):
    f = {}
    if d.get("invite_only"):
        f["invite_only"] = 1.15
    if d.get("new_scope"):
        f["new_scope"] = 1.25
    ttb = d.get("time_to_bounty_days")
    if ttb is not None:
        f["time_to_bounty"] = round(max(0.5, 1 - (ttb or 0) / 365), 3)
    ir = d.get("informative_rate")
    if ir is not None:
        ir = min(1.0, ir / 100 if ir > 1 else ir)
        f["informative_rate"] = round(max(0.4, 1 - ir), 3)
    if velocity is not None:
        f["bounty_velocity"] = round(min(1.3, 0.5 + velocity), 3)
    return f


def to_bounty(d, repo_has_history):
    age = days_since(d.get("created_at"))
    sig = d["signals"]
    score, band = score_competition(
        d["comments"], sig["linked_prs"], sig["reactions"], age,
        d["cross_listed"], sig["source_notes"], d.get("hackers_thanked"))
    # avg_bounty beats max_reward where a source reports real payout means;
    # a headline max is a ceiling, not an expectation.
    reward = (d["amount_usd"] if d["amount_usd"] is not None
              else d.get("avg_bounty") if d.get("avg_bounty") is not None
              else d["max_reward"])
    velocity = bounty_velocity_of(d)
    factors = ev_factors(d, velocity)
    mult = 1.0
    for v in factors.values():
        mult *= v
    return {
        "source": d["source"], "url": d["url"], "title": d["title"],
        "repo": d["repo"], "number": d["number"],
        "reward_usd": reward, "amount_usd": d["amount_usd"],
        "avg_bounty": d.get("avg_bounty"),
        "max_reward": d["max_reward"], "funding": classify_funding(d, repo_has_history),
        "escrowed": d["escrowed"], "competition_score": score,
        "competition_band": band,
        "competition_signals": {
            "comments": d["comments"], "linked_prs": sig["linked_prs"],
            "reactions": sig["reactions"], "age_days": age,
            "cross_listed": d["cross_listed"], "source_notes": sig["source_notes"],
            "hackers_thanked": d.get("hackers_thanked"),
        },
        "bounty_velocity": velocity,
        "invite_only": bool(d.get("invite_only")),
        "new_scope": bool(d.get("new_scope")),
        "time_to_bounty_days": d.get("time_to_bounty_days"),
        "informative_rate": d.get("informative_rate"),
        "ev_factors": factors,
        "scam_flags": d["scam_reasons"], "trust": d["trust"],
        "discovered_at": d["created_at"], "age_days": age,
        "deadline": d["deadline"], "labels": d["labels"],
        "table_updated_at": d.get("table_updated_at"),
        "comments": d["comments"], "cross_listed": d["cross_listed"],
        "language": d["language"], "severity": d["severity"],
        "value_score": round((reward or 0) * (1 - score / 100) * mult, 2),
    }


# --- Reward-table snapshots --------------------------------------------------
# Per-program reward table persisted across runs (one JSON file per program
# under memory/radar-snapshots/). Diffing consecutive snapshots exposes table
# direction: supply is elastic, programs that cut bounties draw ~22% fewer
# reports (~50% fewer criticals), so "down" devalues a record and "up" boosts
# it. TREND_WEIGHT multiplies value_score; the trend is also emitted per
# record and changed tables produce trigger lines (triggers.jsonl) that feed
# change-detect watches via `detect.py add <url>`.

TREND_WEIGHT = {"up": 1.15, "down": 0.78, "flat": 1.0, "new": 1.0}
DEFAULT_SNAPSHOT_DIR = (Path(__file__).resolve().parents[2]
                        / "memory" / "radar-snapshots")


def program_slug(repo):
    s = re.sub(r"[^a-z0-9]+", "-", (repo or "").lower()).strip("-")
    return s or "program-" + hashlib.sha1((repo or "?").encode()).hexdigest()[:8]


def program_table(records):
    tiers = sorted({v for d in records
                    for v in (d.get("amount_usd"), d.get("max_reward"))
                    if v is not None})
    ups = [d["table_updated_at"] for d in records if d.get("table_updated_at")]
    return {"min_reward": tiers[0] if tiers else None,
            "max_reward": tiers[-1] if tiers else None,
            "tiers": tiers,
            "table_updated_at": max(ups) if ups else None,
            "table_hash": hashlib.sha256(
                json.dumps(tiers).encode()).hexdigest()[:16]}


def trend_from(prev, cur):
    pt, ct = set(prev.get("tiers") or []), set(cur["tiers"])
    pmax, cmax = prev.get("max_reward"), cur["max_reward"]
    if pt == ct and pmax == cmax:
        return "flat"
    if pmax is not None and (cmax is None or cmax < pmax):
        return "down"
    if cmax is not None and (pmax is None or cmax > pmax):
        return "up"
    if ct - pt and not pt - ct:
        return "up"
    return "down"  # tiers removed or churned below an unchanged cap


def update_snapshots(kept, snap_dir, run_ts):
    """Diff current reward tables against persisted snapshots; write new ones.

    Runs on deduped records before --min-reward filtering so filtered-out
    tiers don't masquerade as cuts. Returns (slug -> trend, trigger records).
    """
    groups = {}
    for d in kept:
        groups.setdefault(program_slug(d.get("repo")), []).append(d)
    snap_dir = Path(snap_dir)
    snap_dir.mkdir(parents=True, exist_ok=True)
    trends, triggers = {}, []
    for slug, records in groups.items():
        cur = program_table(records)
        path = snap_dir / (slug + ".json")
        prev = None
        if path.is_file():
            try:
                prev = json.loads(path.read_text())
            except (OSError, ValueError) as e:
                log.warning("unreadable snapshot %s: %s -- rebasing", path, e)
        trend = "new" if prev is None else trend_from(prev, cur)
        trends[slug] = trend
        url = records[0].get("url") or ""
        snap = dict(cur)
        snap.update({"program": slug, "url": url,
                     "first_seen": (prev or {}).get("first_seen") or run_ts,
                     "last_seen": run_ts, "reward_trend": trend})
        path.write_text(json.dumps(snap, indent=2, sort_keys=True) + "\n")
        if trend in ("up", "down"):
            triggers.append({
                "kind": "reward-table-change", "direction": trend,
                "program": slug, "url": url,
                "prev": {"max_reward": (prev or {}).get("max_reward"),
                         "table_hash": (prev or {}).get("table_hash")},
                "cur": {"max_reward": cur["max_reward"],
                        "table_hash": cur["table_hash"]},
                "at": run_ts})
            log.info("trigger: reward-table-%s %s %s", trend, slug, url)
    return trends, triggers


# --- program ranking ---------------------------------------------------------
# Reads an ingest-scope catalog (programs.json) and EV-ranks the PROGRAMS
# themselves — which program is worth hunting, before any per-bounty ranking.

def program_ev_factors(r):
    """EV factors for a catalog program record -> {factor_name: multiplier}."""
    f = {}
    if r.get("safe_harbor") is True:
        f["safe_harbor"] = 1.10
    elif r.get("safe_harbor") is False:
        f["safe_harbor"] = 0.80
    scope = r.get("in_scope") or []
    n_scope = len(scope)
    n_wild = sum(1 for t in scope
                 if "*" in str((t or {}).get("target", "")))
    f["scope_breadth"] = round(min(1.30, 0.80 + n_scope * 0.02
                                 + n_wild * 0.10), 3)
    if r.get("offers_bounty") is False:
        f["pay_flag"] = 0.30           # VDP-only: rep grind, not cash
    elif r.get("offers_bounty") is True:
        f["pay_flag"] = 1.00
    else:
        f["pay_flag"] = 0.85           # unknown; small discount
    st = (r.get("policy_url_status") or "").lower()
    sectxt = r.get("securitytxt") or {}
    if st in ("dead", "gone", "404") or sectxt.get("expired") is True:
        f["liveness"] = 0.40           # dead-program detector
    elif st == "community-verified" or "community" in r.get("source", ""):
        f["liveness"] = 1.05
    else:
        f["liveness"] = 1.00
    fresh = r.get("fresh_scope_at") or r.get("launch_date")
    d = days_since(fresh) if fresh else None
    if d is not None and d <= 2:
        f["freshness"] = 1.50          # <48h window: zero prior testing
    elif d is not None and d <= 30:
        f["freshness"] = 1.25
    elif d is not None and d <= 90:
        f["freshness"] = 1.10
    else:
        f["freshness"] = 1.00
    excl = len(r.get("excluded_methods") or [])
    if excl:
        f["method_exclusions"] = round(max(0.7, 1.0 - excl * 0.03), 3)
    return f


def program_score(r):
    payout = (r.get("max_payout") or {}).get("value") or 0
    payout_n = min(1.0, math.log10(1 + payout) / 6)  # $1M+ saturates
    facs = program_ev_factors(r)
    mult = 1.0
    for v in facs.values():
        mult *= v
    return round(100 * payout_n * mult, 2), facs


def rank_programs(catalog_path, out_dir, min_scope=1):
    """Score + rank catalog programs; write programs-ranked.{jsonl,tsv}."""
    recs = json.loads(Path(catalog_path).read_text())
    ranked = []
    for r in recs:
        if len(r.get("in_scope") or []) < min_scope:
            continue
        score, facs = program_score(r)
        scope = r.get("in_scope") or []
        ranked.append({
            "rank_score": score,
            "ev_factors": facs,
            "platform": r.get("platform"),
            "name": r.get("name"),
            "handle": r.get("handle"),
            "url": r.get("url"),
            "max_payout": r.get("max_payout"),
            "safe_harbor": r.get("safe_harbor"),
            "offers_bounty": r.get("offers_bounty"),
            "n_in_scope": len(scope),
            "n_wildcards": sum(1 for t in scope
                               if "*" in str((t or {}).get("target", ""))),
            "n_out_of_scope": len(r.get("out_of_scope") or []),
            "fresh_scope_at": r.get("fresh_scope_at"),
            "launch_date": r.get("launch_date"),
            "dead": bool((r.get("securitytxt") or {}).get("expired")
                         or (r.get("policy_url_status") or "").lower()
                         in ("dead", "gone", "404")),
            "contact": {k: v for k, v in (r.get("contact") or {}).items()
                        if v},
            "policy_url_status": r.get("policy_url_status"),
            "source": r.get("source"),
            "scope_sample": [(t or {}).get("target") for t in scope[:5]],
        })
    ranked.sort(key=lambda x: -x["rank_score"])
    for i, r in enumerate(ranked, 1):
        r["rank"] = i
    with open(out_dir / "programs-ranked.jsonl", "w") as f:
        for r in ranked:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    with open(out_dir / "programs-ranked.tsv", "w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["rank", "score", "platform", "name", "max_payout",
                    "safe_harbor", "n_scope", "wild", "fresh", "dead", "url"])
        for r in ranked:
            mp = r.get("max_payout") or {}
            mp_s = "%s %s" % (mp.get("value"), mp.get("currency")) if mp else ""
            w.writerow([r["rank"], r["rank_score"], r["platform"] or "",
                        (r["name"] or "").replace("\t", " "), mp_s,
                        {True: "yes", False: "no"}.get(r["safe_harbor"], ""),
                        r["n_in_scope"], r["n_wildcards"],
                        r["fresh_scope_at"] or r["launch_date"] or "",
                        "dead" if r["dead"] else "", r["url"] or ""])
    return len(ranked)


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate funded bug bounties (GitHub issues, Immunefi, "
                    "algora/opire/sherlock keyless feeds, bbscope fresh scope), "
                    "scam-filter, competition-score, and EV-rank them.")
    ap.add_argument("--min-reward", type=float, default=None,
                    help="keep bounties with reward_usd >= N")
    ap.add_argument("--max-competition", type=float, default=None,
                    help="keep bounties with competition_score <= N (0-100)")
    ap.add_argument("--sources",
                    default="github,github-extras,immunefi,algora,opire,sherlock,bbscope",
                    help="comma list of: github, github-extras, immunefi, "
                         "algora, opire, sherlock, bbscope")
    ap.add_argument("--include-suspect", action="store_true",
                    help="keep scam-suspect listings (dropped by default)")
    ap.add_argument("--out-dir", default="./out", help="output directory")
    ap.add_argument("--snapshot-dir", default=str(DEFAULT_SNAPSHOT_DIR),
                    help="reward-table snapshot dir (one <program-slug>.json "
                         "per program, diffed against the previous run)")
    ap.add_argument("--teaser", action="store_true",
                    help="also write teaser.txt: ranked numbers with program "
                         "identity masked (shareable without leaking targets)")
    ap.add_argument("--rank-programs", metavar="CATALOG.json",
                    help="program-ranking mode: read an ingest-scope catalog "
                         "(programs.json) and EV-rank the programs "
                         "themselves; writes programs-ranked.{jsonl,tsv}")
    ap.add_argument("--min-scope", type=int, default=1,
                    help="min in_scope rows for --rank-programs (default 1)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s",
                        stream=sys.stderr)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.rank_programs:
        try:
            n = rank_programs(args.rank_programs, out_dir, args.min_scope)
        except Exception as e:
            log.error("rank-programs failed: %s", e)
            return 1
        log.info("ranked %d programs -> %s/programs-ranked.{jsonl,tsv}",
                 n, out_dir)
        return 0

    want = {s.strip().lower() for s in args.sources.split(",") if s.strip()}

    index = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
             "sources": []}
    drafts = []
    for name, fn in SOURCES.items():
        if name not in want:
            continue
        entry = {"source": name, "status": "ok", "n_drafts": 0}
        try:
            got = fn()
            drafts += got
            entry["n_drafts"] = len(got)
            log.info("%s: %d drafts", name, len(got))
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = "%s: %s" % (type(e).__name__, e)
            log.warning("%s failed: %s", name, e)
        index["sources"].append(entry)

    kept = dedupe_and_flag(drafts)
    index["total_drafts"] = len(drafts)
    index["merged_drafts"] = len(kept)

    if not args.include_suspect:
        kept = [d for d in kept if d.get("trust", "likely_real") == "likely_real"]

    mark_fresh_scope(kept)

    trends, triggers = update_snapshots(kept, args.snapshot_dir,
                                        index["generated_at"])

    if args.min_reward is not None:
        kept = [d for d in kept
                if (d["amount_usd"] if d["amount_usd"] is not None
                    else d.get("avg_bounty") if d.get("avg_bounty") is not None
                    else d["max_reward"] or 0) >= args.min_reward]

    enrich_linked_prs(kept)
    history = {}
    if gh_token():
        repos = sorted({d["repo"] for d in kept
                        if d["source"].startswith("github")})[:10]
        history = {r: repo_bounty_history(r) for r in repos}

    out = [to_bounty(d, history.get(d["repo"], False)) for d in kept]
    for b in out:
        trend = trends.get(program_slug(b["repo"]), "new")
        b["reward_trend"] = trend
        b["value_score"] = round(b["value_score"] * TREND_WEIGHT[trend], 2)
    if args.max_competition is not None:
        out = [b for b in out if b["competition_score"] <= args.max_competition]
    out.sort(key=lambda b: (-b["value_score"],
                            b["age_days"] if b["age_days"] is not None else 1e9))

    with open(out_dir / "bounties.jsonl", "w") as f:
        for b in out:
            f.write(json.dumps(b, ensure_ascii=False) + "\n")

    with open(out_dir / "triggers.jsonl", "w") as f:
        for t in triggers:
            f.write(json.dumps(t, ensure_ascii=False) + "\n")

    index["total_bounties"] = len(out)
    index["ranking"] = ("reward_usd(amount|avg|max) * (1 - competition_score/100) "
                        "* ev_factors(invite_only/new_scope/time_to_bounty/"
                        "informative_rate/bounty_velocity) "
                        "* trend_weight(up 1.15 / down 0.78), ties by age asc")
    index["snapshot_dir"] = str(args.snapshot_dir)
    index["table_changes"] = len(triggers)
    index["reward_trends"] = {t: sum(1 for b in out if b["reward_trend"] == t)
                              for t in ("up", "down", "flat", "new")}
    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")

    if args.teaser:
        addr = sum(b["reward_usd"] or 0 for b in out)
        esc = sum(1 for b in out if b["funding"] == "escrowed")
        lines = [
            "bounty-radar teaser — %d bounties ranked, identity masked" % len(out),
            "addressable: $%s | escrowed: %d | generated: %s" % (
                f"{addr:,.0f}", esc, index["generated_at"]),
            "",
            "%-4s %-12s %12s %11s %6s %9s" % (
                "rank", "id", "reward_usd", "competition", "funding", "value"),
            "-" * 60,
        ]
        for i, b in enumerate(out, 1):
            alias = "bty-" + hashlib.sha1(
                (b.get("url") or b["title"]).encode()).hexdigest()[:8]
            lines.append("%-4d %-12s %12s %11s %6s %9.1f" % (
                i, alias,
                f"{b['reward_usd']:,.0f}" if b["reward_usd"] else "-",
                "%.0f" % b["competition_score"], b["funding"],
                b["value_score"]))
        (out_dir / "teaser.txt").write_text("\n".join(lines) + "\n")
        log.info("wrote teaser.txt (%d masked rows)", len(out))
    n_err = sum(1 for s in index["sources"] if s["status"] != "ok")
    log.info("wrote %d bounties to %s (%d source(s) failed)",
             len(out), out_dir, n_err)

    flagger = Path(__file__).resolve().parent.parent / "content-scan" / "flag_corpus.py"
    try:
        r = subprocess.run([sys.executable, str(flagger), "--file",
                            str(out_dir / "bounties.jsonl")],
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
