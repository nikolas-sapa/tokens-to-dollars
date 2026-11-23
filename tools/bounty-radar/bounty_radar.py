#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

log = logging.getLogger("bounty_radar")
UA = "tokens-to-dollars-bounty-radar/0.1 (+https://github.com/tokens-to-dollars)"
GH = "https://api.github.com"
IMMUNEFI_URL = "https://immunefi.com/public-api/bounties.json"
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
ESCROW_QUERIES = [
    ('"algora.io/bounties" in:body state:open type:issue', "escrow-link:algora"),
    ('"polar.sh" in:body state:open type:issue', "escrow-link:polar"),
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


# --- GitHub drafts -----------------------------------------------------------

def gh_issue_to_draft(it, source="github", note=None, escrowed=False):
    repo = "/".join(it.get("repository_url", "").split("/")[-2:])
    labels = [l.get("name") for l in it.get("labels") or [] if l.get("name")]
    reasons = detect_scam(repo, it.get("number"), it.get("title") or "")
    notes = [note] if note else []
    return {
        "repo": repo, "number": it.get("number"),
        "title": it.get("title") or "", "url": it.get("html_url") or "",
        "created_at": it.get("created_at"), "comments": it.get("comments") or 0,
        "labels": labels, "amount_usd": parse_amount(it.get("title") or "", labels),
        "max_reward": None, "source": source, "escrowed": escrowed,
        "deadline": None, "severity": None, "language": None,
        "signals": {"linked_prs": 0,
                    "reactions": (it.get("reactions") or {}).get("total_count") or 0,
                    "source_notes": notes},
        "funding_hint": "escrowed" if escrowed else None,
        "trust": "suspect_scam" if reasons else "likely_real",
        "scam_reasons": reasons, "cross_listed": False,
    }


def gh_repo_to_draft(r, note):
    return {
        "repo": r.get("full_name") or "", "number": None,
        "title": r.get("description") or "%s (bug-bounty tagged repo)" % r.get("full_name"),
        "url": r.get("html_url") or "", "created_at": r.get("pushed_at"),
        "comments": 0, "labels": r.get("topics") or [],
        "amount_usd": None, "max_reward": None, "source": "github-extras",
        "escrowed": False, "deadline": None, "severity": None, "language": None,
        "signals": {"linked_prs": 0, "reactions": 0, "source_notes": [note]},
        "funding_hint": None, "trust": "likely_real", "scam_reasons": [],
        "cross_listed": False,
    }


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
            if it.get("html_url") not in seen:
                seen.add(it["html_url"])
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
                if r.get("html_url") not in by_url:
                    by_url[r["html_url"]] = gh_repo_to_draft(r, note)
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
        drafts.append({
            "repo": gh_repo_from_url(p.get("githubUrl")) or project,
            "number": None,
            "title": "%s -- Immunefi bug bounty" % project,
            "url": url or "", "created_at": p.get("launchDate") or p.get("updatedDate"),
            "comments": 0, "labels": sorted(set(tags)),
            "amount_usd": p.get("maxBounty"), "max_reward": p.get("maxBounty"),
            "source": "immunefi", "escrowed": True,
            "deadline": p.get("endDate"), "severity": None,
            "language": lang[0] if lang else None,
            "signals": {"linked_prs": 0, "reactions": 0, "source_notes": notes},
            "funding_hint": "escrowed", "trust": "likely_real",
            "scam_reasons": [], "cross_listed": False,
        })
    return drafts


SOURCES = {
    "github": fetch_github_labels,
    "github-extras": fetch_github_extras,
    "immunefi": fetch_immunefi,
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
            + bool(d.get("deadline")) * 2
            + (d.get("number") is not None)
            + min(d.get("comments") or 0, 2))


def merge_fields(keep, lose):
    keep["escrowed"] = keep["escrowed"] or lose["escrowed"]
    keep["comments"] = max(keep["comments"], lose["comments"])
    keep["labels"] = sorted(set(keep["labels"]) | set(lose["labels"]))
    keep["scam_reasons"] = sorted(set(keep["scam_reasons"]) | set(lose["scam_reasons"]))
    if lose.get("trust") == "suspect_scam":
        keep["trust"] = "suspect_scam"
    if keep.get("funding_hint") != "escrowed" and lose.get("funding_hint"):
        keep["funding_hint"] = lose["funding_hint"]
    for k in ("deadline", "amount_usd", "max_reward", "severity", "created_at",
              "number", "language"):
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


# --- Scoring (scoring.ts port) ----------------------------------------------
# comments -> up to 40 (4/pt); linked_prs -> up to 36 (12/pr);
# reactions -> up to 8 (2/pt); cross_listed +15; source_notes +2 each cap 10;
# freshness <2d +8.

def score_competition(comments, linked_prs, reactions, age_days,
                      cross_listed, source_notes):
    score = (min(comments * 4, 40) + min(linked_prs * 12, 36)
             + min(reactions * 2, 8) + (15 if cross_listed else 0)
             + min(len(source_notes) * 2, 10))
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


def to_bounty(d, repo_has_history):
    age = days_since(d.get("created_at"))
    sig = d["signals"]
    score, band = score_competition(
        d["comments"], sig["linked_prs"], sig["reactions"], age,
        d["cross_listed"], sig["source_notes"])
    reward = d["amount_usd"] if d["amount_usd"] is not None else d["max_reward"]
    return {
        "source": d["source"], "url": d["url"], "title": d["title"],
        "repo": d["repo"], "number": d["number"],
        "reward_usd": reward, "amount_usd": d["amount_usd"],
        "max_reward": d["max_reward"], "funding": classify_funding(d, repo_has_history),
        "escrowed": d["escrowed"], "competition_score": score,
        "competition_band": band,
        "competition_signals": {
            "comments": d["comments"], "linked_prs": sig["linked_prs"],
            "reactions": sig["reactions"], "age_days": age,
            "cross_listed": d["cross_listed"], "source_notes": sig["source_notes"],
        },
        "scam_flags": d["scam_reasons"], "trust": d["trust"],
        "discovered_at": d["created_at"], "age_days": age,
        "deadline": d["deadline"], "labels": d["labels"],
        "comments": d["comments"], "cross_listed": d["cross_listed"],
        "language": d["language"], "severity": d["severity"],
        "value_score": round((reward or 0) * (1 - score / 100), 2),
    }


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate funded bug bounties (GitHub issues + Immunefi), "
                    "scam-filter, competition-score, and value-rank them.")
    ap.add_argument("--min-reward", type=float, default=None,
                    help="keep bounties with reward_usd >= N")
    ap.add_argument("--max-competition", type=float, default=None,
                    help="keep bounties with competition_score <= N (0-100)")
    ap.add_argument("--sources", default="github,github-extras,immunefi",
                    help="comma list of: github, github-extras, immunefi")
    ap.add_argument("--include-suspect", action="store_true",
                    help="keep scam-suspect listings (dropped by default)")
    ap.add_argument("--out-dir", default="./out", help="output directory")
    ap.add_argument("--teaser", action="store_true",
                    help="also write teaser.txt: ranked numbers with program "
                         "identity masked (shareable without leaking targets)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s",
                        stream=sys.stderr)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
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
    if args.min_reward is not None:
        kept = [d for d in kept
                if (d["amount_usd"] if d["amount_usd"] is not None
                    else d["max_reward"] or 0) >= args.min_reward]

    enrich_linked_prs(kept)
    history = {}
    if gh_token():
        repos = sorted({d["repo"] for d in kept
                        if d["source"].startswith("github")})[:10]
        history = {r: repo_bounty_history(r) for r in repos}

    out = [to_bounty(d, history.get(d["repo"], False)) for d in kept]
    if args.max_competition is not None:
        out = [b for b in out if b["competition_score"] <= args.max_competition]
    out.sort(key=lambda b: (-b["value_score"],
                            b["age_days"] if b["age_days"] is not None else 1e9))

    with open(out_dir / "bounties.jsonl", "w") as f:
        for b in out:
            f.write(json.dumps(b, ensure_ascii=False) + "\n")

    index["total_bounties"] = len(out)
    index["ranking"] = "reward_usd * (1 - competition_score/100), ties by age asc"
    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n")

    if args.teaser:
        import hashlib
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
