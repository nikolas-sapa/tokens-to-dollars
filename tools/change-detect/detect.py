#!/usr/bin/env python3
import argparse
import difflib
import hashlib
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

UA = "tokens-to-dollars-change-detect/1.0 (authorized-scope-only)"
TIMEOUT = 30
TEXT_HINTS = ("text/", "json", "xml", "javascript", "ecmascript", "html", "csv")


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def state_path(tdir):
    return Path(tdir) / "state.json"


def load_state(tdir):
    p = state_path(tdir)
    return json.loads(p.read_text()) if p.is_file() else {"watches": {}}


def save_state(tdir, st):
    Path(tdir).mkdir(parents=True, exist_ok=True)
    state_path(tdir).write_text(json.dumps(st, indent=2, sort_keys=True) + "\n")


def url_key(url):
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def host_allowed(url, allowed):
    """Exact host match only — authorization names assets, never propagates."""
    return (urlparse(url).hostname or "").lower() in {h.lower().lstrip(".") for h in allowed}


class AllowlistRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects to hosts outside the allowlist (skills/safety-gates)."""

    def __init__(self, allowed):
        self.allowed = allowed

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not host_allowed(newurl, self.allowed):
            raise urllib.error.HTTPError(
                newurl, code,
                "redirect to non-allowlisted host: %s" % urlparse(newurl).hostname,
                headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, opener):
    """HEAD-then-GET. HEAD metadata is advisory; the sha256 is over the GET body."""
    meta = {}
    try:
        with opener.open(urllib.request.Request(url, method="HEAD",
                                                headers={"User-Agent": UA}),
                         timeout=TIMEOUT) as r:
            meta["head"] = {"status": r.status,
                            "etag": r.headers.get("ETag"),
                            "last_modified": r.headers.get("Last-Modified"),
                            "content_length": r.headers.get("Content-Length")}
    except Exception as e:
        meta["head_error"] = "%s: %s" % (type(e).__name__, e)
    with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}),
                     timeout=TIMEOUT) as r:
        body = r.read()
        meta["status"] = r.status
        meta["content_type"] = r.headers.get("Content-Type") or ""
        meta["final_url"] = r.geturl()
    return meta, body


def is_text(meta):
    ct = meta.get("content_type", "").lower()
    return any(h in ct for h in TEXT_HINTS)


def store_bodies(tdir, url, body, changed):
    bdir = Path(tdir) / "bodies"
    bdir.mkdir(parents=True, exist_ok=True)
    k = url_key(url)
    cur, prv = bdir / (k + ".cur"), bdir / (k + ".prev")
    if changed and cur.exists():
        cur.replace(prv)
    cur.write_bytes(body)


def do_add(a):
    scheme = urlparse(a.url).scheme.lower()
    if scheme not in ("http", "https"):
        sys.exit("error: only http(s) URLs are watchable, got %s" % a.url)
    st = load_state(a.target)
    if a.url in st["watches"]:
        print(json.dumps({"ok": True, "already_watched": True, "url": a.url}))
        return 0
    st["watches"][a.url] = {"added": utcnow(), "sha256": None, "last_checked": None,
                            "status": "registered"}
    save_state(a.target, st)
    print(json.dumps({"ok": True, "url": a.url}))
    return 0


def write_changes_md(tdir, results, run_ts):
    counts = {"changed": 0, "unchanged": 0, "baseline": 0, "error": 0}
    for r in results.values():
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    out = ["# changes — %s" % run_ts, "",
           "changed: %d   baseline: %d   unchanged: %d   error: %d"
           % (counts["changed"], counts["baseline"], counts["unchanged"], counts["error"]),
           "", "| url | result | sha256 | detail |", "|---|---|---|---|"]
    for url in sorted(results):
        r = results[url]
        out.append("| %s | %s | %s | %s |"
                   % (url, r["result"], (r.get("sha256") or "-")[:12],
                      r.get("error") or ("bytes=%s" % r.get("bytes") if r.get("bytes") is not None else "-")))
    changed = [u for u, r in sorted(results.items()) if r["result"] == "changed"]
    out += ["", "## new-wave candidates"]
    out += ["- %s" % u for u in changed] or ["- none"]
    (Path(tdir) / "changes.md").write_text("\n".join(out) + "\n")


def do_check(a):
    st = load_state(a.target)
    if not st["watches"]:
        sys.exit("error: no watches registered — add <url> first")
    opener = urllib.request.build_opener(AllowlistRedirect(a.only_host))
    results = {}
    for url in sorted(st["watches"]):
        w = st["watches"][url]
        if not host_allowed(url, a.only_host):
            results[url] = {"result": "error",
                            "error": "host %s not in --only-host allowlist" % urlparse(url).hostname}
            continue
        try:
            meta, body = fetch(url, opener)
        except Exception as e:
            w.update({"last_checked": utcnow(), "status": "error"})
            results[url] = {"result": "error", "error": "%s: %s" % (type(e).__name__, e)}
            continue
        digest = hashlib.sha256(body).hexdigest()
        prev = w.get("sha256")
        result = "unchanged" if prev == digest else ("baseline" if prev is None else "changed")
        if a.store_bodies and (result != "unchanged" or not (Path(a.target) / "bodies" / (url_key(url) + ".cur")).exists()):
            store_bodies(a.target, url, body, changed=(result == "changed"))
        w.update({"sha256": digest, "last_checked": utcnow(), "status": result,
                  "content_type": meta["content_type"], "bytes": len(body),
                  "etag": meta.get("head", {}).get("etag"),
                  "last_modified": meta.get("head", {}).get("last_modified")})
        results[url] = {"result": result, "sha256": digest, "bytes": len(body),
                        "head_status": meta.get("head", {}).get("status"),
                        "head_error": meta.get("head_error")}
    st["last_run"] = utcnow()
    save_state(a.target, st)
    write_changes_md(a.target, results, st["last_run"])
    print(json.dumps({"target": str(a.target), "run": st["last_run"],
                      "checked": len(results),
                      "changed": sum(1 for r in results.values() if r["result"] == "changed"),
                      "errors": sum(1 for r in results.values() if r["result"] == "error"),
                      "results": results}, indent=2))
    return 0


def decode_body(raw, content_type):
    for part in (content_type or "").split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            return raw.decode(part.split("=", 1)[1].strip() or "utf-8", "replace")
    return raw.decode("utf-8", "replace")


def do_diff(a):
    st = load_state(a.target)
    bdir = Path(a.target) / "bodies"
    printed = False
    for url in sorted(st["watches"]):
        k = url_key(url)
        prv, cur = bdir / (k + ".prev"), bdir / (k + ".cur")
        if not (prv.is_file() and cur.is_file()):
            continue
        old = decode_body(prv.read_bytes(), st["watches"][url].get("content_type")).splitlines(True)
        new = decode_body(cur.read_bytes(), st["watches"][url].get("content_type")).splitlines(True)
        diff = difflib.unified_diff(old, new, fromfile="previous %s" % url,
                                    tofile="current %s" % url)
        sys.stdout.writelines(diff)
        printed = True
    if not printed:
        print("no stored body pairs — run check with --store-bodies after a change")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Commit-triggered change detector: watch URLs, report what moved "
                    "(feeds the orchestrator's unfinished-chains-first + new-wave triggers).")
    ap.add_argument("--target", required=True, help="state dir (state.json, bodies/, changes.md)")
    ap.add_argument("--store-bodies", action="store_true",
                    help="keep last/current bodies so diff can render unified diffs")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add", help="register a watch URL (no fetch)")
    p.add_argument("url")
    p = sub.add_parser("check", help="refetch all watches; JSON to stdout + changes.md")
    p.add_argument("--only-host", action="append", required=True, metavar="HOST",
                   help="exact host allowed to be fetched; repeatable. Required — no allowlist, no traffic")
    sub.add_parser("diff", help="unified diff of stored bodies (needs --store-bodies checks)")
    args = ap.parse_args()

    return {"add": do_add, "check": do_check, "diff": do_diff}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
