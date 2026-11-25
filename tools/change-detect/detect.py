#!/usr/bin/env python3
import argparse
import difflib
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

UA = "tokens-to-dollars-change-detect/1.1 (authorized-scope-only)"
TIMEOUT = 30
TEXT_HINTS = ("text/", "json", "xml", "javascript", "ecmascript", "html", "csv")

# add <url> [kind] — kind tags let the orchestrator map a trigger to an
# action without re-classifying the watch ("generic" = untagged)
WATCH_KINDS = ("js", "schema", "changelog", "fingerprint", "generic")
ETH_CONDITIONS = ("nonzero-address", "uint-gt", "slippage-auction-activation")
ETH_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,79}$")
ETH_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}$")
ETH_DATA_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*$")
# SlippageAuction v1.0.x selectors: detailsLength() and getLatestAuction().
SLIPPAGE_DETAILS_LENGTH = "0x561ad39f"
SLIPPAGE_GET_LATEST = "0x5f28bc5b"
ZERO_ADDRESS = "0x" + "0" * 40

FEED_KEYWORDS = re.compile(
    r"auth|payment|admin|token|session|oauth|upload|billing|permission", re.I)
CT_LABELS = ("api", "staging", "admin", "dev", "beta")
DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

# Don't-wake gate: a trigger fires only when the change introduces a new
# deploy-shaped token. Sets are diffed (new - old), so minified bundles work.
TOK_HOST = re.compile(r"https?://([a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,63})", re.I)
TOK_ENDPOINT = re.compile(
    r"[\"'`]((?:/(?:api|v\d+|graphql|rpc|internal|admin|auth)[\w./{}$~-]*)"
    r"|(?:/[\w$~-]+){2,}/?)[\"'`]")
TOK_ASSET = re.compile(
    r"[\"'\(\s]((?:https?:)?//[\w.-]+/[\w./~-]*\.(?:js|mjs|json|wasm)"
    r"|(?:/[\w.~-]+)+\.(?:js|mjs|json|wasm))[\"'\)\s]")
TOK_VERSION = re.compile(r"\bv?\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?\b", re.I)
TOK_BUILD = re.compile(
    r"(?:version|build|commit|revision|release)[\"'\s]*[:=][\"'\s]*[\w.-]{3,}", re.I)
# CSS/media/.map/status-text never wakes: tokens ending in these are dropped,
# and pure text churn yields no tokens at all.
NOISE_PATH = re.compile(
    r"\.(css|map|png|jpe?g|gif|svg|webp|ico|avif|woff2?|ttf|eot|otf"
    r"|mp4|webm|mp3|wav|pdf|txt|xml)$", re.I)


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


def emit_trigger(tdir, rec):
    """Append one trigger line to triggers.jsonl; ts is stamped here so every
    producer emits the same {kind, url, signal, ts} envelope."""
    rec = dict(rec)
    rec["ts"] = utcnow()
    Path(tdir).mkdir(parents=True, exist_ok=True)
    with (Path(tdir) / "triggers.jsonl").open("a") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")
    return rec


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


def valid_eth_data(data):
    return bool(data) and ETH_DATA_RE.match(data) is not None


def eth_rpc(rpc_url, method, params, opener):
    """One JSON-RPC POST. Callers restrict this to read-only methods."""
    payload = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "method": method, "params": params}).encode()
    req = urllib.request.Request(
        rpc_url, data=payload, method="POST",
        headers={"User-Agent": UA, "Content-Type": "application/json",
                 "Accept": "application/json"})
    with opener.open(req, timeout=TIMEOUT) as r:
        out = json.loads(r.read().decode("utf-8", "replace"))
    if out.get("error") is not None:
        raise ValueError("rpc error: %s" % json.dumps(out["error"], sort_keys=True)[:240])
    if "result" not in out:
        raise ValueError("rpc response missing result")
    return out["result"]


def eth_call(rpc_url, contract, data, opener):
    result = eth_rpc(rpc_url, "eth_call",
                     [{"to": contract, "data": data}, "latest"], opener)
    if not isinstance(result, str) or not valid_eth_data(result):
        raise ValueError("invalid eth_call result")
    return result


def eth_chain_id(rpc_url, opener):
    result = eth_rpc(rpc_url, "eth_chainId", [], opener)
    if not isinstance(result, str) or not result.startswith("0x"):
        raise ValueError("invalid eth_chainId result")
    return int(result, 16)


def abi_word(result, index):
    if not valid_eth_data(result):
        raise ValueError("invalid ABI hex")
    raw = result[2:]
    end = (index + 1) * 64
    if len(raw) < end:
        raise ValueError("short ABI result: need word %d, got %d bytes"
                         % (index, len(raw) // 2))
    return int(raw[index * 64:end], 16)


def abi_address(result):
    return "0x%040x" % (abi_word(result, 0) & ((1 << 160) - 1))


def parse_int_auto(value):
    return int(str(value), 0)


def snapshot_detail(snapshot):
    if "value" in snapshot:
        return "value=%s" % snapshot["value"]
    return ("details_length=%s active=%s amount_left=%s expiry=%s"
            % (snapshot.get("details_length"), snapshot.get("active"),
               snapshot.get("amount_left"), snapshot.get("expiry")))


def eval_eth_watch(w, opener):
    """Evaluate one on-chain watch using read-only eth_call. Returns the
    activation snapshot plus edge-transition booleans; does not mutate state."""
    cond = w["condition"]
    rpc_url, contract = w["rpc"], w["contract"]
    if cond == "nonzero-address":
        value = abi_address(eth_call(rpc_url, contract, w["data"], opener))
        active = value.lower() != ZERO_ADDRESS
        snapshot = {"active": active, "value": value}
        signal = "address-became-nonzero"
    elif cond == "uint-gt":
        value = abi_word(eth_call(rpc_url, contract, w["data"], opener), 0)
        threshold = int(w["threshold"])
        active = value > threshold
        snapshot = {"active": active, "value": str(value),
                    "threshold": str(threshold)}
        signal = "uint-threshold-crossed"
    elif cond == "slippage-auction-activation":
        length = abi_word(eth_call(rpc_url, contract, SLIPPAGE_DETAILS_LENGTH, opener), 0)
        latest = eth_call(rpc_url, contract, SLIPPAGE_GET_LATEST, opener)
        active = abi_word(latest, 11) != 0
        snapshot = {"active": active, "details_length": length,
                    "amount_left": str(abi_word(latest, 1)),
                    "expiry": abi_word(latest, 10)}
        signal = "slippage-auction-activated"
    else:
        raise ValueError("unsupported eth condition: %s" % cond)

    prev = w.get("snapshot")
    if prev is None:
        changed = False
        triggered = False
    elif cond == "slippage-auction-activation":
        length_increased = snapshot["details_length"] > int(prev.get("details_length", 0))
        reactivated = snapshot["active"] and not bool(prev.get("active"))
        changed = (length_increased or
                   snapshot["active"] != bool(prev.get("active")))
        # A length increase means an auction started even if it already stopped
        # inside the polling interval; active false->true is the same edge.
        triggered = length_increased or reactivated
    else:
        changed = snapshot["active"] != bool(prev.get("active"))
        triggered = snapshot["active"] and not bool(prev.get("active"))
    return {"snapshot": snapshot, "changed": changed,
            "triggered": triggered, "signal": signal}


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


def signal_tokens(text):
    """Deploy-shaped tokens in a body. Media/.map/css paths are noise and
    never count; pure text churn yields no tokens."""
    toks = {"new-host": {m.group(1).lower() for m in TOK_HOST.finditer(text)},
            "new-endpoint": set(), "new-asset-url": set(), "version-bump": set()}
    for m in TOK_ENDPOINT.finditer(text):
        p = m.group(1)
        if not NOISE_PATH.search(p):
            toks["new-endpoint"].add(p)
    for m in TOK_ASSET.finditer(text):
        a = m.group(1)
        if not NOISE_PATH.search(a):
            toks["new-asset-url"].add(a)
    toks["version-bump"] = {m.group(0) for m in TOK_VERSION.finditer(text)}
    toks["version-bump"] |= {m.group(0) for m in TOK_BUILD.finditer(text)}
    return toks


def detect_signals(old, new):
    """Token-set delta old -> new. Returns {signal: [sample tokens]}."""
    o, n = signal_tokens(old), signal_tokens(new)
    return {k: sorted(n[k] - o[k])[:3] for k in n if n[k] - o[k]}


def do_add(a):
    scheme = urlparse(a.url).scheme.lower()
    if scheme not in ("http", "https"):
        sys.exit("error: only http(s) URLs are watchable, got %s" % a.url)
    st = load_state(a.target)
    w = st["watches"].get(a.url)
    if w is not None:
        # re-add with an explicit kind retags; bare `add` never downgrades
        if a.kind != "generic" and w.get("kind") != a.kind:
            w["kind"] = a.kind
            save_state(a.target, st)
        print(json.dumps({"ok": True, "already_watched": True,
                          "url": a.url, "kind": w.get("kind", "generic")}))
        return 0
    st["watches"][a.url] = {"added": utcnow(), "kind": a.kind, "sha256": None,
                            "last_checked": None, "status": "registered"}
    save_state(a.target, st)
    print(json.dumps({"ok": True, "url": a.url, "kind": a.kind}))
    return 0


def do_add_eth(a):
    if ETH_NAME_RE.match(a.name) is None:
        sys.exit("error: eth watch name must be lowercase letters/digits/hyphens")
    if urlparse(a.rpc).scheme.lower() not in ("http", "https"):
        sys.exit("error: rpc must be an http(s) URL")
    if ETH_ADDRESS_RE.match(a.contract) is None:
        sys.exit("error: contract must be a 20-byte hex address")
    try:
        chain_id = parse_int_auto(a.chain_id)
    except ValueError:
        sys.exit("error: chain id must be decimal or 0x-prefixed hex")
    if chain_id <= 0:
        sys.exit("error: chain id must be positive")
    cfg = {"added": utcnow(), "kind": "onchain", "name": a.name,
           "rpc": a.rpc, "chain_id": chain_id,
           "contract": a.contract.lower(), "condition": a.condition,
           "last_checked": None, "status": "registered"}
    if a.condition in ("nonzero-address", "uint-gt"):
        if not a.data or not valid_eth_data(a.data):
            sys.exit("error: --data must be even-length 0x hex for %s" % a.condition)
        cfg["data"] = a.data.lower()
    elif a.data:
        sys.exit("error: --data is implicit for slippage-auction-activation")
    if a.condition == "uint-gt":
        if a.threshold is None:
            sys.exit("error: uint-gt requires --threshold <wei>")
        if a.threshold < 0:
            sys.exit("error: threshold must be non-negative")
        cfg["threshold"] = a.threshold
    elif a.threshold is not None:
        sys.exit("error: --threshold is only valid for uint-gt")

    st = load_state(a.target)
    watches = st.setdefault("eth_watches", {})
    old = watches.get(a.name)
    if old is not None:
        semantic_keys = ("chain_id", "contract", "condition", "data", "threshold")
        if all(old.get(k) == cfg.get(k) for k in semantic_keys):
            # Endpoint replacement must not manufacture a false edge. If the
            # watched object itself changed, the old snapshot is meaningless.
            for key in ("snapshot", "last_checked", "status"):
                if key in old:
                    cfg[key] = old[key]
        cfg["added"] = old.get("added", cfg["added"])
        watches[a.name] = cfg
        save_state(a.target, st)
        print(json.dumps({"ok": True, "updated": True, "eth_watch": a.name,
                          "condition": a.condition}))
        return 0
    watches[a.name] = cfg
    save_state(a.target, st)
    print(json.dumps({"ok": True, "eth_watch": a.name,
                      "condition": a.condition}))
    return 0


def write_changes_md(tdir, results, run_ts, triggers):
    counts = {"changed": 0, "unchanged": 0, "baseline": 0, "error": 0}
    for r in results.values():
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    out = ["# changes — %s" % run_ts, "",
           "changed: %d   baseline: %d   unchanged: %d   error: %d"
           % (counts["changed"], counts["baseline"], counts["unchanged"], counts["error"]),
           "", "| url | result | kind | sha256 | detail |", "|---|---|---|---|---|"]
    for url in sorted(results):
        r = results[url]
        detail = r.get("error") or r.get("gated") or r.get("detail") \
            or ("bytes=%s" % r.get("bytes") if r.get("bytes") is not None else "-")
        out.append("| %s | %s | %s | %s | %s |"
                   % (url, r["result"], r.get("kind") or "-",
                      (r.get("sha256") or "-")[:12], detail))
    changed = [u for u, r in sorted(results.items()) if r["result"] == "changed"]
    out += ["", "## new-wave candidates"]
    out += ["- %s" % u for u in changed] or ["- none"]
    out += ["", "## triggers (also appended to triggers.jsonl)"]
    out += ["- `%s`" % json.dumps(t, sort_keys=True) for t in triggers] or ["- none"]
    (Path(tdir) / "changes.md").write_text("\n".join(out) + "\n")


def do_check(a):
    st = load_state(a.target)
    eth_watches = st.setdefault("eth_watches", {})
    if not st["watches"] and not eth_watches:
        sys.exit("error: no watches registered — add <url> or add-eth first")
    opener = urllib.request.build_opener(AllowlistRedirect(a.only_host))
    results = {}
    triggers = []
    bdir = Path(a.target) / "bodies"
    for url in sorted(st["watches"]):
        w = st["watches"][url]
        kind = w.get("kind", "generic")
        if not host_allowed(url, a.only_host):
            results[url] = {"result": "error", "kind": kind,
                            "error": "host %s not in --only-host allowlist" % urlparse(url).hostname}
            continue
        try:
            meta, body = fetch(url, opener)
        except Exception as e:
            w.update({"last_checked": utcnow(), "status": "error"})
            results[url] = {"result": "error", "kind": kind,
                            "error": "%s: %s" % (type(e).__name__, e)}
            continue
        digest = hashlib.sha256(body).hexdigest()
        prev = w.get("sha256")
        result = "unchanged" if prev == digest else ("baseline" if prev is None else "changed")
        cur = bdir / (url_key(url) + ".cur")
        if result == "changed":
            # Don't-wake gate: a diff of the stored bodies must yield a new
            # endpoint/asset-url/version/host token, else it's content churn.
            old_text = None
            if cur.is_file():
                old_text = decode_body(cur.read_bytes(), w.get("content_type"))
            if old_text is not None:
                sig = detect_signals(old_text,
                                     decode_body(body, meta["content_type"]))
                if sig:
                    triggers.append(emit_trigger(
                        a.target, {"kind": kind, "url": url,
                                   "signal": sorted(sig), "evidence": sig}))
                    results_sig = ",".join(sorted(sig))
                else:
                    results[url] = {"gated": "no deploy signal (content-only change)"}
                    results_sig = None
            elif kind != "generic":
                # no stored body to diff: a tagged watch's hash change is the
                # coarse signal; run with --store-bodies for a precise gate
                triggers.append(emit_trigger(
                    a.target, {"kind": kind, "url": url,
                               "signal": ["content-hash-changed"]}))
                results_sig = "content-hash-changed"
            else:
                results_sig = None
        else:
            results_sig = None
        if a.store_bodies and (result != "unchanged" or not cur.exists()):
            store_bodies(a.target, url, body, changed=(result == "changed"))
        w.update({"sha256": digest, "last_checked": utcnow(), "status": result,
                  "content_type": meta["content_type"], "bytes": len(body),
                  "etag": meta.get("head", {}).get("etag"),
                  "last_modified": meta.get("head", {}).get("last_modified")})
        r = results.setdefault(url, {})
        r.update({"result": result, "kind": kind, "sha256": digest,
                  "bytes": len(body),
                  "head_status": meta.get("head", {}).get("status"),
                  "head_error": meta.get("head_error")})
        if results_sig:
            r["signals"] = results_sig

    chain_ids = {}
    for name in sorted(eth_watches):
        w = eth_watches[name]
        key = "eth:" + name
        kind = "onchain"
        rpc = w.get("rpc", "")
        if not host_allowed(rpc, a.only_host):
            results[key] = {"result": "error", "kind": kind,
                            "error": "host %s not in --only-host allowlist" % urlparse(rpc).hostname}
            continue
        try:
            if rpc not in chain_ids:
                chain_ids[rpc] = eth_chain_id(rpc, opener)
            expected_chain = int(w.get("chain_id", 0))
            if chain_ids[rpc] != expected_chain:
                raise ValueError("chain id mismatch: rpc=%s configured=%s"
                                 % (chain_ids[rpc], expected_chain))
            outcome = eval_eth_watch(w, opener)
        except Exception as e:
            w.update({"last_checked": utcnow(), "status": "error"})
            results[key] = {"result": "error", "kind": kind,
                            "error": "%s: %s" % (type(e).__name__, e)}
            continue
        prev = w.get("snapshot")
        snapshot = outcome["snapshot"]
        result = "baseline" if prev is None else (
            "changed" if outcome["changed"] else "unchanged")
        if outcome["triggered"]:
            triggers.append(emit_trigger(a.target, {
                "kind": kind, "url": rpc, "signal": [outcome["signal"]],
                "watch": name, "contract": w.get("contract"),
                "condition": w.get("condition"),
                "evidence": {"previous": prev, "current": snapshot}}))
        w.update({"snapshot": snapshot, "last_checked": utcnow(),
                  "status": result})
        r = {"result": result, "kind": kind, "contract": w.get("contract"),
             "condition": w.get("condition"), "chain_id": chain_ids[rpc],
             "detail": snapshot_detail(snapshot)}
        if outcome["triggered"]:
            r["signals"] = outcome["signal"]
        results[key] = r
    st["last_run"] = utcnow()
    save_state(a.target, st)
    write_changes_md(a.target, results, st["last_run"], triggers)
    print(json.dumps({"target": str(a.target), "run": st["last_run"],
                      "checked": len(results),
                      "changed": sum(1 for r in results.values() if r["result"] == "changed"),
                      "triggers": len(triggers),
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


def do_poll_ct(a):
    """crt.sh poll: new cert-log names for the domain -> new-subdomain triggers.
    The queried domain must itself be named by --only-host; only the crt.sh
    HTTP host is fetched, redirects off it refused."""
    domain = a.domain.strip().lower().strip(".")
    if not DOMAIN_RE.match(domain):
        sys.exit("error: not a domain: %s" % a.domain)
    if not host_allowed("https://" + domain, a.only_host):
        sys.exit("error: %s not in --only-host allowlist" % domain)
    url = "https://crt.sh/?q=%s&output=json" % quote("%." + domain, safe="")
    opener = urllib.request.build_opener(AllowlistRedirect(["crt.sh"]))
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}),
                         timeout=TIMEOUT) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        sys.exit("error: crt.sh query failed: %s: %s" % (type(e).__name__, e))
    names = set()
    for row in data if isinstance(data, list) else []:
        for n in str(row.get("name_value") or "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n == domain or n.endswith("." + domain):
                names.add(n)
    st = load_state(a.target)
    seen = set(st.setdefault("ct_seen", {}).get(domain, []))
    new = sorted(names - seen)
    st["ct_seen"][domain] = sorted(seen | names)
    st["ct_last_run"] = utcnow()
    save_state(a.target, st)
    for n in new:
        rec = {"kind": "new-subdomain", "url": n, "signal": ["ct-log"]}
        if any(lbl == p or lbl.startswith(p) for lbl in n.split(".") for p in CT_LABELS):
            rec["priority"] = "high"
        emit_trigger(a.target, rec)
    print(json.dumps({"domain": domain, "seen_total": len(seen | names),
                      "new": new,
                      "priority": [n for n in new
                                   if any(lbl == p or lbl.startswith(p)
                                          for lbl in n.split(".") for p in CT_LABELS)]},
                     indent=2))
    return 0


def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(el, name):
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip() or None
    return None


def _child_link(el):
    for c in el:
        if _local(c.tag) == "link":
            return c.get("href") or (c.text or "").strip() or None
    return None


def parse_feed(body):
    """Atom <entry> and RSS <item> -> {id, title, link, summary}, namespace-
    agnostic. Unparseable feeds yield []."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("entry", "item"):
            continue
        title = _child_text(el, "title") or ""
        link = _child_link(el)
        eid = (_child_text(el, "id") or _child_text(el, "guid")
               or link or title)
        summary = (_child_text(el, "summary") or _child_text(el, "description")
                   or _child_text(el, "content") or "")
        if eid:
            out.append({"id": eid, "title": title, "link": link,
                        "summary": summary})
    return out


def do_poll_feed(a):
    """Release/changelog feed poll: new entries are deduped in state.json;
    only keyword-gated entries (auth|payment|admin|token|session|oauth|
    upload|billing|permission) emit kind:changelog triggers."""
    if not host_allowed(a.url, a.only_host):
        sys.exit("error: host %s not in --only-host allowlist"
                 % (urlparse(a.url).hostname or a.url))
    opener = urllib.request.build_opener(AllowlistRedirect(a.only_host))
    try:
        meta, body = fetch(a.url, opener)
    except Exception as e:
        sys.exit("error: feed fetch failed: %s: %s" % (type(e).__name__, e))
    entries = parse_feed(body)
    st = load_state(a.target)
    feeds = st.setdefault("feeds", {})
    seen = set(feeds.get(a.url, []))
    new = [e for e in entries if e["id"] not in seen]
    hits = []
    for e in new:
        kws = sorted({k.lower() for k in
                      FEED_KEYWORDS.findall(e["title"] + " " + e["summary"])})
        if not kws:
            continue
        hits.append(emit_trigger(a.target, {
            "kind": "changelog", "url": a.url,
            "signal": ["keyword:" + k for k in kws],
            "entry": (e["title"] or "")[:160], "link": e["link"]}))
    feeds[a.url] = sorted(seen | {e["id"] for e in entries})
    st["feed_last_run"] = utcnow()
    save_state(a.target, st)
    print(json.dumps({"feed": a.url, "entries": len(entries),
                      "new_entries": len(new), "triggers": hits}, indent=2))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Commit-triggered change detector: watch URLs, report what moved "
                    "(feeds the orchestrator's unfinished-chains-first + new-wave triggers).")
    ap.add_argument("--target", required=True, help="state dir (state.json, bodies/, changes.md, triggers.jsonl)")
    ap.add_argument("--store-bodies", action="store_true",
                    help="keep last/current bodies so diff can render unified diffs "
                         "and the don't-wake gate can extract deploy signals")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add", help="register a watch URL (no fetch)")
    p.add_argument("url")
    p.add_argument("kind", nargs="?", choices=WATCH_KINDS, default="generic",
                   help="watch class the orchestrator maps to an action "
                        "(default generic; re-add with a kind to retag)")
    p = sub.add_parser("add-eth", help="register a read-only eth_call watch (no network)")
    p.add_argument("name", help="lowercase watch id, e.g. frax-custodian-registry")
    p.add_argument("--rpc", required=True, help="http(s) JSON-RPC endpoint")
    p.add_argument("--chain-id", required=True,
                   help="expected chain id, decimal or 0x hex; checked every run")
    p.add_argument("--contract", required=True, help="contract address to eth_call")
    p.add_argument("--condition", required=True, choices=ETH_CONDITIONS,
                   help="nonzero-address: first ABI word is a nonzero address; "
                        "uint-gt: first ABI word crosses --threshold; "
                        "slippage-auction-activation: detailsLength/active edge")
    p.add_argument("--data", help="exact eth_call calldata for nonzero-address/uint-gt")
    p.add_argument("--threshold", type=int,
                   help="wei threshold for uint-gt (strictly greater-than)")
    p = sub.add_parser("check", help="refetch all watches; JSON to stdout + changes.md + triggers.jsonl")
    p.add_argument("--only-host", action="append", required=True, metavar="HOST",
                   help="exact host allowed to be fetched; repeatable. Required — no allowlist, no traffic")
    p = sub.add_parser("poll-ct", help="crt.sh cert-log poll: new subdomains -> triggers.jsonl")
    p.add_argument("domain", help="apex domain to query as %%.domain")
    p.add_argument("--only-host", action="append", required=True, metavar="HOST",
                   help="the queried domain must appear here (repeatable)")
    p = sub.add_parser("poll-feed", help="atom/rss changelog poll: keyword-gated entries -> triggers.jsonl")
    p.add_argument("url", help="releases.atom / changelog feed URL")
    p.add_argument("--only-host", action="append", required=True, metavar="HOST",
                   help="exact host allowed to be fetched; repeatable")
    sub.add_parser("diff", help="unified diff of stored bodies (needs --store-bodies checks)")
    args = ap.parse_args()

    return {"add": do_add, "add-eth": do_add_eth, "check": do_check,
            "diff": do_diff, "poll-ct": do_poll_ct,
            "poll-feed": do_poll_feed}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
