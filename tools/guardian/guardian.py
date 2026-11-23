#!/usr/bin/env python3
"""guardian.py — action-level adjudicator, the layer behind wrap.py.

wrap.py enforces scope on the *string* of a command line; guardian
adjudicates a proposed ACTION — one http request or one shell invocation —
before dispatch. It is blind by design: it evaluates the action itself,
never the agent's stated reason for it. A hijacked worker can argue;
the action cannot.

  python3 guardian.py --manifest <roe-manifest.md|json>
                      (--action-file action.json | --stdin) [--json]

action.json shapes:
  {"type": "http",  "method": "GET", "url": "https://h/x",
   "headers": {...}, "body": "...", "rate": 2}
  {"type": "shell", "argv": ["httpx", "-u", "https://h"], "cwd": "/tmp"}

Verdict on stdout. With --json: {"verdict": ..., "rule": ..., "reason"}.
Otherwise one line: "<verdict> [<rule>] <reason>".
Exit codes: 0 = allow, 2 = escalate, 3 = deny. Fail closed: an
unreadable manifest, a malformed action, or an unknown type is a deny —
and anything the adjudicator cannot prove safe is at best an escalate.
"""
import argparse
import importlib.util
import json
import os
import re
import shlex
import sys
from pathlib import Path

# Host extraction, host-vs-pattern matching, and the .md manifest parser
# are delegated to wrap.py — one scope authority, one implementation.
_WRAP_PATH = Path(__file__).resolve().parent.parent / "wrap" / "wrap.py"


def _load_wrap():
    try:
        spec = importlib.util.spec_from_file_location("t2d_wrap", _WRAP_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except (OSError, ImportError, AttributeError):
        return None


wrap = _load_wrap()

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
MUTATING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}

# Carrying these to a host you are not authorized to touch is exfil-shape.
SECRET_HEADERS = {"authorization", "proxy-authorization", "x-api-key",
                  "api-key", "x-auth-token", "x-access-token",
                  "x-secret-key", "cookie"}

# NAME=value where NAME looks secret-bearing: env names in argv or bodies.
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b[a-z_][a-z0-9_]*(?:secret|token|passwd|password|api_?key"
    r"|private_?key|access_?key|credential)[a-z0-9_]*=\S+")

# Destructive shell shapes. Token-level checks (rm flags, dd of=) live in
# destructive_argv(); these match the normalized argv string.
FORK_BOMB_RE = re.compile(r":\(\)\s*\{[^}]*:\s*\|\s*:")
PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:env\s+\S+=\S+\s+)*"
    r"(?:ba|z|fi|da)?sh\b")
MKFS_RE = re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b")
SHRED_RE = re.compile(r"\bshred\b")


def verdict(v, rule, reason):
    return {"verdict": v, "rule": rule, "reason": reason}


def load_manifest(path):
    """Normalize a roe-manifest into {authorized, denied, forbidden,
    rps_cap, allow_g3}. .md goes through wrap.parse_manifest plus a pass
    for guardian-only keys; .json mirrors the same sections. Any read or
    parse failure propagates — the caller fails closed."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if text.lstrip().startswith("{"):
        m = json.loads(text)
        auth, deny = [], []
        for a in m.get("authorized_assets") or []:
            if isinstance(a, str):
                auth.append(a)
            elif isinstance(a, dict):
                if a.get("eligible_for_bounty") is False:
                    deny.append(str(a.get("asset") or ""))
                else:
                    auth.append(str(a.get("asset") or ""))
        for d in m.get("hard_denylist") or []:
            deny.append(str(d.get("pattern") or "" if isinstance(d, dict)
                            else d))
        rl = m.get("rate_limits") or {}
        return {"authorized": [x for x in auth if x],
                "denied": [x for x in deny if x],
                "forbidden": [str(x) for x in m.get("forbidden_actions") or []],
                "rps_cap": rl.get("rps_cap"),
                "allow_g3": bool(m.get("allow_g3"))}
    base = wrap.parse_manifest(path)
    forbidden, g3 = [], False
    sec = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            sec = line[3:].strip().split()[0].lower()
            continue
        if sec == "forbidden_actions" and line.startswith("- "):
            q = re.search(r'"([^"]+)"', line)
            forbidden.append(q.group(1) if q
                             else line[2:].split("#")[0].strip())
        elif re.match(r"(?i)(allow_g3|g3|destructive_shell)\s*:"
                      r"\s*(true|yes|allowed|g3)\b", line):
            g3 = True
    return {"authorized": base["authorized"], "denied": base["denied"],
            "forbidden": [x for x in forbidden if x],
            "rps_cap": base["rps_cap"], "allow_g3": g3}


def scope_of(host, manifest):
    """'denied' | 'authorized' | 'outside' for one candidate host, same
    precedence wrap applies: denylist first (subdomains inherit), then
    authorized assets (exact-only unless the pattern wildcards)."""
    for pat in manifest["denied"]:
        if wrap.match(pat, host, subs=True):
            return "denied"
    if any(wrap.match(p, host, subs=False)
           for p in manifest["authorized"]):
        return "authorized"
    return "outside"


def destructive_argv(argv):
    """Name the destructive shape in argv, or None. Token-level so flag
    order and =-joined forms cannot slip past a string match."""
    s = " ".join(argv)
    if FORK_BOMB_RE.search(s):
        return "fork-bomb"
    if PIPE_TO_SHELL_RE.search(s):
        return "curl|sh-pipe"
    if MKFS_RE.search(s):
        return "mkfs"
    if SHRED_RE.search(s):
        return "shred"
    for i, tok in enumerate(argv):
        base = os.path.basename(tok)
        if base == "dd" and any(x.startswith("of=") for x in argv[i + 1:]):
            return "dd-of"
        if base == "rm":
            shorts = "".join(x[1:] for x in argv[i + 1:]
                             if x.startswith("-") and not x.startswith("--"))
            longs = {x for x in argv[i + 1:] if x.startswith("--")}
            recursive = ("r" in shorts or "R" in shorts
                         or "--recursive" in longs)
            force = "f" in shorts or "--force" in longs
            if recursive and force:
                return "rm-rf"
    return None


def argv_hosts(argv):
    """Candidate hosts in a shell invocation: =-joined flag values, bare
    positional hosts/URLs, host literals inside token text, and every
    literal in positional files. Returns (hosts, targetish, unreadable):
    targetish = an input existed that could carry targets, so under a
    manifest zero extracted hosts is ambiguous, not clean."""
    cands, targetish, unreadable = [], False, []
    for tok in argv:
        if tok.startswith("-"):
            _, eq, val = tok.partition("=")
            if eq:
                targetish = True
                h = wrap.host_of(val)
                if h:
                    cands.append(h)
                else:
                    cands += wrap.HOST_RE.findall(val)
                    cands += wrap.IPV4_RE.findall(val)
            continue
        h = wrap.host_of(tok)
        if h:
            cands.append(h)
            continue
        if os.path.isfile(tok):
            targetish = True
            try:
                cands += wrap.file_hosts(tok)
            except OSError as e:
                unreadable.append("%r: %s" % (tok, e))
        else:
            cands += wrap.HOST_RE.findall(tok)
            cands += wrap.IPV4_RE.findall(tok)
    return cands, targetish, unreadable


def forbidden_hit(manifest, hay):
    h = hay.lower()
    for pat in manifest["forbidden"]:
        if pat and pat.lower() in h:
            return pat
    return None


def secret_in_text(text):
    m = SECRET_ASSIGN_RE.search(text or "")
    return m.group(0) if m else None


def judge_http(a, mf):
    method = str(a.get("method") or "").upper()
    url = a.get("url")
    if not method or not isinstance(url, str) or not url.strip():
        return verdict("deny", "malformed_action",
                       "http action requires non-empty method and url")
    host = wrap.host_of(url)
    if host is None:
        return verdict("escalate", "ambiguous_scope",
                       "cannot derive a target host from url %r" % url)
    headers = a.get("headers") or {}
    if not isinstance(headers, dict):
        return verdict("deny", "malformed_action", "headers must be an object")
    secret_hdrs = sorted(str(k) for k in headers
                         if str(k).lower() in SECRET_HEADERS)
    scope = scope_of(host, mf)
    if scope != "authorized" and secret_hdrs:
        return verdict("deny", "exfil_shape",
                       "secret-bearing headers (%s) to %s host %s"
                       % (", ".join(secret_hdrs), scope, host))
    if scope == "denied":
        return verdict("deny", "denylisted",
                       "host %s matches hard_denylist" % host)
    if scope == "outside":
        note = ("mutating %s to out-of-scope host %s"
                % (method, host) if method in MUTATING_METHODS
                else "host %s not in authorized_assets" % host)
        return verdict("deny", "out_of_scope", note)
    body = a.get("body")
    body_s = body if isinstance(body, str) else json.dumps(body or "")
    hit = secret_in_text(body_s)
    if hit:
        return verdict("deny", "secret_material",
                       "body carries secret-shaped material %r" % hit)
    hit = forbidden_hit(mf, "%s %s" % (method, url))
    if hit:
        return verdict("escalate", "forbidden_action",
                       "action matches manifest forbidden_actions entry %r"
                       % hit)
    if method in SAFE_METHODS:
        return verdict("allow", "in_scope_readonly",
                       "%s on authorized host %s" % (method, host))
    cap = mf["rps_cap"] or 1  # unstated rps -> <=1, per scope-parser
    rate = a.get("rate", a.get("rps"))
    if rate is None:
        return verdict("escalate", "mutation_rate",
                       "state-mutating %s on in-scope %s with no declared "
                       "rate; cannot prove <= rps_cap %d" % (method, host, cap))
    try:
        over = float(rate) > cap
    except (TypeError, ValueError):
        return verdict("deny", "malformed_action",
                       "unparseable rate %r" % (rate,))
    if over:
        return verdict("escalate", "mutation_rate",
                       "state-mutating %s at %s rps exceeds rps_cap %d "
                       "on %s" % (method, rate, cap, host))
    return verdict("allow", "in_scope_mutation",
                   "%s on authorized host %s within rps_cap %d"
                   % (method, host, cap))


def judge_shell(a, mf):
    argv = a.get("argv")
    if isinstance(argv, str):
        try:
            argv = shlex.split(argv)
        except ValueError:
            argv = []
    if (not isinstance(argv, list) or not argv
            or not all(isinstance(x, str) for x in argv)):
        return verdict("deny", "malformed_action",
                       "shell action requires a non-empty argv list")
    s = " ".join(argv)
    hit = secret_in_text(s)
    if hit:
        return verdict("deny", "secret_material",
                       "argv carries secret-shaped material %r" % hit)
    killer = destructive_argv(argv)
    if killer and not mf["allow_g3"]:
        return verdict("deny", "destructive_shell",
                       "destructive shape %r; manifest does not allow G3"
                       % killer)
    cands, targetish, unreadable = argv_hosts(argv)
    if unreadable:
        return verdict("escalate", "ambiguous_scope",
                       "cannot scope-check unreadable file arg(s): %s"
                       % "; ".join(unreadable))
    for h in cands:
        if scope_of(h, mf) == "denied":
            return verdict("deny", "denylisted",
                           "argv host %s matches hard_denylist" % h)
    outside = [h for h in cands if scope_of(h, mf) == "outside"]
    if outside:
        return verdict("deny", "out_of_scope",
                       "argv host(s) not in authorized_assets: %s"
                       % ", ".join(sorted(set(outside))))
    hit = forbidden_hit(mf, s)
    if hit:
        return verdict("escalate", "forbidden_action",
                       "argv matches manifest forbidden_actions entry %r"
                       % hit)
    if killer:  # destructive but manifest opted into G3: still never silent
        return verdict("escalate", "g3_destructive",
                       "destructive shape %r permitted by manifest G3; "
                       "confirm before dispatch" % killer)
    if cands:
        return verdict("allow", "in_scope_argv",
                       "all argv hosts authorized: %s"
                       % ", ".join(sorted(set(cands))))
    if targetish:
        return verdict("escalate", "ambiguous_scope",
                       "target-bearing args present but no hosts could be "
                       "extracted; scope unverifiable")
    return verdict("allow", "safe_argv", "no remote targets in argv")


def judge(action, mf):
    t = action.get("type")
    if t == "http":
        return judge_http(action, mf)
    if t == "shell":
        return judge_shell(action, mf)
    return verdict("deny", "unknown_type", "unknown action type %r" % (t,))


def main(argv):
    ap = argparse.ArgumentParser(prog="guardian.py")
    ap.add_argument("--manifest", required=True,
                    help="roe-manifest (.md from skills/scope-parser, or .json)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--action-file", help="action JSON to adjudicate")
    src.add_argument("--stdin", action="store_true",
                     help="read the action JSON from stdin")
    ap.add_argument("--json", action="store_true",
                    help="emit the verdict as a JSON object")
    a = ap.parse_args(argv)

    if wrap is None:
        v = verdict("deny", "scope_engine_unavailable",
                    "cannot load scope logic from %s" % _WRAP_PATH)
        return emit(v, a.json)

    try:
        mf = load_manifest(a.manifest)
    except (OSError, ValueError, KeyError) as e:
        v = verdict("deny", "manifest_unreadable",
                    "cannot load manifest %s: %s" % (a.manifest, e))
        return emit(v, a.json)

    try:
        text = sys.stdin.read() if a.stdin else open(
            a.action_file, encoding="utf-8").read()
        action = json.loads(text)
    except (OSError, ValueError) as e:
        v = verdict("deny", "malformed_action",
                    "cannot read/parse action: %s" % e)
        return emit(v, a.json)
    if not isinstance(action, dict):
        v = verdict("deny", "malformed_action", "action must be an object")
        return emit(v, a.json)

    return emit(judge(action, mf), a.json)


def emit(v, as_json):
    if as_json:
        print(json.dumps(v))
    else:
        print("%s [%s] %s" % (v["verdict"], v["rule"], v["reason"]))
    return {"allow": 0, "escalate": 2, "deny": 3}[v["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
