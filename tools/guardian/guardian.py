#!/usr/bin/env python3
"""guardian.py — action-level adjudicator, the layer behind wrap.py.

wrap.py enforces scope on the *string* of a command line; guardian
adjudicates a proposed ACTION — one http request or one shell invocation —
before dispatch. It is blind by design: it evaluates the action itself,
never the agent's stated reason for it. A hijacked worker can argue;
the action cannot.

Beyond scope gating, Harmless Mode adjudicates the action CLASS
(VenusTech/Ethiack pattern): six high-risk shapes — file_write_delete,
tunneling, dos_shaped, persistence, brute_force, destructive_request —
are denied or escalated even when the target is authorized. A manifest
may allow-list entries per program via harmless_allow (e.g.
"file_write_delete:/uploads/" on a file-upload scope).

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

# ── Harmless Mode — high-risk action taxonomy ─────────────────────────
# Scope gating decides WHERE an action may land; these classes decide
# WHAT the action is. Deny classes are never hunting actions; escalate
# classes have legitimate uses the manifest or a human must bless.
AUTH_ATTEMPT_CAP = 5   # declared credential tries before it stuffs
DOS_RATE_FLOOR = 50    # declared rps that is a flood on any program
DOS_CAP_MULT = 10      # rps this multiple over rps_cap is a flood

# Persistence: scheduled-task/service/startup writes and account
# creation — never a hunting action, so deny.
PERSIST_RE = re.compile(
    r"(?:^|[\s|;&/])(?:crontab|launchctl|schtasks|chkconfig|rc-update"
    r"|update-rc\.d|useradd|adduser|newuser|dscl)\b"
    r"|\bsystemctl\b[^|;&]*\b(?:enable|link|daemon-reload)\b"
    r"|\busermod\b[^|;&]*-G\b|\bnet\s+user\b[^|;&]*/add\b")
PERSIST_PATH_RE = re.compile(
    r"(?:/etc/cron|/var/spool/cron|/etc/init\.d|/etc/rc\.local"
    r"|/etc/systemd|/lib/systemd|/usr/lib/systemd|/etc/profile\.d"
    r"|LaunchAgents|LaunchDaemons|authorized_keys"
    r"|\.bashrc\b|\.bash_profile\b|\.zshrc\b|\.zprofile\b|\.profile\b)")
PERSIST_POS_TOOLS = {"at", "atd", "batch"}  # common-word names: cmd position only

# DoS shapes: flood tools deny outright; burst/loop/resource-exhaustion
# shapes and generic load tools escalate — a rate cap or a human can
# bless them.
DOS_FLOOD_RE = re.compile(
    r"(?:^|[\s|;&/])(?:hping2|hping3|slowloris|slowhttptest|pyloris|t50"
    r"|hulk|goldeneye|xerxes|stress|stress-ng)\b")
DOS_LOAD_RE = re.compile(
    r"(?:^|[\s|;&/])(?:siege|wrk2?|vegeta|bombardier|k6|jmeter|locust"
    r"|gatling|drill|ali)\b")
DOS_POS_TOOLS = {"ab", "hey"}  # short names: cmd position only
SHELL_LOOP_RE = re.compile(
    r"\b(?:while|until)\s[^|&]*\bdo\b|\bfor\s+(?:\w+\s+in|\(\()")
XARGS_BURST_RE = re.compile(r"\bxargs\b[^|;&]*-P\s*0*(?:[2-9]\d|\d{3,})\b")
SEQ_PIPE_RE = re.compile(r"\bseq\b[^|;&]*\|\s*xargs")
YES_PIPE_RE = re.compile(r"\byes\b[^|;&]*\|")
HTTP_CLIENT_RE = re.compile(
    r"\b(?:curl|wget|httpx|nuclei|ffuf|gobuster|dirb|feroxbuster|katana"
    r"|arjun|wfuzz|hydra)\b")

# Tunneling / port-forwarding: forwarding tools and ssh forward flags
# deny; nc-family listeners/exec relays escalate.
TUNNEL_RE = re.compile(
    r"(?:^|[\s|;&/])(?:socat|ngrok|chisel|frpc|frps|cloudflared|bore"
    r"|localtunnel|gost|ligolo(?:-ng)?|stunnel|rinetd|iodine|dnscat2"
    r"|sshuttle|proxifier|proxychains4?|regeorg|tunna)\b")
TUNNEL_POS_TOOLS = {"lt"}
SSH_BIN_RE = re.compile(r"(?:^|[\s|;&/])(?:ssh|autossh|plink)\b")
SSH_FWD_FLAG_RE = re.compile(r"^-[A-Za-z]*[LRDWw][A-Za-z0-9=:,.-]*$")
SSH_FWD_OPT_RE = re.compile(r"^(?:Local|Remote|Dynamic)Forward=")
NC_RE = re.compile(r"(?:^|[\s|;&/])(?:nc|ncat|netcat)\b")
NC_LISTEN_RE = re.compile(
    r"^-[a-z]*[lekc][a-z0-9]*$"
    r"|^--(?:listen|exec|sh-exec|keep-open)")

# Brute force: dedicated credential-attack tools deny; an unbounded or
# stuffing-scale attempt count on a credential-shaped endpoint is
# denied/escalated per its bound.
BRUTE_RE = re.compile(
    r"(?:^|[\s|;&/])(?:hydra|thc-hydra|medusa|ncrack|patator|crowbar"
    r"|brutespray|legba|sucrack)\b")
AUTH_PATH_RE = re.compile(
    r"/(?:login|log[-_]?in|sign[-_]?in|auth|oauth|token|otp|2fa|mfa"
    r"|password|passwd|reset[-_]?password|credentials?|session)\b", re.I)

# Destructive requests: mutating verbs on collection/bulk/account paths
# deny; bare DELETE/PUT elsewhere escalates unless the endpoint is
# manifest-marked via harmless_allow.
MASS_PATH_RE = re.compile(
    r"/(?:bulk|batch|mass)[-_/.]|/(?:users?|accounts?|members?|admins?"
    r"|administrators?|tenants?|teams?|organizations?|orgs?|subscribers?"
    r"|customers?|employees?|groups?|roles?)(?:[/?#.]|$)", re.I)

# File writes/deletes outside the approved workspace (the action's cwd
# plus manifest `workspace` roots): deletes deny, writes escalate.
DEL_OPS = {"rm", "unlink", "rmdir", "srm", "wipe", "shred", "truncate"}
COPY_OPS = {"cp", "mv", "ln", "install", "rsync"}
WRITE_OPS = {"tee", "touch", "mkdir", "patch", "chmod", "chown",
             "chgrp", "dd"}
_ARG_SEP = {";", "&&", "||", "|", "&", ">", ">>", "&>", "<"}
REDIRECT_RE = re.compile(
    r"[>&]{1,2}>?\s*(/[^\s;&|\"'<>]+|~[/\w][^\s;&|\"'<>]*)")
_CMD_PREFIX = {"sudo", "doas", "env", "nice", "nohup", "sh", "bash",
               "zsh", "dash", "xargs"}


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
        ws = m.get("workspace")
        return {"authorized": [x for x in auth if x],
                "denied": [x for x in deny if x],
                "forbidden": [str(x) for x in m.get("forbidden_actions") or []],
                "harmless_allow": [str(x) for x in
                                   m.get("harmless_allow") or []],
                "workspace": ([ws] if isinstance(ws, str)
                              else [str(x) for x in ws or []]),
                "rps_cap": rl.get("rps_cap"),
                "allow_g3": bool(m.get("allow_g3"))}
    base = wrap.parse_manifest(path)
    forbidden, g3, allow, ws = [], False, [], []
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
        elif sec in ("harmless_allow", "workspace") \
                and line.startswith("- "):
            q = re.search(r'"([^"]+)"', line)
            (allow if sec == "harmless_allow" else ws).append(
                q.group(1) if q else line[2:].split("#")[0].strip())
        elif re.match(r"(?i)workspace\s*:", line):
            q = re.search(r'"([^"]+)"', line)
            ws.append(q.group(1) if q else line.split(":", 1)[1].strip())
        elif re.match(r"(?i)(allow_g3|g3|destructive_shell)\s*:"
                      r"\s*(true|yes|allowed|g3)\b", line):
            g3 = True
    return {"authorized": base["authorized"], "denied": base["denied"],
            "forbidden": [x for x in forbidden if x],
            "harmless_allow": [x for x in allow if x],
            "workspace": [x for x in ws if x],
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


def harmless_allowed(mf, cls, detail):
    """A `harmless_allow` entry is "class" or "class:qualifier" — the
    bare name disables the class program-wide; a qualifier disables it
    when the qualifier is "*" or a substring of the hit detail (path
    prefix, METHOD url, tool name)."""
    for ent in mf["harmless_allow"]:
        name, _, qual = str(ent).partition(":")
        if name.strip() != cls:
            continue
        qual = qual.strip()
        if not qual or qual == "*" or qual in detail:
            return True
    return False


def _harmless_pick(checks, mf):
    """First non-allow-listed hit wins; checks arrive in severity order."""
    for cls, v, detail in checks:
        if not harmless_allowed(mf, cls, detail):
            return verdict(v, cls, "harmless-mode %s: %s" % (cls, detail))
    return None


def _cmd_names(argv):
    """Basenames of tokens in command position: argv[0], tokens after a
    shell separator or a prefix command (sudo/env/sh), and the first
    word inside -c payloads. Keeps 'at'-shaped common words from firing
    as tool names mid-argument."""
    names = set()
    seps = _ARG_SEP | _CMD_PREFIX
    for i, tok in enumerate(argv):
        if i == 0 or argv[i - 1] in seps:
            b = os.path.basename(tok).split()[0] if tok.split() else ""
            if b:
                names.add(b)
    for i, tok in enumerate(argv):
        if tok == "-c" and i + 1 < len(argv):
            first = os.path.basename(argv[i + 1].split()[0]
                                     if argv[i + 1].split() else "")
            if first:
                names.add(first)
    return names


def _operands(argv, i):
    """Non-flag tokens following argv[i] up to the next separator or
    recognized file op — the operand run of one command."""
    out = []
    for x in argv[i + 1:]:
        if x in _ARG_SEP or os.path.basename(x) in DEL_OPS | WRITE_OPS \
                | COPY_OPS:
            break
        if not x.startswith("-"):
            out.append(x)
    return out


def _abspath(p):
    return os.path.isabs(os.path.expanduser(p)) or p.startswith("~")


def _eq_path(tok):
    """key=value operands (dd of=/x): the value is the path."""
    return [tok.split("=", 1)[1]] if "=" in tok else [tok]


def _fs_targets(argv):
    """(delete_targets, write_targets): absolute paths an argv removes
    or writes. Relative paths resolve inside the action cwd; /dev/*
    writes are plumbing, not file ops."""
    dels, writes = [], []
    for i, tok in enumerate(argv):
        base = os.path.basename(tok)
        ops = _operands(argv, i)
        if base in DEL_OPS:
            dels += ops
        elif base in COPY_OPS:
            if ops:
                writes.append(ops[-1])  # destination operand only
        elif base == "find" and any(
                x in ("-delete", "--delete") for x in argv[i + 1:]):
            dels += ops
        elif base == "sed" and any(
                x == "-i" or x.startswith("-i") for x in argv[i + 1:]):
            writes += ops
        elif base in ("curl", "wget"):
            for j in range(i + 1, len(argv) - 1):
                if argv[j] in ("-o", "-O", "--output"):
                    writes.append(argv[j + 1])
        elif base in WRITE_OPS:
            writes += ops
    writes += REDIRECT_RE.findall(" ".join(argv))
    dels = [p for t in dels for p in _eq_path(t) if _abspath(p)]
    writes = [p for t in writes for p in _eq_path(t)
              if _abspath(p) and not p.startswith("/dev/")]
    return dels, writes


def _ws_roots(a, mf):
    return [os.path.abspath(os.path.expanduser(r))
            for r in [a.get("cwd")] + list(mf["workspace"])
            if isinstance(r, str) and r]


def _outside(path, roots):
    p = os.path.abspath(os.path.expanduser(path))
    return not any(p == r or p.startswith(r + os.sep) for r in roots)


def harmless_http(a, method, host, mf):
    """High-risk action classes on an http action, checked even when the
    host is authorized. Returns a verdict or None."""
    url = a.get("url") or ""
    checks = []
    if method in MUTATING_METHODS:
        m = MASS_PATH_RE.search(url)
        if m:
            checks.append(("destructive_request", "deny",
                           "%s %s — mass/account-shaped path %r"
                           % (method, url, m.group(0))))
        elif method in ("DELETE", "PUT"):
            checks.append(("destructive_request", "escalate",
                           "%s %s — destructive verb on unmarked endpoint"
                           % (method, url)))
    if method == "POST" and AUTH_PATH_RE.search(url):
        att = a.get("attempts", a.get("max_attempts"))
        if att is None:
            checks.append(("brute_force", "escalate",
                           "credential-shaped POST %s with no attempt "
                           "bound declared" % url))
        else:
            try:
                over = float(att) > AUTH_ATTEMPT_CAP
            except (TypeError, ValueError):
                over = None
            if over is None:
                checks.append(("brute_force", "escalate",
                               "unparseable attempts bound %r on %s"
                               % (att, url)))
            elif over:
                checks.append(("brute_force", "deny",
                               "%s declared attempts on credential path "
                               "%s" % (att, url)))
    cap = mf["rps_cap"] or 1
    rate = a.get("rate", a.get("rps"))
    try:
        r = float(rate) if rate is not None else None
    except (TypeError, ValueError):
        r = None
    if r is not None and r > max(DOS_CAP_MULT * cap, DOS_RATE_FLOOR):
        checks.append(("dos_shaped", "deny",
                       "%s rps on %s is a flood (cap %d)"
                       % (rate, host, cap)))
    return _harmless_pick(checks, mf)


def harmless_shell(a, argv, mf):
    """High-risk action classes on a shell invocation. Returns a verdict
    or None. Ordered persistence > dos > tunneling > brute > file ops —
    the most specific deny wins."""
    s = " ".join(argv)
    cmds = _cmd_names(argv)
    checks = []

    m = PERSIST_RE.search(s)
    pos = cmds & PERSIST_POS_TOOLS
    if m is not None or pos:
        detail = m.group(0).strip() if m else sorted(pos)[0]
        checks.append(("persistence", "deny",
                       "scheduled-task/service/account shape %r" % detail))
    else:
        m = PERSIST_PATH_RE.search(s)
        if m and any(os.path.basename(t) in DEL_OPS | WRITE_OPS | COPY_OPS
                     or REDIRECT_RE.search(t) for t in argv):
            checks.append(("persistence", "deny",
                           "write to startup/service/credential path %r"
                           % m.group(0)))

    if DOS_FLOOD_RE.search(s):
        checks.append(("dos_shaped", "deny",
                       "flood tool in argv: %r"
                       % DOS_FLOOD_RE.search(s).group(0).strip()))
    else:
        burst = (XARGS_BURST_RE.search(s) or YES_PIPE_RE.search(s)
                 or SEQ_PIPE_RE.search(s))
        if burst or (SHELL_LOOP_RE.search(s) and HTTP_CLIENT_RE.search(s)):
            checks.append(("dos_shaped", "escalate",
                           "burst/loop shape %r — unbounded request rate "
                           "or resource exhaustion"
                           % (burst.group(0) if burst else "loop")))
        elif DOS_LOAD_RE.search(s) or cmds & DOS_POS_TOOLS:
            checks.append(("dos_shaped", "escalate",
                           "load-generation tool in argv"))

    m = TUNNEL_RE.search(s)
    pos = cmds & TUNNEL_POS_TOOLS
    if m is not None or pos:
        detail = m.group(0).strip() if m else sorted(pos)[0]
        checks.append(("tunneling", "deny",
                       "port-forward/tunnel tool: %r" % detail))
    elif SSH_BIN_RE.search(s):
        fwd = next((t for t in argv
                    if SSH_FWD_FLAG_RE.match(t) or SSH_FWD_OPT_RE.match(t)),
                   None)
        if fwd:
            checks.append(("tunneling", "deny",
                           "ssh forwarding flag %r" % fwd))
    elif NC_RE.search(s):
        if any(NC_LISTEN_RE.match(t) for t in argv):
            checks.append(("tunneling", "escalate",
                           "nc-family listener/exec relay in argv"))

    m = BRUTE_RE.search(s)
    if m is not None:
        checks.append(("brute_force", "deny",
                       "credential-attack tool: %r" % m.group(0).strip()))

    dels, writes = _fs_targets(argv)
    roots = _ws_roots(a, mf)
    out_d = [p for p in dels if _outside(p, roots)]
    out_w = [p for p in writes if _outside(p, roots)]
    if out_d:
        checks.append(("file_write_delete", "deny",
                       "delete outside approved workspace: %s" % out_d[0]))
    elif out_w:
        checks.append(("file_write_delete", "escalate",
                       "write outside approved workspace: %s" % out_w[0]))

    return _harmless_pick(checks, mf)


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
    hv = harmless_http(a, method, host, mf)
    if hv:
        return hv
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
    hv = harmless_shell(a, argv, mf)
    if hv:
        return hv
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
