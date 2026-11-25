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
are denied or escalated even when the target is authorized. Only the
hand-written operator override file may allow-list exceptions (e.g.
"file_write_delete:/uploads/" on a file-upload scope); a policy-derived
manifest can tighten scope but never loosen these local gates.

Shell actions are unpacked before adjudication: -c bodies, heredocs,
base64 blobs, and piped scripts are classified on their CONTENT, not
the wrapping argv — a fail-open judge that sees only argv lets scripted
deletes sail through. An unclassifiable payload fails closed (escalate).

Every verdict is appended to the hash-chained audit log
(tools/audit-log, kind "decision") — tamper-evident record of what was
adjudicated. The action's digest is stored, never its body, so denied
secret material does not land in the durable log.

  python3 guardian.py --manifest <roe-manifest.md|json>
                      (--action-file action.json | --stdin) [--json]
                      [--operator-overrides PATH] [--log PATH] [--no-log]

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
import base64
import contextlib
import hashlib
import importlib.util
import json
import math
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

# Decision log is delegated to audit_log.py — one hash chain, one
# implementation. Loaded the same way; a missing log engine warns and
# the adjudicator still runs (logging is not the enforcement path).
_AUDIT_PATH = Path(__file__).resolve().parent.parent / "audit-log" / "audit_log.py"


def _load_audit():
    try:
        spec = importlib.util.spec_from_file_location("t2d_audit", _AUDIT_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except (OSError, ImportError, AttributeError):
        return None


audit_log = _load_audit()
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_LOG = str(_REPO_ROOT / "memory" / "audit.jsonl")
_DEFAULT_OVERRIDES = str(_REPO_ROOT / "memory" / "operator-overrides.md")

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
# classes have legitimate uses the operator or a human must bless.
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
# operator-marked via harmless_allow.
MASS_PATH_RE = re.compile(
    r"/(?:bulk|batch|mass)[-_/.]|/(?:users?|accounts?|members?|admins?"
    r"|administrators?|tenants?|teams?|organizations?|orgs?|subscribers?"
    r"|customers?|employees?|groups?|roles?)(?:[/?#.]|$)", re.I)

# File writes/deletes outside the approved workspace (operator-overrides
# `workspace` roots only): deletes deny, writes escalate. A caller-chosen
# cwd outside those roots is itself untrusted.
DEL_OPS = {"rm", "unlink", "rmdir", "srm", "wipe", "shred", "truncate"}
COPY_OPS = {"cp", "mv", "ln", "install", "rsync"}
WRITE_OPS = {"tee", "touch", "mkdir", "patch", "chmod", "chown",
             "chgrp", "dd"}
_ARG_SEP = {";", "&&", "||", "|", "&", ">", ">>", "&>", "<"}
REDIRECT_RE = re.compile(
    r"[>&]{1,2}>?\s*(/[^\s;&|\"'<>]+|~[/\w][^\s;&|\"'<>]*)")
_CMD_PREFIX = {"sudo", "doas", "env", "nice", "nohup", "sh", "bash",
               "zsh", "dash", "xargs"}

# ── Embedded payloads ─────────────────────────────────────────────────
# A wrapper (bash -c, heredoc, base64, a pipe) can hide a whole script
# from token-level argv checks; the bodies below are unpacked and
# classified like top-level argv.
INTERPRETERS = {"sh", "bash", "zsh", "dash", "fish", "ksh", "python",
                "python2", "python3", "perl", "ruby", "php", "node",
                "lua", "osascript", "pwsh", "powershell"}
B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
# Destructive shapes inside a body string, where tokenization cannot be
# trusted (os.system('rm -rf /') splits into no 'rm' token).
BODY_DESTRUCTIVE_RE = re.compile(
    r"\brm\b\s+(?:-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR])[a-zA-Z]*"
    r"|\bmkfs(?:\.[a-z0-9]+)?\b|\bshred\b|:\(\)\s*\{[^}]*:\s*\|\s*:")

# Trust split: a policy-derived roe-manifest may tighten scope, never loosen
# local execution gates. These keys are valid only in the hand-written
# operator override file.
LOOSENING_KEYS = {"workspace", "harmless_allow", "allow_g3", "g3",
                  "destructive_shell"}
HARMLESS_CLASSES = {"persistence", "tunneling", "dos_shaped", "brute_force",
                    "file_write_delete", "destructive_request"}

POLICY_SECTIONS = {"identity", "authorized_assets", "hard_denylist",
                   "prohibited_methods", "automation_policy", "rate_limits",
                   "safe_harbor", "enforcement", "unknowns",
                   "forbidden_actions"}
POLICY_KEYS = {
    "platform", "program", "policy_url", "url", "fetched_at", "policy_hash",
    "contact", "email", "source", "securitytxt", "encryption", "languages",
    "session", "session_slot", "asset", "type", "eligible_for_bounty",
    "pattern", "method", "blocks", "ceiling", "ai_output", "ai_disclosure",
    "submitter", "rps_cap", "test_accounts", "submission_cost", "notes",
    "status", "disclosure", "embargo_days", "signal_gate",
    "submission_throttle", "idv_required", "trial_quota"}
POLICY_ITEM_KEYS = {
    "authorized_assets": {"asset", "type", "eligible_for_bounty"},
    "hard_denylist": {"pattern"},
    "prohibited_methods": {"method", "blocks", "ceiling"}}
POLICY_JSON_KEYS = {"identity", "authorized_assets", "hard_denylist",
                    "prohibited_methods", "automation_policy", "rate_limits",
                    "safe_harbor", "enforcement", "unknowns",
                    "forbidden_actions"}
POLICY_JSON_OBJECT_KEYS = {
    "identity": {"platform", "program", "policy_url", "fetched_at",
                 "policy_hash", "contact", "session", "session_slot"},
    "automation_policy": {"ai_output", "ai_disclosure", "submitter"},
    "rate_limits": {"rps_cap", "test_accounts", "submission_cost", "notes"},
    "safe_harbor": {"status", "disclosure", "embargo_days"},
    "enforcement": {"signal_gate", "submission_throttle", "idv_required",
                    "trial_quota"}}
POLICY_JSON_LISTS = {"authorized_assets", "hard_denylist",
                     "prohibited_methods", "unknowns", "forbidden_actions"}
CONTACT_KEYS = {"email", "source", "securitytxt", "encryption", "languages"}

OPERATOR_SECTIONS = {"workspace", "harmless_allow", "g3"}
OPERATOR_G3_KEYS = {"allow_g3", "g3", "destructive_shell"}
G3_TRUE = {"1", "true", "yes", "on"}
G3_FALSE = {"0", "false", "no", "off"}

KEY_LINE_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_-]*)\s*:")
INLINE_KEY_RE = re.compile(r"(?:^|\s)([A-Za-z][A-Za-z0-9_-]*)\s*:(?!/)")
QUOTED_RE = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
HEADING_RE = re.compile(r"^(#{2,})\s*(.*)$")


def _md_heading(line):
    m = HEADING_RE.match(line)
    return (len(m.group(1)), m.group(2).strip()) if m else None


def verdict(v, rule, reason):
    return {"verdict": v, "rule": rule, "reason": reason}


def _schema_error(path, lineno, msg):
    if lineno is None:
        raise ValueError("%s: %s" % (path, msg))
    raise ValueError("%s:%d: %s" % (path, lineno, msg))


def _operator_key_error(path, lineno, key):
    _schema_error(path, lineno,
                  "operator-only key %r may not appear in a policy-derived "
                  "manifest" % key)


def _md_value(line, bullet=False):
    q = re.search(r'"([^"]*)"', line)
    if q:
        return q.group(1).strip()
    s = line[2:] if bullet else line.split(":", 1)[1]
    return s.split("#", 1)[0].strip().strip("'").strip('"')


def _strip_unquoted_comment(s):
    out = []
    quote = None
    esc = False
    for ch in s:
        if esc:
            out.append(ch)
            esc = False
            continue
        if quote and ch == "\\":
            out.append(ch)
            esc = True
            continue
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
            continue
        if ch in ("\"", "'"):
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


def _strict_md_value(line, path, lineno, bullet=False):
    """One scalar and nothing else; operator files fail closed on trailing
    tokens that the forgiving manifest reader would have discarded."""
    s = line[2:] if bullet else line.split(":", 1)[1]
    s = _strip_unquoted_comment(s).strip()
    if not s:
        return ""
    if s[0] in ("\"", "'"):
        m = re.fullmatch(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'', s)
        if not m:
            _schema_error(path, lineno, "malformed quoted scalar")
        return (m.group(1) if m.group(1) is not None else m.group(2)).strip()
    return s


def _validate_policy_markdown(text, path):
    """Reject operator-only and unknown schema keys in policy-derived
    markdown. Quoted bullet text is data, so it is stripped before the
    inline-key scan; plaintext prose without a key shape stays inert."""
    sec = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        heading = _md_heading(line)
        if heading:
            level, head = heading
            sec = head.split()[0].lower() if head else ""
            if level != 2 or not sec:
                _schema_error(path, lineno,
                              "malformed manifest section heading")
            if sec in LOOSENING_KEYS:
                _operator_key_error(path, lineno, sec)
            if sec not in POLICY_SECTIONS:
                _schema_error(path, lineno,
                              "unknown manifest section %r" % sec)
            continue
        if line.startswith("#"):
            continue
        m = KEY_LINE_RE.match(line)
        if m:
            key = m.group(1).lower()
            if key in LOOSENING_KEYS:
                _operator_key_error(path, lineno, key)
            if key not in POLICY_KEYS:
                _schema_error(path, lineno, "unknown manifest key %r" % key)
            continue
        if not line.startswith("- "):
            continue
        scan = QUOTED_RE.sub('""', line).split("#", 1)[0]
        for key in [k.lower() for k in INLINE_KEY_RE.findall(scan)]:
            if key in LOOSENING_KEYS:
                _operator_key_error(path, lineno, key)
            if key not in POLICY_KEYS:
                _schema_error(path, lineno,
                              "unknown manifest item key %r" % key)
            allowed = POLICY_ITEM_KEYS.get(sec)
            if allowed is not None and key not in allowed:
                _schema_error(path, lineno,
                              "unknown %s item key %r" % (sec, key))


def _json_object_keys(obj):
    if isinstance(obj, dict):
        for key, val in obj.items():
            yield key
            yield from _json_object_keys(val)
    elif isinstance(obj, list):
        for val in obj:
            yield from _json_object_keys(val)


def _unknown_json_keys(obj, allowed, what, path):
    extra = sorted(set(obj) - allowed)
    if extra:
        _schema_error(path, None, "unknown %s key(s): %s"
                      % (what, ", ".join(extra)))


def _validate_json_list(value, name, path):
    if value is None:
        return []
    if not isinstance(value, list):
        _schema_error(path, None, "%s must be a list" % name)
    return value


def _validate_policy_json(m, path):
    if not isinstance(m, dict):
        _schema_error(path, None, "manifest root must be an object")
    for key in _json_object_keys(m):
        if str(key).lower() in LOOSENING_KEYS:
            _operator_key_error(path, None, key)
    _unknown_json_keys(m, POLICY_JSON_KEYS, "manifest", path)

    for name, allowed in POLICY_JSON_OBJECT_KEYS.items():
        obj = m.get(name)
        if obj is None:
            continue
        if not isinstance(obj, dict):
            _schema_error(path, None, "%s must be an object" % name)
        _unknown_json_keys(obj, allowed, name, path)
    identity = m.get("identity") or {}
    contact = identity.get("contact") if isinstance(identity, dict) else None
    if contact is not None:
        if not isinstance(contact, dict):
            _schema_error(path, None, "identity.contact must be an object")
        _unknown_json_keys(contact, CONTACT_KEYS, "identity.contact", path)

    for name in POLICY_JSON_LISTS:
        _validate_json_list(m.get(name), name, path)
    for item in m.get("authorized_assets") or []:
        if isinstance(item, str):
            continue
        if not isinstance(item, dict):
            _schema_error(path, None,
                          "authorized_assets items must be strings or objects")
        _unknown_json_keys(item, {"asset", "type", "eligible_for_bounty"},
                           "authorized_assets item", path)
        if not isinstance(item.get("asset"), str):
            _schema_error(path, None,
                          "authorized_assets item asset must be a string")
    for item in m.get("hard_denylist") or []:
        if isinstance(item, str):
            continue
        if not isinstance(item, dict):
            _schema_error(path, None,
                          "hard_denylist items must be strings or objects")
        _unknown_json_keys(item, {"pattern"}, "hard_denylist item", path)
        if not isinstance(item.get("pattern"), str):
            _schema_error(path, None,
                          "hard_denylist item pattern must be a string")
    for item in m.get("prohibited_methods") or []:
        if not isinstance(item, dict):
            _schema_error(path, None,
                          "prohibited_methods items must be objects")
        _unknown_json_keys(item, {"method", "blocks", "ceiling"},
                           "prohibited_methods item", path)
    for name in ("unknowns", "forbidden_actions"):
        if any(not isinstance(x, str) for x in m.get(name) or []):
            _schema_error(path, None, "%s items must be strings" % name)
    rps = (m.get("rate_limits") or {}).get("rps_cap")
    if rps is not None:
        try:
            rps_n = float(rps)
        except (TypeError, ValueError):
            rps_n = None
        if isinstance(rps, bool) or rps_n is None \
                or not math.isfinite(rps_n) or rps_n < 0:
            _schema_error(path, None,
                          "rate_limits.rps_cap must be null or a finite "
                          "number >= 0")


def load_operator_overrides(path=None):
    """Load the hand-written local override file. Absence means no
    loosening. The format is deliberately small and strict: workspace /
    harmless_allow entries plus one G3 boolean; unknown keys fail closed."""
    out = {"harmless_allow": [], "workspace": [], "allow_g3": False}
    path = _DEFAULT_OVERRIDES if path is None else path
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return out
    sec = None
    g3_seen = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        heading = _md_heading(line)
        if heading:
            level, head = heading
            sec = head.split()[0].lower() if head else ""
            if level != 2 or not sec:
                _schema_error(path, lineno,
                              "malformed operator-overrides section heading")
            if sec not in OPERATOR_SECTIONS:
                _schema_error(path, lineno,
                              "unknown operator-overrides section %r" % sec)
            continue
        if line.startswith("#"):
            continue
        if line.startswith("- "):
            if sec not in ("workspace", "harmless_allow"):
                _schema_error(path, lineno,
                              "override entries require a workspace or "
                              "harmless_allow section")
            val = _strict_md_value(line, path, lineno, bullet=True)
            if not val:
                _schema_error(path, lineno, "empty %s entry" % sec)
            out[sec].append(val)
            continue
        m = KEY_LINE_RE.match(line)
        if not m:
            _schema_error(path, lineno,
                          "unparseable operator-overrides line")
        key = m.group(1).lower()
        if key in ("workspace", "harmless_allow"):
            if sec not in (None, key):
                _schema_error(path, lineno,
                              "%s key outside its operator-overrides section"
                              % key)
            val = _strict_md_value(line, path, lineno)
            if not val:
                _schema_error(path, lineno, "empty %s value" % key)
            out[key].append(val)
        elif key in OPERATOR_G3_KEYS:
            if sec not in (None, "g3"):
                _schema_error(path, lineno,
                              "%s key outside the g3 section" % key)
            if g3_seen:
                _schema_error(path, lineno,
                              "duplicate G3 operator override")
            g3_seen = True
            val = _strict_md_value(line, path, lineno).lower()
            if val in G3_TRUE:
                out["allow_g3"] = True
            elif val in G3_FALSE:
                out["allow_g3"] = False
            else:
                _schema_error(path, lineno,
                              "G3 override must be true or false; destructive "
                              "shapes can never be allow, only escalate")
        else:
            _schema_error(path, lineno,
                          "unknown operator-overrides key %r" % key)
    for root in out["workspace"]:
        if not os.path.isabs(os.path.expanduser(root)):
            _schema_error(path, None,
                          "workspace root %r must be absolute" % root)
    for ent in out["harmless_allow"]:
        cls = str(ent).partition(":")[0].strip()
        if cls not in HARMLESS_CLASSES:
            _schema_error(path, None,
                          "unknown harmless_allow class %r" % cls)
    return out


def load_policy_manifest(path):
    """Normalize a policy-derived roe-manifest into scope and tightening
    data only. Any operator-only loosening key, unknown key, read failure,
    or parse failure propagates — the caller fails closed."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if text.lstrip().startswith("{"):
        m = json.loads(text)
        _validate_policy_json(m, path)
        auth, deny = [], []
        for a in m.get("authorized_assets") or []:
            if isinstance(a, str):
                auth.append(a)
            elif a.get("eligible_for_bounty") is False:
                deny.append(a.get("asset") or "")
            else:
                auth.append(a.get("asset") or "")
        for d in m.get("hard_denylist") or []:
            deny.append(d.get("pattern") if isinstance(d, dict) else d)
        rl = m.get("rate_limits") or {}
        return {"authorized": [x for x in auth if x],
                "denied": [str(x) for x in deny if x],
                "forbidden": [str(x) for x in m.get("forbidden_actions") or []],
                "harmless_allow": [],
                "workspace": [],
                "rps_cap": rl.get("rps_cap"),
                "allow_g3": False}
    _validate_policy_markdown(text, path)
    base = wrap.parse_manifest(path)
    forbidden = []
    sec = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            sec = line[3:].strip().split()[0].lower()
            continue
        if sec == "forbidden_actions" and line.startswith("- "):
            forbidden.append(_md_value(line, bullet=True))
    return {"authorized": base["authorized"], "denied": base["denied"],
            "forbidden": [x for x in forbidden if x],
            "harmless_allow": [],
            "workspace": [],
            "rps_cap": base["rps_cap"], "allow_g3": False}


def load_manifest(path, overrides_path=None):
    """Load the policy manifest, then apply gate-loosening exceptions from
    the separate hand-written operator override file only. The policy file
    can tighten scope; it can never widen workspace, harm classes, or G3."""
    mf = load_policy_manifest(path)
    ov = load_operator_overrides(overrides_path)
    mf["harmless_allow"] = ov["harmless_allow"]
    mf["workspace"] = ov["workspace"]
    mf["allow_g3"] = ov["allow_g3"]
    return mf


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


def g3_floor_verdict(shape, payload=False):
    """Hard invariant: even explicit operator G3 approval lowers a
    destructive shape only from deny to escalate — never to allow."""
    rule = "payload_g3_destructive" if payload else "g3_destructive"
    return verdict("escalate", rule,
                   "destructive shape %r permitted by operator G3; "
                   "confirm before dispatch" % shape)


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


def _find_roots(argv, i):
    """Starting paths of one find invocation (before the expression)."""
    roots = []
    for x in argv[i + 1:]:
        if x in ("-H", "-L", "-P"):
            continue
        if x in _ARG_SEP or x.startswith("-") or x in ("!", "(", ")"):
            break
        roots.append(x)
    return roots or ["."]


def _find_exec_targets(argv, i):
    """File operands of commands run by find -exec/-execdir. `{}` means
    every matched path, so the find roots are the conservative boundary."""
    roots = _find_roots(argv, i)
    dels, writes = [], []
    j = i + 1
    while j < len(argv):
        if argv[j] in _ARG_SEP:
            break
        if argv[j] not in ("-exec", "-execdir"):
            j += 1
            continue
        sub = []
        j += 1
        while j < len(argv) and argv[j] not in (";", "\\;", "+"):
            sub.append(argv[j])
            j += 1
        if not sub:
            continue
        base = os.path.basename(sub[0])
        ops = []
        for tok in sub[1:]:
            if tok == "{}":
                ops += roots
            elif not tok.startswith("-"):
                ops.append(tok)
        if base in DEL_OPS:
            dels += ops
        elif base in COPY_OPS:
            if ops:
                writes.append(ops[-1])
        elif base in WRITE_OPS:
            writes += ops
        j += 1
    return dels, writes


def _xargs_delete(argv):
    """Delete command an xargs invocation runs. xargs operands arrive on
    stdin, so even a bare `xargs rm` cannot be proven workspace-bound."""
    for i, tok in enumerate(argv):
        if os.path.basename(tok) != "xargs":
            continue
        for x in argv[i + 1:]:
            if x in _ARG_SEP:
                break
            base = os.path.basename(x)
            if base in DEL_OPS:
                return base
    return None


def _tar_extract_writes(argv, i):
    """`-C`/`--directory` extraction roots of one tar invocation."""
    args = []
    for x in argv[i + 1:]:
        if x in _ARG_SEP:
            break
        args.append(x)
    extracting = any(
        x in ("--extract", "--get")
        or (x.startswith("-") and not x.startswith("--") and "x" in x[1:])
        for x in args)
    if args and not args[0].startswith("-") and "x" in args[0]:
        extracting = True                       # old-style `tar xf`
    if not extracting:
        return []
    out = []
    for j, x in enumerate(args):
        if x == "-C" and j + 1 < len(args):
            out.append(args[j + 1])
        elif x.startswith("-C") and len(x) > 2:
            out.append(x[2:])
        elif x == "--directory" and j + 1 < len(args):
            out.append(args[j + 1])
        elif x.startswith("--directory="):
            out.append(x.split("=", 1)[1])
    return [x for x in out if x]


def _expand_cwd_tilde(p, cwd):
    """Bash expands ~+ to $PWD; Python's expanduser deliberately does not."""
    if p == "~+" or p.startswith("~+/"):
        base = cwd if isinstance(cwd, str) and cwd else os.getcwd()
        rest = p[2:].lstrip("/")
        return os.path.join(base, rest) if rest else base
    return p


def _fs_targets(argv, cwd=None):
    """(delete_targets, write_targets): absolute paths an argv removes
    or writes. Relative paths resolve inside the action cwd (process
    cwd when unset); /dev/* writes are plumbing, not file ops."""
    dels, writes = [], []
    for i, tok in enumerate(argv):
        base = os.path.basename(tok)
        ops = _operands(argv, i)
        if base in DEL_OPS:
            dels += ops
        elif base in COPY_OPS:
            if ops:
                writes.append(ops[-1])  # destination operand only
        elif base == "find":
            if any(x in ("-delete", "--delete") for x in argv[i + 1:]):
                dels += ops
            fd, fw = _find_exec_targets(argv, i)
            dels += fd
            writes += fw
        elif base == "sed" and any(
                x == "-i" or x.startswith("-i") for x in argv[i + 1:]):
            writes += ops
        elif base in ("curl", "wget"):
            for j in range(i + 1, len(argv) - 1):
                if argv[j] in ("-o", "-O", "--output"):
                    writes.append(argv[j + 1])
        elif base == "tar":
            writes += _tar_extract_writes(argv, i)
        elif base in WRITE_OPS:
            writes += ops
    writes += REDIRECT_RE.findall(" ".join(argv))

    def res(p):
        p = _expand_cwd_tilde(p, cwd)
        if _abspath(p):
            return p
        base = cwd if isinstance(cwd, str) and cwd else os.getcwd()
        return os.path.join(base, p)
    dels = [res(p) for t in dels for p in _eq_path(t)]
    writes = [res(p) for t in writes for p in _eq_path(t)]
    writes = [p for p in writes if not p.startswith("/dev/")]
    return dels, writes


def _ws_roots(mf):
    return [os.path.realpath(os.path.expanduser(r))
            for r in mf["workspace"]
            if isinstance(r, str) and r]


def _outside(path, roots):
    p = os.path.realpath(os.path.expanduser(path))
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
                att_n = float(att)
                invalid = not math.isfinite(att_n) or att_n < 0
            except (TypeError, ValueError):
                att_n, invalid = None, True
            if invalid:
                checks.append(("brute_force", "escalate",
                               "invalid attempts bound %r on %s; must be "
                               "finite and >= 0" % (att, url)))
            elif att_n > AUTH_ATTEMPT_CAP:
                checks.append(("brute_force", "deny",
                               "%s declared attempts on credential path "
                               "%s" % (att, url)))
    cap = mf["rps_cap"] or 1
    rate = a.get("rate", a.get("rps"))
    try:
        r = float(rate) if rate is not None else None
    except (TypeError, ValueError):
        r = None
    if r is not None and math.isfinite(r) and r >= 0 \
            and r > max(DOS_CAP_MULT * cap, DOS_RATE_FLOOR):
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

    dels, writes = _fs_targets(argv, a.get("cwd"))
    roots = _ws_roots(mf)
    out_d = [p for p in dels if _outside(p, roots)]
    out_w = [p for p in writes if _outside(p, roots)]
    xargs_del = _xargs_delete(argv)
    if out_d:
        checks.append(("file_write_delete", "deny",
                       "delete outside approved workspace: %s" % out_d[0]))
    elif out_w:
        checks.append(("file_write_delete", "escalate",
                       "write outside approved workspace: %s" % out_w[0]))
    elif xargs_del:
        checks.append(("file_write_delete", "escalate",
                       "xargs invokes delete op %r with stdin-supplied "
                       "operands; workspace scope unverifiable" % xargs_del))

    cwd = a.get("cwd")
    if isinstance(cwd, str) and cwd and _outside(cwd, roots):
        checks.append(("file_write_delete", "escalate",
                       "cwd outside approved workspace: %s" % cwd))

    return _harmless_pick(checks, mf)


def payload_bodies(argv):
    """Script bodies an argv wrapper hides from token-level checks:
    -c code strings, heredoc/multi-line tokens, base64 -d blobs. Returns
    (bodies, opaque) — opaque flags a payload channel the judge cannot
    decode (a pipe into an interpreter, an unreadable blob), which must
    fail closed at escalate."""
    bodies, opaque = [], False
    for i, tok in enumerate(argv):
        if "\n" in tok or "<<" in tok:
            bodies.append(tok)                       # heredoc / inline script
        if os.path.basename(tok) in INTERPRETERS:
            base = os.path.basename(tok)
            eval_flags = ("-c",) if base not in {"perl", "ruby", "node", "lua"} \
                else ("-c", "-e")
            for j in range(i + 1, len(argv)):
                if argv[j] in eval_flags and j + 1 < len(argv):
                    bodies.append(argv[j + 1])
                    break
                if not argv[j].startswith("-"):      # script path, not code
                    break
        if tok == "|" and i + 1 < len(argv) \
                and os.path.basename(argv[i + 1]) in INTERPRETERS:
            opaque = True                            # generated/piped code
        if os.path.basename(tok) == "base64" and any(
                f in ("-d", "-D", "--decode") for f in argv[i + 1:]):
            decoded = False
            for cand in argv:
                if not B64_BLOB_RE.fullmatch(cand):
                    continue
                try:
                    bodies.append(base64.b64decode(cand, validate=True)
                                  .decode("utf-8", "replace"))
                    decoded = True
                except (ValueError, TypeError):
                    opaque = True
            if not decoded:
                opaque = True                        # decodes unseen stdin
    return bodies, opaque


def judge_payload(body, a, mf):
    """Classify one embedded script body against the same high-risk
    classes argv faces — the fix for the fail-open judge that saw only
    argv. A wrapped `rm -rf` must verdict like a bare one."""
    m = BODY_DESTRUCTIVE_RE.search(body)
    if m:
        if not mf["allow_g3"]:
            return verdict("deny", "destructive_payload",
                           "embedded payload has destructive shape %r"
                           % m.group(0))
        return g3_floor_verdict(m.group(0), payload=True)
    try:
        sub = shlex.split(body)
    except ValueError:
        sub = body.split()
    if not sub:
        return verdict("escalate", "opaque_payload",
                       "unparseable payload body cannot be classified")
    killer = destructive_argv(sub)
    if killer:
        if not mf["allow_g3"]:
            return verdict("deny", "destructive_payload",
                           "embedded payload has destructive shape %r" % killer)
        return g3_floor_verdict(killer, payload=True)
    hv = harmless_shell(a, sub, mf)
    if hv:
        return verdict(hv["verdict"], "payload_" + hv["rule"], hv["reason"])
    return None


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
    cap = mf["rps_cap"] or 1  # unstated rps -> <=1, per scope-parser
    rate = a.get("rate", a.get("rps"))
    r = None
    if rate is not None:
        try:
            r = float(rate)
        except (TypeError, ValueError):
            return verdict("deny", "malformed_action",
                           "unparseable rate %r" % (rate,))
        if not math.isfinite(r) or r < 0:
            return verdict("deny", "malformed_action",
                           "invalid rate %r; must be finite and >= 0" % (rate,))
    hv = harmless_http(a, method, host, mf)
    if hv:
        return hv
    if method in SAFE_METHODS:
        return verdict("allow", "in_scope_readonly",
                       "%s on authorized host %s" % (method, host))
    if rate is None:
        return verdict("escalate", "mutation_rate",
                       "state-mutating %s on in-scope %s with no declared "
                       "rate; cannot prove <= rps_cap %d" % (method, host, cap))
    if r > cap:
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
                       "destructive shape %r; operator overrides do not "
                       "permit G3" % killer)
    bodies, opaque = payload_bodies(argv)
    hits = [v for v in (judge_payload(b, a, mf) for b in bodies) if v]
    deny_hit = next((v for v in hits if v["verdict"] == "deny"), None)
    if deny_hit:
        return deny_hit
    if hits or opaque:
        return hits[0] if hits else verdict(
            "escalate", "opaque_payload",
            "payload channel into an interpreter cannot be decoded and "
            "classified; fail closed")
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
    if killer:  # operator G3 approval has a hard floor: escalate, never allow
        return g3_floor_verdict(killer)
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
    ap.add_argument("--operator-overrides", default=_DEFAULT_OVERRIDES,
                    help="hand-written operator override file "
                         "(default: %(default)s)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--action-file", help="action JSON to adjudicate")
    src.add_argument("--stdin", action="store_true",
                     help="read the action JSON from stdin")
    ap.add_argument("--json", action="store_true",
                    help="emit the verdict as a JSON object")
    ap.add_argument("--log", default=_DEFAULT_LOG,
                    help="hash-chained decision log path "
                         "(default: %(default)s)")
    ap.add_argument("--no-log", action="store_true",
                    help="do not append the verdict to the decision log")
    a = ap.parse_args(argv)

    if wrap is None:
        v = verdict("deny", "scope_engine_unavailable",
                    "cannot load scope logic from %s" % _WRAP_PATH)
        return emit(v, a)

    try:
        mf = load_manifest(a.manifest, a.operator_overrides)
    except (OSError, ValueError, KeyError) as e:
        print("guardian: cannot load manifest/operator overrides: %s" % e,
              file=sys.stderr)
        v = verdict("deny", "manifest_unreadable",
                    "cannot load manifest/operator overrides %s: %s"
                    % (a.manifest, e))
        return emit(v, a)

    text = None
    try:
        text = sys.stdin.read() if a.stdin else open(
            a.action_file, encoding="utf-8").read()
        action = json.loads(text)
    except (OSError, ValueError) as e:
        v = verdict("deny", "malformed_action",
                    "cannot read/parse action: %s" % e)
        return emit(v, a, raw=text)
    if not isinstance(action, dict):
        v = verdict("deny", "malformed_action", "action must be an object")
        return emit(v, a, raw=text)

    return emit(judge(action, mf), a, action=action)


def record_decision(log_path, action, v, raw=None):
    """Append the verdict to the hash-chained audit log — tamper-evident
    record of WHAT was adjudicated and how it was decided. Stores the
    action's digest rather than its body, so denied secret material
    never lands in the durable log. Best-effort: a log failure warns on
    stderr, it never blocks the verdict."""
    if audit_log is None or not log_path:
        return
    data = {"verdict": v["verdict"], "rule": v["rule"], "reason": v["reason"]}
    if action is not None:
        data["type"] = action.get("type")
        data["action_sha256"] = "sha256:" + hashlib.sha256(
            json.dumps(action, sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()
    elif raw is not None:
        data["raw_sha256"] = "sha256:" + hashlib.sha256(
            raw.encode()).hexdigest()
    try:
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        with contextlib.redirect_stdout(sys.stderr):
            audit_log.append(log_path, "decision", data, None)
    except (Exception, SystemExit) as e:
        print("guardian: audit-log append failed: %s" % e, file=sys.stderr)


def emit(v, a, action=None, raw=None):
    record_decision(None if a.no_log else a.log, action, v, raw)
    if a.json:
        print(json.dumps(v))
    else:
        print("%s [%s] %s" % (v["verdict"], v["rule"], v["reason"]))
    return {"allow": 0, "escalate": 2, "deny": 3}[v["verdict"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
