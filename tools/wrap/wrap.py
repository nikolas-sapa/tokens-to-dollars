#!/usr/bin/env python3
"""wrap.py — one dispatcher for scoped, rate-limited wrappers around the
atomic hunting tools. Wrap, never reinvent.

  python3 wrap.py <tool> [tool args...] -- [--manifest M] [--budget N]
                                          [--rate N] [--json]
                                          [--allow-unmanifested]

Exit codes: 0..n = wrapped tool's own code; 2 = usage/unmanifested refusal;
3 = scope or budget refusal; 4 = session-auth refusal (broker declined to
stamp — never run unauthenticated); 127 = unknown tool or binary missing.
"""
import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading

# Per tool: json = flag that makes it emit JSON/JSONL on stdout,
# rate = flag enforcing a req/sec cap, rate_ms = flag enforcing a
# milliseconds-between-requests delay (--rate N -> 1000/N ms), tflags =
# target-bearing flags ("host" = value is a target or comma-list of targets,
# "file" = value is a file of targets or a raw request carrying
# Host:/Referer: headers, "hostfile" = value is a file when it exists on
# disk else a target), posfile = positional args that are existing files
# are also scanned for targets (trufflehog), bin = real binary name when
# the registered alias differs (naabu-passive -> naabu), force = flags
# always injected (naabu-passive's -passive), deny_flags = flags refused
# outright (port-scan args on the passive-only alias), outfile = spec for
# tools whose JSON lands in a file not on stdout: {flag, args, skip} —
# when the user set no flag in skip we write flag <tmpfile> + args and
# parse the file into records after the run, install = hint printed when
# the binary is missing, ident = marker the resolved binary's
# -version/-h output must carry (PATH name-collision guard).
TOOLS = {
    "subfinder": {"json": "-json", "rate": "-rl",
                  "tflags": {"-d": "host", "-domain": "host", "-dL": "file"},
                  "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx": {"json": "-json", "rate": "-rl",
              "tflags": {"-u": "host", "-target": "host", "-l": "file", "-list": "file"},
              "ident": "projectdiscovery",
              "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "nuclei": {"json": "-jsonl", "rate": "-rl",
               "tflags": {"-u": "host", "-target": "host", "-l": "file", "-list": "file",
                          "-request": "file"},
               "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "katana": {"json": "-jsonl", "rate": "-rl",
               "tflags": {"-u": "host", "-url": "host", "-list": "file"},
               "install": "go install github.com/projectdiscovery/katana/cmd/katana@latest"},
    "ffuf": {"json": "-json", "rate": "-rate",
             "tflags": {"-u": "host", "-request": "file"},
             "install": "go install github.com/ffuf/ffuf/v2@latest"},
    "trufflehog": {"json": "--json", "rate": None,
                   "tflags": {}, "posfile": True,
                   "install": "brew install trufflehog"},
    "dnsx": {"json": "-json", "rate": "-rl",
             "tflags": {"-d": "host", "-domain": "host", "-l": "file", "-list": "file"},
             "install": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    # archive URL collectors — passive, target via positional domain or stdin
    "gau": {"json": "--json", "rate": None,
            "tflags": {},
            "install": "go install github.com/lc/gau/v2/cmd/gau@latest"},
    "waybackurls": {"json": None, "rate": None,
                    "tflags": {},
                    "install": "go install github.com/tomnomnom/waybackurls@latest"},
    # hidden-parameter discovery (active)
    "arjun": {"json": None, "rate": "--ratelimit",
              "tflags": {"-u": "host", "-i": "file"},
              "outfile": {"flag": "-oJ", "args": [],
                          "skip": {"-oJ", "-oT", "-oB"}},
              "install": "pip3 install arjun"},
    "x8": {"json": None, "rate_ms": "-d",
           "tflags": {"-u": "hostfile", "--url": "hostfile",
                      "-r": "file", "--request": "file"},
           "outfile": {"flag": "-o", "args": ["-O", "json"],
                       "skip": {"-o", "--output", "-O", "--output-format"}},
           "install": "cargo install x8"},
    # subdomain-takeover and WAF checks
    "subzy": {"json": None, "rate": None,
              "tflags": {"--target": "host", "-target": "host",
                         "--targets": "hostfile", "-targets": "hostfile"},
              "install": "go install -v github.com/PentestPad/subzy@latest"},
    "wafw00f": {"json": None, "rate": None,
                "tflags": {"-i": "file", "--input": "file",
                           "--input-file": "file"},
                "outfile": {"flag": "-o", "args": ["-f", "json"],
                            "skip": {"-o", "--output", "-f", "--format"}},
                "install": "pip3 install wafw00f"},
    # naabu passive alias — OSINT port intel only; the active port scanner
    # stays gated (unknown tool here, run it outside wrap or via a manifest
    # gate that is not this one)
    "naabu-passive": {"bin": "naabu", "json": "-json", "rate": None,
                      "force": ["-passive"],
                      "deny_flags": {"-p", "-ports", "-top-ports",
                                     "-exclude-ports", "-ep", "-scan-type",
                                     "-s", "-nmap", "-interface", "-it",
                                     "-source-ip"},
                      "tflags": {"-host": "host", "--host": "host",
                                 "-l": "file", "-list": "file",
                                 "--list": "file"},
                      "install": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
}

# Line parsers: one raw stdout line -> normalized record dict or None.
# File parsers: whole outfile text -> list of record dicts. Records print as
# {"tool": <name>, "record": {...}} — the fleet's asset-graph ingest shape.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SUBZY_RE = re.compile(r"^\[\s*([A-Za-z _-]+?)\s*\]\s*-?\s*(\S+)(?:\s*-\s*(.*))?$")


def _rec(kind, **kw):
    d = {"kind": kind}
    d.update({k: v for k, v in kw.items() if v is not None})
    return d


def parse_urlish_line(line):
    """gau / waybackurls: bare URL per line, `ts url` under -dates, or gau
    --json objects {"url": ..., "provider": ...}."""
    try:
        obj = json.loads(line)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        u = obj.get("url") or obj.get("uri")
        if not u:
            return None
        rec = _rec("asset-url", url=u)
        for k in ("provider", "source", "date"):
            if obj.get(k):
                rec[k] = obj[k]
        return rec
    s = line.strip()
    if not s or s[0] in "[{]}":
        return None
    parts = s.split(None, 1)
    if len(parts) == 2 and parts[1].startswith(("http://", "https://")):
        return _rec("asset-url", url=parts[1], fetched=parts[0])
    if s.startswith(("http://", "https://")) or HOST_RE.fullmatch(s):
        return _rec("asset-url", url=s)
    return None


def parse_subzy_line(line):
    """subzy console rows: `[ STATUS ] - host - detail`; banner/config rows
    (`[ Yes ] HTTPS by default`, `[ 10 ] Concurrent requests`) are filtered
    by the host check."""
    s = ANSI_RE.sub("", line).strip()
    m = SUBZY_RE.match(s)
    if not m:
        return None
    status, host, detail = m.group(1).strip(), m.group(2), (m.group(3) or "").strip()
    if not (host_of(host) or HOST_RE.fullmatch(host)):
        return None
    return _rec("takeover", host=host, status=status.lower(),
                detail=detail or None)


def parse_naabu_line(line):
    """naabu -json rows: {"host": ..., "ip": ..., "port": n}."""
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    host, port = obj.get("host"), obj.get("port")
    if host is None and port is None:
        return None
    return _rec("open-port", host=host, ip=obj.get("ip"), port=port)


def _param_names(params):
    if isinstance(params, dict):
        return sorted(params)
    out = []
    for p in params or []:
        n = p.get("name") if isinstance(p, dict) else p
        if n:
            out.append(n)
    return sorted(set(out))


def _params_record(url, method, params, status=None):
    rec = _rec("params", url=url, method=method, params=params, status=status)
    # asset-graph endpoint-node shape; wrapper fills method/params, the
    # rest is filled by downstream probing, never guessed
    rec.setdefault("auth_required", None)
    rec.setdefault("state_changing", None)
    return rec


def parse_arjun_file(text):
    """arjun -oJ: {url: {"method": ..., "params": {...}}, ...}"""
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    out = []
    for url, data in obj.items() if isinstance(obj, dict) else []:
        if not isinstance(data, dict):
            continue
        out.append(_params_record(url, data.get("method"),
                                  _param_names(data.get("params"))))
    return out


def parse_x8_file(text):
    """x8 -O json: [{method, url, status, found_params: [{name, ...}]}]"""
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    items = obj if isinstance(obj, list) else [obj]
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(_params_record(it.get("url"), it.get("method"),
                                  _param_names(it.get("found_params")),
                                  status=it.get("status")))
    return out


def parse_wafw00f_file(text):
    """wafw00f -f json: [{url, detected, firewall, manufacturer}]"""
    try:
        obj = json.loads(text)
    except ValueError:
        return []
    items = obj if isinstance(obj, list) else [obj]
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(_rec("waf", url=it.get("url"), detected=it.get("detected"),
                        firewall=it.get("firewall"),
                        manufacturer=it.get("manufacturer")))
    return out


LINE_PARSERS = {"gau": parse_urlish_line, "waybackurls": parse_urlish_line,
                "subzy": parse_subzy_line, "naabu-passive": parse_naabu_line}
FILE_PARSERS = {"arjun": parse_arjun_file, "x8": parse_x8_file,
                "wafw00f": parse_wafw00f_file}

# User already chose an output format -> don't inject ours.
JSONY_FLAGS = {"-json", "-jsonl", "--json", "-oJ", "-j"}

HOST_RE = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}")
IPV4_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
URL_RE = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(?:[^@/\s]*@)?(\[?[a-zA-Z0-9.:_-]+\]?)(?::\d+)?(?:[/?#]|$)")

NO_MANIFEST = """\
WRAP: NO ROE MANIFEST — %s would run unscoped.
WRAP: the manifest is the only scope authority (skills/scope-parser).
WRAP: pass --manifest <roe-manifest.md>, or --allow-unmanifested to override.
"""


def warn(msg):
    sys.stderr.write("wrap: %s\n" % msg)


def die(code, msg):
    if code == 3:
        # our policy refusal, not a target-side WAF/rate-limit — the caller
        # must read this as "stop", never as a signal to evade
        msg = "[platform-deny] %s" % msg
    warn(msg)
    return code


# --- session injection -------------------------------------------------
# The manifest's `session:` field names a broker program; wrap is the
# egress point that stamps auth. The token exists only inside the child
# process argv — we scrub it out of everything we re-emit (tool stdout
# records, outfile parses, child stderr, our own errors).
BROKER = os.environ.get("T2D_BROKER") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir,
    "session-broker", "broker.py")
MASK = "[session]"

# Fields in tool JSON output that can carry an HTTP status or a redirect
# target — scanned per line so a dead session feeds broker expire-check.
STATUS_KEYS = {"status", "status_code", "statuscode"}
LOCATION_KEYS = {"location", "redirect", "redirect_url"}
AUTH_STATUS_RE = re.compile(
    r'"(?:status(?:_code)?|statusCode)"\s*:\s*"?(\d{3})'
    r"|\[(\d{3})\]|\bStatus:\s*(\d{3})", re.I)
LOGIN_HINT_RE = re.compile(
    r"(?i)(login|signin|sign-in|log-?in|sso|oauth|session/new)")


def broker_call(prog, slot, *verb):
    """One broker invocation. Its stdout may carry token material — the
    caller consumes it into argv or a verdict line, never re-emits it."""
    cmd = [sys.executable, BROKER] + list(verb) + \
        ["--program", prog, "--account", slot]
    return subprocess.run(cmd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL)


def inject_args(prog, slot, tool):
    """Ask the broker for this tool's stamped-auth argv fragment (a JSON
    list). None = refused — expired, parked, or a tool that cannot carry
    the session; the caller then fails closed."""
    p = broker_call(prog, slot, "inject", "--tool", tool)
    if p.returncode != 0:
        warn("broker inject refused for %r [%s]: %s"
             % (prog, slot, (p.stderr or p.stdout).strip() or "unknown"))
        return None
    try:
        frag = json.loads(p.stdout)
    except ValueError:
        frag = None
    if not (isinstance(frag, list)
            and all(isinstance(x, str) for x in frag)):
        warn("broker inject returned a malformed fragment")
        return None
    return frag


def frag_secrets(frag):
    """The token material inside an inject fragment, for scrubbing:
    'Name: value' elements contribute their value; any bare non-flag
    element counts whole."""
    out = []
    for el in frag:
        if el.startswith("-"):
            continue
        val = el.split(":", 1)[1].strip() if ":" in el else el.strip()
        if val:
            out.append(val)
            # mask the bare credential too — a tool may echo the token
            # without its 'Bearer '/'Basic ' scheme prefix
            scheme, _, rest = val.partition(" ")
            if rest and scheme.lower() in ("bearer", "basic"):
                out.append(rest)
    return out


def make_scrub(secrets):
    secs = sorted(set(secrets), key=len, reverse=True)

    def scrub(s):
        for sec in secs:
            if sec:
                s = s.replace(sec, MASK)
        return s
    return scrub


def pump_err(stream, scrub):
    """Child stderr -> our stderr, token-masked. Only used when a session
    is active; otherwise stderr stays untouched."""
    for raw in stream:
        try:
            sys.stderr.write(scrub(raw))
            sys.stderr.flush()
        except (OSError, ValueError):
            break


def _walk_values(obj, keys):
    """Yield values found under any of `keys` (case-insensitive) in a
    nested JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in keys:
                yield v
            for x in _walk_values(v, keys):
                yield x
    elif isinstance(obj, list):
        for v in obj:
            for x in _walk_values(v, keys):
                yield x


def authfail_in_line(line):
    """(status, location|None) if a tool output line shows a dead session
    — 401/403 anywhere, or a 3xx whose Location looks like a login page.
    Parsed JSON fields first (httpx status_code/location, ffuf
    results[].status, nuclei status_code); raw-text fallbacks cover
    console formats (httpx '[401]', ffuf 'Status: 403')."""
    statuses, locs = [], []
    try:
        obj = json.loads(line)
    except ValueError:
        obj = None
    if isinstance(obj, (dict, list)):
        for v in _walk_values(obj, STATUS_KEYS):
            try:
                statuses.append(int(v))
            except (TypeError, ValueError):
                pass
        locs = [str(v) for v in _walk_values(obj, LOCATION_KEYS)]
    else:
        for m in AUTH_STATUS_RE.finditer(line):
            statuses += [int(g) for g in m.groups() if g]
    for s in statuses:
        if s in (401, 403):
            return (s, None)
    for s in statuses:
        if s in (301, 302, 303, 307, 308):
            for loc in locs:
                if LOGIN_HINT_RE.search(loc):
                    return (s, loc)
    return None


def host_of(tok):
    """Return the hostname/IP a token points at, else None."""
    tok = tok.strip()
    if not tok:
        return None
    m = URL_RE.match(tok)
    if not m:
        return None
    h = m.group(1).strip("[]")
    if HOST_RE.fullmatch(h) or IPV4_RE.fullmatch(h):
        return h
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        return None


def parse_manifest(path):
    """Pull the sections the wrapper enforces out of roe-manifest.md
    (schema: skills/scope-parser/SKILL.md): authorized_assets,
    hard_denylist, rate_limits, and the optional identity session
    fields."""
    auth, deny, rps = [], [], None
    sess, slot = None, None
    sec = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("## "):
                sec = line[3:].strip().split()[0].lower()
                continue
            if line.startswith("#"):
                continue
            if sec == "identity":
                # session/session_slot name the broker profile (and IDOR
                # slot) whose auth the egress layer stamps per request
                m = re.match(r'session_slot:\s*"?([^"\s]+)"?', line)
                if m:
                    slot = m.group(1).lower()
                m = re.match(r'session:\s*"?([^"\s]+)"?', line)
                if m:
                    sess = m.group(1)
            if sec == "authorized_assets" and line.startswith("- "):
                m = (re.search(r'asset:\s*"([^"]+)"', line)
                     or re.search(r'asset:\s*(\S+)', line)
                     or re.search(r'"([^"]+)"', line))
                if m:
                    if re.search(r'eligible_for_bounty:\s*false', line, re.I):
                        # mapped for context, never attacked -> denied
                        deny.append(m.group(1))
                    else:
                        auth.append(m.group(1))
            elif sec == "hard_denylist" and line.startswith("- "):
                m = re.search(r'"([^"]+)"', line)
                if m:
                    pat = m.group(1)
                else:
                    item = line[2:].split("#")[0].strip()
                    m = re.search(r'pattern:\s*(\S+)', item)
                    pat = m.group(1) if m else (item.split() or [""])[0]
                if pat:
                    deny.append(pat)
                    if not matchable(pat):
                        warn("hard_denylist pattern %r can never match a host"
                             % pat)
            elif sec == "rate_limits":
                m = re.match(r'rps_cap:\s*(\d+)', line)
                if m:
                    rps = int(m.group(1))
    return {"authorized": auth, "denied": deny, "rps_cap": rps,
            "session": sess, "session_slot": slot}


def matchable(pat):
    """Can this denylist pattern ever match a host? CIDR/network is fine;
    otherwise only host-pattern chars count — 'third-party:*' & friends
    (asset-class shorthands, URL patterns) can never match and are inert."""
    p = pat.strip().strip('"').strip("'").lower()
    if not p:
        return False
    try:
        ipaddress.ip_network(p, strict=False)
        return True
    except ValueError:
        return re.fullmatch(r"[a-z0-9.*_-]+", p) is not None


def match(pat, host, subs):
    """pat from a manifest section vs host. subs=True lets an exact deny
    cover its subdomains (per scope-parser: subdomains of a denied asset
    are denied); authorized 'domain' entries stay exact-only."""
    pat = pat.strip().strip('"').strip("'").lower()
    host = host.lower().rstrip(".")
    if not pat:
        return False
    try:
        net = ipaddress.ip_network(pat, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    if pat.startswith("*."):
        base = pat[2:]
        return host == base or host.endswith("." + base)
    if "*" in pat:
        return re.fullmatch(re.escape(pat).replace(r"\*", ".*"), host) is not None
    return host == pat or (subs and host.endswith("." + pat))


def file_hosts(path):
    """Candidate hosts in a target-list or request file: every hostname/IP
    literal in each line — bare lists, URLs, Host:/Referer: headers."""
    out = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            h = host_of(line)
            if h:
                out.append(h)
            out += HOST_RE.findall(line) + IPV4_RE.findall(line)
    return out


def hosts_in(val):
    """A flag value may carry a comma-separated host list (naabu -host,
    subzy --target/--targets); hosts themselves never contain commas."""
    out = []
    for part in val.split(","):
        h = host_of(part)
        if h:
            out.append(h)
    return out


def extract_targets(tdef, args, stdin_text):
    """Every host the wrapped tool is about to touch: known target-flag
    values (space- or =joined), the files they point at, =joined values on
    *unknown* flags, bare positional targets, piped stdin lines.
    Returns (candidates, saw_targetish, unreadable): saw_targetish means an
    arg/input that should carry targets was seen, so under a manifest an
    empty candidate list is a refusal, not a skip."""
    cands = []
    saw_targetish = bool(stdin_text.strip())
    unreadable = []
    i = 0
    while i < len(args):
        a = args[i]
        flag, eq, val = a.partition("=")
        kind = tdef["tflags"].get(flag) if a.startswith("-") else None
        if kind:
            saw_targetish = True
            if not eq:
                i += 1
                val = args[i] if i < len(args) else ""
            if kind == "file":
                try:
                    cands += file_hosts(val)
                except OSError as e:
                    unreadable.append("%s %r: %s" % (flag, val, e))
            elif kind == "hostfile":
                # x8 -u and subzy --targets take URLs/hosts OR a list file
                if os.path.isfile(val):
                    try:
                        cands += file_hosts(val)
                    except OSError as e:
                        unreadable.append("%s %r: %s" % (flag, val, e))
                else:
                    cands += hosts_in(val)
            else:
                cands += hosts_in(val)
        elif a.startswith("-"):
            # unknown flag: only an =joined value can still smuggle a target
            # (--opt=https://evil.com); space-separated next args land in the
            # positional branch below on their own.
            if eq:
                h = host_of(val)
                if h:
                    cands.append(h)
                else:
                    cands += HOST_RE.findall(val) + IPV4_RE.findall(val)
        elif os.path.exists(a):
            # an existing path we were not told is a target file may still
            # hold targets (raw requests, trufflehog file args)
            saw_targetish = True
            if tdef.get("posfile") and os.path.isfile(a):
                try:
                    cands += file_hosts(a)
                except OSError as e:
                    unreadable.append("%r: %s" % (a, e))
        else:
            h = host_of(a)
            if h:
                cands.append(h)
        i += 1
    for line in stdin_text.splitlines():
        h = host_of(line)
        if h:
            cands.append(h)
    return cands, saw_targetish, unreadable


def emit(tool, line, wrap_all, parser=None):
    rec = parser(line) if parser else None
    if rec is not None:
        print(json.dumps({"tool": tool, "record": rec}, sort_keys=True))
        return
    try:
        print(json.dumps({"tool": tool, "line": json.loads(line)}))
    except ValueError:
        print(json.dumps({"tool": tool, "line": line}) if wrap_all else line)


def emit_outfile(tool, path, scrub=None):
    """Parse the tool's JSON output file into normalized records."""
    parser = FILE_PARSERS.get(tool)
    if parser is None:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        warn("cannot read %s output file %s: %s" % (tool, path, e))
        return []
    if scrub:
        text = scrub(text)
    recs = parser(text)
    if not recs:
        warn("%s wrote no parseable results to %s" % (tool, path))
    return recs


def ident_ok(exe, marker):
    """PATH can bind a different binary under a wrapped tool's name — the
    Python `httpx` client CLI shadows ProjectDiscovery httpx. The resolved
    exe must name its upstream in -version/-h output or we refuse."""
    for flag in ("-version", "-h"):
        try:
            p = subprocess.run([exe, flag], capture_output=True, text=True,
                               timeout=15, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if marker in ((p.stdout or "") + (p.stderr or "")).lower():
            return True
    return False


def main(argv):
    if "--" in argv:
        # the LAST -- is the tool/wrapper split: a -- inside tool args must
        # not shift wrapper flags into argparse's reach
        idx = len(argv) - 1 - argv[::-1].index("--")
        head, wargs = argv[:idx], argv[idx + 1:]
    else:
        head, wargs = argv, []
    if not head or head[0] in ("-h", "--help"):
        sys.stderr.write(__doc__)
        return 0 if head else 2
    tool, tool_args = head[0], head[1:]
    tdef = TOOLS.get(tool)
    if tdef is None:
        return die(127, "unknown tool %r (supported: %s)"
                   % (tool, ", ".join(sorted(TOOLS))))

    ap = argparse.ArgumentParser(prog="wrap.py %s [args] --" % tool)
    ap.add_argument("--manifest", help="roe-manifest.md from skills/scope-parser")
    ap.add_argument("--budget", type=int, help="max target count this run may touch")
    ap.add_argument("--rate", type=int, help="req/sec cap, mapped to the tool's native flag")
    ap.add_argument("--json", action="store_true",
                    help="wrap every stdout line as {\"tool\":..., \"line\":...}")
    ap.add_argument("--allow-unmanifested", action="store_true",
                    help="run without a manifest (loud override)")
    wa = ap.parse_args(wargs)

    manifest = None
    if wa.manifest:
        try:
            manifest = parse_manifest(wa.manifest)
        except OSError as e:
            return die(3, "cannot read manifest %s: %s" % (wa.manifest, e))
    else:
        sys.stderr.write(NO_MANIFEST % tool)
        if not wa.allow_unmanifested:
            return 2

    session_prog = session_slot = None
    if manifest and manifest.get("session"):
        session_prog = manifest["session"]
        session_slot = manifest.get("session_slot") or "a"
        if session_slot not in ("a", "b"):
            return die(3, "manifest session_slot %r must be 'a' or 'b'"
                       % manifest["session_slot"])

    # Piped stdin is target input for several of these tools (httpx, dnsx);
    # it must be scope-checked too, then replayed to the child.
    stdin_text = ""
    if not sys.stdin.isatty():
        stdin_text = sys.stdin.buffer.read().decode("utf-8", "replace")

    cands, saw_targetish, unreadable = extract_targets(tdef, tool_args,
                                                       stdin_text)
    if unreadable:
        return die(3, "cannot scope-check unreadable target file(s): %s"
                   % "; ".join(unreadable))
    if manifest:
        for h in cands:
            for pat in manifest["denied"]:
                if match(pat, h, subs=True):
                    return die(3, "target %s is hard-denylisted (%s)" % (h, pat))
        unauth = [h for h in cands
                  if not any(match(p, h, subs=False) for p in manifest["authorized"])]
        if unauth:
            return die(3, "target(s) not in authorized_assets: %s"
                       % ", ".join(sorted(set(unauth))))
        if not cands:
            if saw_targetish:
                return die(3, "target-bearing args present but no targets "
                           "could be extracted; refusing to run unverifiable")
            warn("no remote targets detected; scope check skipped")
    if wa.budget is not None and len(set(cands)) > wa.budget:
        return die(3, "%d distinct targets exceeds --budget %d"
                   % (len(set(cands)), wa.budget))

    deny = tdef.get("deny_flags") or set()
    bad = sorted(a.split("=")[0] for a in tool_args
                 if a.split("=")[0] in deny)
    if bad:
        return die(3, "%s is passive-only; port-scan flag(s) gated: %s"
                   % (tool, ", ".join(bad)))

    exe = shutil.which(tdef.get("bin") or tool)
    if exe is None:
        return die(127, "%r not found on PATH\nwrap: install: %s"
                   % (tdef.get("bin") or tool, tdef["install"]))
    if tdef.get("ident") and not ident_ok(exe, tdef["ident"]):
        return die(127, "%r resolves to %s, which does not identify as %r "
                   "— PATH name collision (Python httpx CLI vs "
                   "ProjectDiscovery httpx)\nwrap: install: %s"
                   % (tool, exe, tdef["ident"], tdef["install"]))

    final = [exe]
    for f in tdef.get("force") or ():
        if not any(a == f or a.startswith(f + "=") for a in tool_args):
            final.append(f)
    final += tool_args
    if tdef["json"] and not any(a.split("=")[0] in JSONY_FLAGS for a in tool_args):
        final.append(tdef["json"])
    rate = wa.rate or (manifest or {}).get("rps_cap")
    if rate:
        if tdef.get("rate") and not any(a.split("=")[0] == tdef["rate"] for a in tool_args):
            final += [tdef["rate"], str(rate)]
        elif tdef.get("rate_ms") and not any(a.split("=")[0] == tdef["rate_ms"] for a in tool_args):
            # x8 & co take a milliseconds-between-requests delay, not req/sec
            final += [tdef["rate_ms"], str(max(1, int(1000 / rate)))]
        elif not tdef.get("rate") and not tdef.get("rate_ms"):
            warn("%s has no rate-limit flag; cap %s not enforced" % (tool, rate))

    scrub = None
    if session_prog:
        # egress stamping: the broker decides this tool's header shape and
        # hands back the argv fragment — token lives in the child argv
        # only. Any refusal (expired/parked/uncarriable tool) fails closed:
        # never run a session-scoped tool unauthenticated.
        frag = inject_args(session_prog, session_slot, tool)
        if frag is None:
            return die(4, "no session stamp for %r — refusing to run %s "
                          "unauthenticated" % (session_prog, tool))
        final += frag
        scrub = make_scrub(frag_secrets(frag))

    ofile = None
    ospec = tdef.get("outfile")
    if ospec and not any(a.split("=")[0] in ospec["skip"] for a in tool_args):
        fd, ofile = tempfile.mkstemp(prefix="wrap-%s-" % tool, suffix=".json")
        os.close(fd)
        final += [ospec["flag"], ofile] + list(ospec.get("args") or [])

    tmp = None
    try:
        stdin = None
        if stdin_text:
            tmp = tempfile.TemporaryFile(mode="w+b")
            tmp.write(stdin_text.encode())
            tmp.seek(0)
            stdin = tmp
        proc = subprocess.Popen(final, stdin=stdin, stdout=subprocess.PIPE,
                                stderr=(subprocess.PIPE if scrub else None),
                                universal_newlines=True, errors="replace")
        err_thread = None
        if scrub:
            err_thread = threading.Thread(target=pump_err,
                                          args=(proc.stderr, scrub),
                                          daemon=True)
            err_thread.start()
        parser = LINE_PARSERS.get(tool)
        auth_fail = None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if session_prog and auth_fail is None:
                auth_fail = authfail_in_line(line)
            emit(tool, scrub(line) if scrub else line, wa.json, parser)
        rc = proc.wait()
        if err_thread:
            err_thread.join(timeout=2)
        if session_prog and auth_fail:
            # the run saw a dead-session signal — feed the status line to
            # the broker; its circuit breaker parks on persistent failure
            verb = ["expire-check", "--status", str(auth_fail[0])]
            if auth_fail[1]:
                verb += ["--location", auth_fail[1]]
            p = broker_call(session_prog, session_slot, *verb)
            warn("session %r: %s"
                 % (session_prog,
                    (p.stdout or p.stderr).strip()
                    or "expire-check rc=%d" % p.returncode))
        if ofile:
            for rec in emit_outfile(tool, ofile, scrub):
                print(json.dumps({"tool": tool, "record": rec},
                                 sort_keys=True))
        return rc
    except BrokenPipeError:
        return proc.wait()
    except OSError as e:
        return die(127, "cannot exec %r: %s" % (tool, e))
    finally:
        if tmp:
            tmp.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
