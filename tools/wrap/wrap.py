#!/usr/bin/env python3
"""wrap.py — one dispatcher for scoped, rate-limited wrappers around the
atomic hunting tools. Wrap, never reinvent.

  python3 wrap.py <tool> [tool args...] -- [--manifest M] [--budget N]
                                          [--rate N] [--json]
                                          [--allow-unmanifested]

Exit codes: 0..n = wrapped tool's own code; 2 = usage/unmanifested refusal;
3 = scope or budget refusal; 127 = unknown tool or binary not on PATH.
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

# Per tool: json = flag that makes it emit JSON/JSONL on stdout,
# rate = flag enforcing a req/sec cap, tflags = target-bearing flags
# ("host" = value is a target, "file" = value is a file of targets or a
# raw request carrying Host:/Referer: headers), posfile = positional args
# that are existing files are also scanned for targets (trufflehog),
# install = hint printed when the binary is missing.
TOOLS = {
    "subfinder": {"json": "-json", "rate": "-rl",
                  "tflags": {"-d": "host", "-domain": "host", "-dL": "file"},
                  "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx": {"json": "-json", "rate": "-rl",
              "tflags": {"-u": "host", "-target": "host", "-l": "file", "-list": "file"},
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
}

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
    warn(msg)
    return code


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
    """Pull the three sections the wrapper enforces out of roe-manifest.md
    (schema: skills/scope-parser/SKILL.md)."""
    auth, deny, rps = [], [], None
    sec = None
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line.startswith("## "):
                sec = line[3:].strip().split()[0].lower()
                continue
            if line.startswith("#"):
                continue
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
    return {"authorized": auth, "denied": deny, "rps_cap": rps}


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
            else:
                h = host_of(val)
                if h:
                    cands.append(h)
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


def emit(tool, line, wrap_all):
    try:
        print(json.dumps({"tool": tool, "line": json.loads(line)}))
    except ValueError:
        print(json.dumps({"tool": tool, "line": line}) if wrap_all else line)


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

    exe = shutil.which(tool)
    if exe is None:
        return die(127, "%r not found on PATH\nwrap: install: %s"
                   % (tool, tdef["install"]))

    final = [exe] + tool_args
    if tdef["json"] and not any(a.split("=")[0] in JSONY_FLAGS for a in tool_args):
        final.append(tdef["json"])
    rate = wa.rate or (manifest or {}).get("rps_cap")
    if rate:
        if tdef["rate"] and not any(a.split("=")[0] == tdef["rate"] for a in tool_args):
            final += [tdef["rate"], str(rate)]
        elif not tdef["rate"]:
            warn("%s has no rate-limit flag; cap %s not enforced" % (tool, rate))

    tmp = None
    try:
        stdin = None
        if stdin_text:
            tmp = tempfile.TemporaryFile(mode="w+b")
            tmp.write(stdin_text.encode())
            tmp.seek(0)
            stdin = tmp
        proc = subprocess.Popen(final, stdin=stdin, stdout=subprocess.PIPE,
                                universal_newlines=True, errors="replace")
        for raw in proc.stdout:
            emit(tool, raw.rstrip("\n"), wa.json)
        return proc.wait()
    except BrokenPipeError:
        return proc.wait()
    except OSError as e:
        return die(127, "cannot exec %r: %s" % (tool, e))
    finally:
        if tmp:
            tmp.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
