#!/usr/bin/env python3
"""MCP server exposing the tokens-to-dollars tools over stdio JSON-RPC.

Hand-rolled, stdlib only: one JSON-RPC message per line. Each tool shells out
to the repo CLI script of the same name — same behavior as running it by hand.
Run: python3 tools/mcp-server.py   (or point a client's .mcp.json at it)
"""
import hashlib
import importlib.util
import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("T2D_ROOT") or TOOLS_DIR.parent).resolve()
PIN_FILE = ROOT / "memory" / "mcp-pins.json"
PATH_ARGS = {"log", "sidecar", "out_dir", "file", "manifest", "ledger"}
MAX_OUTPUT_BYTES = 256 * 1024
MAX_OUTPUT_LINES = 2000
_TYPES = {"string": str, "boolean": bool, "integer": int,
          "number": (int, float), "array": list, "object": dict}


class InvalidParams(Exception):
    pass


# Adjudication is delegated to guardian.py — one judge, one decision log.
# Loaded the way guardian loads wrap.py; a missing adjudicator never
# fails open (see adjudicate()).
_GUARDIAN_PATH = TOOLS_DIR / "guardian" / "guardian.py"
_DECISION_LOG = str(ROOT / "memory" / "audit.jsonl")


def _load_guardian():
    try:
        spec = importlib.util.spec_from_file_location(
            "t2d_guardian", _GUARDIAN_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


guardian = _load_guardian()

# scan.py stays the scanner of record; the import is used only to enrich its
# verdicts with line numbers and to apply its sanitizer after the subprocess
# has produced the verdict.
_SCANNER_PATH = TOOLS_DIR / "content-scan" / "scan.py"


def _load_scanner():
    try:
        spec = importlib.util.spec_from_file_location(
            "t2d_content_scan", _SCANNER_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


scanner = _load_scanner()

# Harmless Mode classes guardian emits as rule names (payload_ prefixed
# when the hit was inside an embedded payload body).
_HARMLESS = {"persistence", "tunneling", "dos_shaped", "brute_force",
             "file_write_delete", "destructive_request"}


def script(*parts):
    return str(TOOLS_DIR.joinpath(*parts))


def safe_path(v):
    p = Path(v).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    p = p.resolve()
    if p != ROOT and not str(p).startswith(str(ROOT) + os.sep):
        raise InvalidParams("path outside workspace root $ROOT: %s" % v)
    return str(p)


def client_safe(text):
    """Scrub operator-local absolute paths from model-facing strings."""
    s = str(text)
    roots = sorted({str(ROOT), str(TOOLS_DIR.parent)}, key=len, reverse=True)
    for root in roots:
        if root != os.sep:
            s = s.replace(root, "$ROOT")
    home = str(Path.home())
    if home != os.sep:
        s = s.replace(home, "$HOME")
    return s


def _target_owner(path):
    """Program name when path is inside memory/targets/<program>/."""
    base = ROOT / "memory" / "targets"
    try:
        rel = Path(path).relative_to(base)
    except ValueError:
        return None
    return rel.parts[0] if rel.parts else None


def check_read_scope(name, args):
    if name != "content_scan" or not args.get("file"):
        return
    owner = _target_owner(args["file"])
    if owner and args.get("program") != owner:
        raise InvalidParams(
            "content_scan file under memory/targets/%s requires "
            "program argument %r" % (owner, owner))


def validate_args(schema, args):
    if not isinstance(args, dict):
        raise InvalidParams("arguments must be an object")
    props = schema.get("properties") or {}
    for k in schema.get("required") or []:
        if args.get(k) is None:
            raise InvalidParams("missing required argument: %s" % k)
    for k, v in args.items():
        spec = props.get(k)
        if spec is None:
            raise InvalidParams("unknown argument: %s" % k)
        t = spec.get("type")
        if t in _TYPES and (not isinstance(v, _TYPES[t])
                            or (t in ("integer", "number")
                                and isinstance(v, bool))):
            raise InvalidParams("argument %s must be %s" % (k, t))
        if "enum" in spec and v not in spec["enum"]:
            raise InvalidParams("argument %s must be one of %s"
                                % (k, spec["enum"]))
        if t == "array":
            it = (spec.get("items") or {}).get("type")
            if it in _TYPES and any(not isinstance(x, _TYPES[it]) for x in v):
                raise InvalidParams("argument %s items must be %s" % (k, it))
        if k in PATH_ARGS and isinstance(v, str):
            args[k] = safe_path(v)


def flags(args, skip=()):
    out = []
    for k, v in args.items():
        if k in skip or v is None or v is False:
            continue
        flag = "--" + k.replace("_", "-")
        if v is True:
            out.append(flag)
        elif isinstance(v, list):
            for x in v:
                out += [flag, str(x)]
        else:
            out += [flag, str(v)]
    return out


def _line_no(text, pos):
    return text.count("\n", 0, pos) + 1


def _hit_line_map(text):
    """Exact source lines when scan.py exposes mapped spans; empty when
    running against an older scanner that only returns match text."""
    if scanner is None or not hasattr(scanner, "_scan"):
        return {}
    try:
        hits = scanner._scan(text, want_spans=True)
    except Exception:
        return {}
    out = {}
    for h in hits:
        span = h.get("_span")
        if span:
            out[h.get("rule")] = _line_no(text, span[0])
    return out


def _hit_line(text, rule_id):
    """Best-effort source line for one scan hit. Raw matches are exact;
    normalized-only matches are searched in short line windows because the
    fold can erase or rewrite characters without a source-span map."""
    if scanner is None or not isinstance(rule_id, str):
        return None
    rule = next((r for r in scanner.RULES if r["id"] == rule_id), None)
    if rule is None:
        return None
    m = rule["re"].search(text)
    if m:
        return _line_no(text, m.start())
    lines = text.splitlines()
    if not lines:
        return None

    def folded_hit(seg):
        folded = scanner._fold(seg)
        flat = re.sub(r"\s+", " ", folded)
        target = folded if rule["id"] == "grip-role-prefix" else flat
        return bool(rule["re"].search(target)
                    or (target is not folded and rule["re"].search(folded)))

    for width in range(1, min(4, len(lines)) + 1):
        for i in range(0, len(lines) - width + 1):
            if folded_hit("\n".join(lines[i:i + width])):
                return i + 1
    return None


def _scan_source(args):
    if args.get("_stdin_file_input") is not None:
        return args["_stdin_file_input"]
    if args.get("file"):
        return Path(args["file"]).read_bytes().decode("utf-8", "replace")
    return args.get("stdin") or ""


def _content_scan_result(args, output):
    try:
        data = json.loads(output)
    except ValueError:
        return err("content_scan: scanner emitted no parseable verdict")
    if not isinstance(data, dict) or not isinstance(data.get("verdict"), str) \
            or not isinstance(data.get("hits"), list):
        return err("content_scan: scanner emitted a malformed verdict")
    try:
        source = _scan_source(args)
    except OSError as e:
        return err("content_scan: cannot read input file: %s" % e)
    hits = []
    line_map = _hit_line_map(source)
    for h in data["hits"]:
        if not isinstance(h, dict):
            continue
        rule = h.get("rule")
        hit = {"rule": rule, "severity": h.get("severity"),
               "line": line_map.get(rule) or _hit_line(source, rule)}
        if h.get("label"):
            hit["label"] = h["label"]
        if h.get("normalized"):
            hit["normalized"] = True
        hits.append(hit)
    result = {"verdict": data["verdict"], "hits": hits}
    if args.get("include_content"):
        content = source
        if args.get("sanitize"):
            if scanner is None:
                return err("content_scan: sanitizer unavailable")
            content = scanner.sanitize(source)
        result["content"] = content
        result["content_sanitized"] = bool(args.get("sanitize"))
    return {"content": [{"type": "text",
                         "text": json.dumps(result, ensure_ascii=False)}]}


def audit_cmd(a):
    cmd = [sys.executable, script("audit-log", "audit_log.py"), "append",
           a["log"], "--kind", a["kind"]]
    if "data" in a:
        cmd += ["--data", a["data"] if isinstance(a["data"], str)
                else json.dumps(a["data"])]
    if a.get("sidecar"):
        cmd += ["--sidecar", a["sidecar"]]
    return cmd


def wrap_cmd(a):
    cmd = [sys.executable, script("wrap", "wrap.py"), a["tool"],
           *[str(x) for x in a.get("tool_args", [])]]
    wargs = flags(a, skip=("tool", "tool_args", "stdin"))
    if wargs:
        cmd += ["--"] + wargs
    return cmd


TOOLS = {
    "ingest_scope": {
        "description": "Pull public bug-bounty scope feeds into a normalized program catalog (programs.json/tsv).",
        "inputSchema": {"type": "object", "properties": {
            "out_dir": {"type": "string"}, "platforms": {"type": "string"},
            "timeout": {"type": "number"}}},
        "cmd": lambda a: [sys.executable, script("ingest-scope", "ingest_scope.py"), *flags(a)],
        "timeout": 180},
    "ingest_knowledge": {
        "description": "Build the disclosed-bug/writeup corpus (records.jsonl) for RAG and few-shot priming.",
        "inputSchema": {"type": "object", "properties": {
            "out_dir": {"type": "string"}, "sources": {"type": "string"},
            "free_corpus": {"type": "boolean"}, "replace": {"type": "boolean"},
            "c4a_tree_cap": {"type": "integer"},
            "timeout": {"type": "number"}}},
        "cmd": lambda a: [sys.executable, script("ingest-knowledge", "ingest_knowledge.py"), *flags(a)],
        "timeout": 180},
    "bounty_radar": {
        "description": "Score + rank bounty opportunities across feeds (competition, funding, scam signals).",
        "inputSchema": {"type": "object", "properties": {
            "min_reward": {"type": "number"},
            "max_competition": {"type": "number"},
            "sources": {"type": "string"},
            "include_suspect": {"type": "boolean"},
            "out_dir": {"type": "string"},
            "teaser": {"type": "boolean"}}},
        "cmd": lambda a: [sys.executable, script("bounty-radar", "bounty_radar.py"), *flags(a)],
        "timeout": 180},
    "ledger": {
        "description": "Scoreboard over memory/ledger.md: spend, yield, cost-per-finding, EV, pipeline.",
        "inputSchema": {"type": "object", "properties": {
            "ledger": {"type": "string"}, "program": {"type": "string"},
            "ceiling": {"type": "number"}, "json": {"type": "boolean"}}},
        "cmd": lambda a: [sys.executable, script("ledger", "ledger.py"), *flags(a)]},
    "knowledge_query": {
        "description": "Search records.jsonl by program/CWE/severity/bounty/keyword; answers 'already disclosed?'",
        "inputSchema": {"type": "object", "properties": {
            "file": {"type": "string"}, "program": {"type": "string"},
            "cwe": {"type": "string"}, "severity": {"type": "string"},
            "min_bounty": {"type": "number"}, "limit": {"type": "integer"},
            "keyword": {"type": "string"}, "json": {"type": "boolean"}}},
        "cmd": lambda a: [sys.executable, script("knowledge-query", "query.py"), *flags(a)]},
    "content_scan": {
        "description": "Scan text for injection/Unicode/secret-leak patterns before it enters agent context.",
        "inputSchema": {"type": "object", "properties": {
            "file": {"type": "string"},
            "program": {"type": "string", "description": "engagement context required for memory/targets/<program>/ files"},
            "sanitize": {"type": "boolean"},
            "include_content": {"type": "boolean", "description": "include scanned content (sanitized when sanitize is true)"},
            "stdin": {"type": "string", "description": "text to scan (else --file)"}}},
        "cmd": lambda a: [sys.executable, script("content-scan", "scan.py"),
                          *flags(a, skip=("stdin", "file", "program",
                                          "sanitize", "include_content"))],
        "stdin_arg": "stdin", "stdin_file": "file", "rc_ok": (0, 1, 2),
        "postprocess": _content_scan_result},
    "wrap": {
        "description": "Scope-checked adapter around external binaries (subfinder, httpx, nuclei...). "
                       "Args: tool (binary name), tool_args (argv list), manifest, budget, rate, stdin.",
        "inputSchema": {"type": "object", "required": ["tool"], "properties": {
            "tool": {"type": "string"},
            "tool_args": {"type": "array", "items": {"type": "string"}},
            "manifest": {"type": "string"}, "budget": {"type": "integer"},
            "rate": {"type": "integer"}, "json": {"type": "boolean"},
            "allow_unmanifested": {"type": "boolean"},
            "stdin": {"type": "string", "description": "piped to the tool's stdin (e.g. target list)"}}},
        "cmd": wrap_cmd,
        "stdin_arg": "stdin"},
    "audit_log_append": {
        "description": "Append to the hash-chained audit log (kinds: intent|fact|finding|dispatch|settle|decision).",
        "inputSchema": {"type": "object", "required": ["log", "kind"], "properties": {
            "log": {"type": "string"},
            "kind": {"type": "string", "enum": ["intent", "fact", "finding", "dispatch", "settle", "decision"]},
            "data": {}, "sidecar": {"type": "string"}}},
        "cmd": audit_cmd},
}


def _tool_hash(name, t):
    blob = name + "\0" + json.dumps(
        {"description": t["description"], "inputSchema": t["inputSchema"]},
        sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def _pins_write():
    PIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    PIN_FILE.write_text(json.dumps(
        {n: _tool_hash(n, t) for n, t in TOOLS.items()},
        indent=2, sort_keys=True) + "\n")


def _pins_check():
    """Tools whose (name, description, inputSchema) hash differs from the
    stored pin; writes the baseline and returns empty on first run."""
    if not PIN_FILE.exists():
        _pins_write()
        return set()
    pins = json.loads(PIN_FILE.read_text())
    return {n for n, t in TOOLS.items()
            if pins.get(n) != _tool_hash(n, t)}


def _rug_pull_warn(drifted):
    print("rug-pull suspected: %s — re-review description before calling"
          % ", ".join(sorted(drifted)), file=sys.stderr)


def err(text):
    return {"content": [{"type": "text", "text": client_safe(text)}],
            "isError": True}


def _program_manifest(program):
    if not isinstance(program, str) or not program.strip() \
            or program in (".", "..") or os.sep in program \
            or (os.altsep and os.altsep in program):
        return None
    cands = sorted((ROOT / "memory" / "targets" / program)
                   .glob("roe-manifest.*"))
    return str(cands[0]) if len(cands) == 1 else None


def _manifest_path(args, program_context=False):
    """Resolve the engaged program's roe-manifest on the same path
    wrap.py's --manifest takes: an explicit `manifest` argument wins,
    then T2D_MANIFEST, then a program-supplied context when the tool
    carries one, then a single engaged program under memory/targets/.
    An explicit path must live at memory/targets/<program>/roe-manifest.*
    — anything else is refused here rather than adjudicated, since a
    manifest outside the engagement tree is a forgery, not a scope source.
    None when absent or ambiguous — the adjudicator fails closed on it."""
    m = args.get("manifest") or os.environ.get("T2D_MANIFEST")
    if isinstance(m, str) and m.strip():
        p = Path(m).expanduser()
        if not p.is_absolute():
            p = ROOT / p
        p = p.resolve()
        if p.parent.parent != ROOT / "memory" / "targets" \
                or not p.name.startswith("roe-manifest."):
            raise InvalidParams(
                "manifest must be memory/targets/<program>/roe-manifest.*"
                " under the repo root: %s" % m)
        return str(p)
    if program_context and args.get("program"):
        return _program_manifest(args["program"])
    cands = sorted(ROOT.glob("memory/targets/*/roe-manifest.*"))
    return str(cands[0]) if len(cands) == 1 else None


def _action_argv(name, args):
    """Logical argv of the proposed call — the object guardian judges.
    wrap's action is the wrapped binary, its argv, and the piped target
    lines; every other tool is its name plus its flags, including local
    path operands so guardian can adjudicate target-bearing file reads.
    Only the python-interpreter/script plumbing of the real subprocess
    stays out of the action."""
    if name == "wrap":
        argv = [args["tool"]] + [str(x) for x in args.get("tool_args") or []]
        argv += [l.strip() for l in (args.get("stdin") or "").splitlines()
                 if l.strip()]
        return argv
    return [name] + flags(args, skip={"stdin"})


def _action_id(action):
    """sha256 of the canonical action — same digest record_decision
    stores, so an escalation's hold id names its decision-log entry."""
    return "sha256:" + hashlib.sha256(json.dumps(
        action, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def adjudicate(name, args):
    """Route the proposed call through guardian before dispatch — the
    MCP-path half of guardian's documented integration point. Returns
    the verdict dict plus a hold id. Never fails open: an adjudicator
    that cannot load or cannot prove the action yields escalate, and
    guardian's own fail-closed verdicts (scope engine gone, manifest
    unreadable) pass through unchanged."""
    action = {"type": "shell", "argv": _action_argv(name, args),
              "cwd": str(ROOT)}
    if guardian is None:
        v = {"verdict": "escalate", "rule": "guardian_unavailable",
             "reason": "cannot load adjudicator %s" % _GUARDIAN_PATH}
    elif guardian.wrap is None:
        v = {"verdict": "deny", "rule": "scope_engine_unavailable",
             "reason": "cannot load scope logic from %s"
                       % guardian._WRAP_PATH}
    else:
        mpath = _manifest_path(args, program_context=name == "content_scan")
        if mpath is None:
            v = {"verdict": "escalate", "rule": "manifest_unresolved",
                 "reason": "no engaged-program manifest: pass 'manifest', "
                           "set T2D_MANIFEST, supply a program context "
                           "where supported, or leave exactly one "
                           "memory/targets/<program>/roe-manifest.*"}
        else:
            try:
                mf = guardian.load_manifest(
                    mpath, str(ROOT / "memory" / "operator-overrides.md"))
            except (OSError, ValueError, KeyError) as e:
                v = {"verdict": "deny", "rule": "manifest_unreadable",
                     "reason": "cannot load manifest/operator overrides %s: %s"
                               % (mpath, e)}
            else:
                try:
                    v = guardian.judge(action, mf)
                except Exception as e:
                    v = {"verdict": "escalate", "rule": "guardian_error",
                         "reason": "adjudicator failed closed: %s" % e}
    if guardian is not None:
        try:
            guardian.record_decision(_DECISION_LOG, action, v)
        except Exception as e:
            print("mcp-server: decision-log append failed: %s" % e,
                  file=sys.stderr)
    v["hold"] = _action_id(action)
    return v


def _blocked(v):
    """Structured non-executed result for an escalate/deny verdict."""
    if v["verdict"] == "escalate":
        payload = {"status": "escalated", "hold": v["hold"],
                   "rule": v["rule"], "reason": v["reason"]}
    else:
        cls = v["rule"][8:] if v["rule"].startswith("payload_") else v["rule"]
        payload = {"status": "denied", "rule": v["rule"],
                   "class": cls if cls in _HARMLESS else None,
                   "reason": v["reason"]}
    return {"content": [{"type": "text",
                         "text": client_safe(json.dumps(
                             payload, ensure_ascii=False))}],
            "isError": True}


def _capture():
    return {"buf": bytearray(), "bytes": 0, "newlines": 0,
            "ended_nl": True}


def _capture_add(cap, chunk):
    cap["bytes"] += len(chunk)
    cap["newlines"] += chunk.count(b"\n")
    if chunk:
        cap["ended_nl"] = chunk.endswith(b"\n")
    room = MAX_OUTPUT_BYTES - len(cap["buf"])
    if room > 0:
        cap["buf"] += chunk[:room]


def _line_count(text):
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _first_lines(text, count):
    pos = 0
    for _ in range(count):
        nl = text.find("\n", pos)
        if nl < 0:
            return text
        pos = nl + 1
    return text[:pos]


def _capture_finish(cap):
    total_lines = 0
    if cap["bytes"]:
        total_lines = cap["newlines"] + (0 if cap["ended_nl"] else 1)
    text = bytes(cap["buf"]).decode("utf-8", "replace")
    if total_lines > MAX_OUTPUT_LINES:
        text = _first_lines(text, MAX_OUTPUT_LINES)
    over = cap["bytes"] > MAX_OUTPUT_BYTES or total_lines > MAX_OUTPUT_LINES
    return text, over, cap["bytes"], total_lines


def _cap_response(text):
    raw = text.encode("utf-8")
    lines = _line_count(text)
    over = len(raw) > MAX_OUTPUT_BYTES or lines > MAX_OUTPUT_LINES
    if not over:
        return text, False, len(raw), lines
    clipped = raw[:MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    if lines > MAX_OUTPUT_LINES:
        clipped = _first_lines(clipped, MAX_OUTPUT_LINES)
    return clipped, True, len(raw), lines


def _trunc_notice(stream, byte_count, line_count):
    return ("[truncated: %s output exceeded cap %d bytes/%d lines; "
            "emitted %d bytes, %d lines]"
            % (stream, MAX_OUTPUT_BYTES, MAX_OUTPUT_LINES,
               byte_count, line_count))


def _write_stdin(pipe, text):
    try:
        view = memoryview(text.encode("utf-8"))
        while len(view):
            n = pipe.write(view)
            if not n:
                break
            view = view[n:]
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except (OSError, ValueError):
            pass


def _group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _kill_group(p):
    """TERM then KILL the child's whole process group; true when empty."""
    pgid = p.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except OSError:
        pass
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        p.poll()
        if not _group_exists(pgid):
            return True
        time.sleep(0.05)
    if _group_exists(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            pass
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        p.poll()
        if not _group_exists(pgid):
            break
        time.sleep(0.05)
    try:
        p.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    return not _group_exists(pgid)


def _run_capped(cmd, input_text, timeout):
    """Run with bounded pipe capture. stdout/stderr are drained incrementally
    so an oversized child cannot expand memory beyond the retained caps."""
    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        start_new_session=True)
    if input_text is not None:
        threading.Thread(target=_write_stdin, args=(p.stdin, input_text),
                         daemon=True).start()
    caps = {"stdout": _capture(), "stderr": _capture()}
    pipes = {p.stdout.fileno(): ("stdout", p.stdout),
             p.stderr.fileno(): ("stderr", p.stderr)}
    for fd in pipes:
        os.set_blocking(fd, False)
    deadline = time.monotonic() + timeout
    timed_out = False
    rc = None
    while pipes:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            break
        try:
            ready, _, _ = select.select(list(pipes), [], [],
                                        min(0.1, remaining))
        except (OSError, ValueError):
            ready = []
        for fd in ready:
            if fd not in pipes:
                continue
            stream, pipe = pipes[fd]
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if chunk:
                _capture_add(caps[stream], chunk)
            else:
                try:
                    pipe.close()
                except OSError:
                    pass
                del pipes[fd]
    if not timed_out:
        try:
            rc = p.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
    if timed_out:
        clean = _kill_group(p)
        for _, pipe in pipes.values():
            try:
                pipe.close()
            except OSError:
                pass
        return {"timed_out": True, "group_clean": clean,
                "stdout": caps["stdout"], "stderr": caps["stderr"],
                "returncode": rc}
    return {"timed_out": False, "group_clean": True,
            "stdout": caps["stdout"], "stderr": caps["stderr"],
            "returncode": rc}


def run_tool(name, args):
    t = TOOLS.get(name)
    if t is None:
        return err("unknown tool: %s" % name)
    validate_args(t["inputSchema"], args)
    check_read_scope(name, args)
    try:
        cmd = t["cmd"](args)
    except (KeyError, TypeError) as e:
        return err("%s: bad arguments: %s" % (name, e))
    v = adjudicate(name, args)
    if v["verdict"] != "allow":
        return _blocked(v)
    input_text = ((args.get(t["stdin_arg"]) or "")
                  if "stdin_arg" in t else None)
    if t.get("stdin_file") and args.get(t["stdin_file"]):
        try:
            input_text = Path(args[t["stdin_file"]]).read_bytes() \
                .decode("utf-8", "replace")
        except OSError as e:
            return err("%s: cannot read input file: %s" % (name, e))
        args["_stdin_file_input"] = input_text
    try:
        # stdin must never reach the child unless the tool explicitly takes
        # piped input: tools like wrap.py would otherwise swallow JSON-RPC.
        p = _run_capped(cmd, input_text, t.get("timeout", 60))
    except OSError as e:
        return err("%s failed to run: %s" % (name, e))
    if p["timed_out"]:
        msg = "%s timed out after %ss" % (name, t.get("timeout", 60))
        if not p["group_clean"]:
            msg += "; process-group survivors remain after SIGKILL"
        return err(msg)
    stdout, out_over, out_bytes, out_lines = _capture_finish(p["stdout"])
    stderr, err_over, err_bytes, err_lines = _capture_finish(p["stderr"])
    if out_over or err_over:
        parts = ["%s output exceeded capture cap (%d bytes/%d lines); "
                 "truncated output follows"
                 % (name, MAX_OUTPUT_BYTES, MAX_OUTPUT_LINES)]
        if out_over:
            parts.append("--- stdout ---\n%s\n%s"
                         % (stdout, _trunc_notice(
                             "stdout", out_bytes, out_lines)))
        if err_over:
            parts.append("--- stderr ---\n%s\n%s"
                         % (stderr, _trunc_notice(
                             "stderr", err_bytes, err_lines)))
        return err("\n\n".join(parts))
    if p["returncode"] not in t.get("rc_ok", (0,)):
        return err(stderr or stdout
                   or "%s exited %d" % (name, p["returncode"]))
    result = {"content": [{"type": "text", "text": stdout}]}
    if t.get("postprocess"):
        result = t["postprocess"](args, stdout)
    if result.get("isError"):
        return result
    text = result["content"][0]["text"]
    text, over, byte_count, line_count = _cap_response(text)
    if over:
        return err("%s response exceeded output cap (%d bytes/%d lines)\n\n"
                   "%s\n%s"
                   % (name, MAX_OUTPUT_BYTES, MAX_OUTPUT_LINES, text,
                      _trunc_notice("response", byte_count, line_count)))
    result["content"][0]["text"] = text
    return result


def main():
    if set(sys.argv[1:]) & {"--rescan", "--pin-refresh"}:
        old = json.loads(PIN_FILE.read_text()) if PIN_FILE.exists() else {}
        _pins_write()
        new = json.loads(PIN_FILE.read_text())
        drift = [n for n in new if old.get(n) != new[n]]
        print("pins refreshed: %d tools%s"
              % (len(new), "; updated: " + ", ".join(drift) if drift else ""))
        return
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            print(json.dumps({"jsonrpc": "2.0", "id": None,
                              "error": {"code": -32700, "message": str(e)}}))
            sys.stdout.flush()
            continue
        rid = req.get("id")
        method = req.get("method")

        if method == "initialize":
            resp = {"protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "tokens-to-dollars", "version": "0.1.0"}}
            drifted = _pins_check()
            if drifted:
                _rug_pull_warn(drifted)
        elif method == "tools/list":
            drifted = _pins_check()
            if drifted:
                _rug_pull_warn(drifted)
            resp = {"tools": [{"name": n, "description": t["description"],
                               "inputSchema": t["inputSchema"]}
                              for n, t in TOOLS.items()]}
            for tool in resp["tools"]:
                if tool["name"] in drifted:
                    tool["description"] = (
                        "[rug-pull suspected — re-review description "
                        "before calling] " + tool["description"])
        elif method == "tools/call":
            p = req.get("params") or {}
            name = p.get("name")
            if not isinstance(name, str) or name not in TOOLS:
                resp = err("unknown tool: %s" % name)
            else:
                try:
                    resp = run_tool(name, p.get("arguments") or {})
                except InvalidParams as e:
                    if rid is not None:
                        print(json.dumps({
                            "jsonrpc": "2.0", "id": rid,
                            "error": {"code": -32602,
                                      "message": client_safe(str(e))}}))
                        sys.stdout.flush()
                    continue
        elif method == "ping":
            resp = {}
        else:
            if rid is not None:
                print(json.dumps({"jsonrpc": "2.0", "id": rid,
                                  "error": {"code": -32601,
                                            "message": "unknown method %s" % method}}))
                sys.stdout.flush()
            continue

        if rid is not None:
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": resp}))
        sys.stdout.flush()


if __name__ == "__main__":
    main()
