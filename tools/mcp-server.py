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
import subprocess
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("T2D_ROOT") or TOOLS_DIR.parent).resolve()
PIN_FILE = ROOT / "memory" / "mcp-pins.json"
PATH_ARGS = {"log", "sidecar", "out_dir", "file"}
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
        raise InvalidParams("path outside workspace root %s: %s" % (ROOT, v))
    return str(p)


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
            "file": {"type": "string"}, "sanitize": {"type": "boolean"},
            "stdin": {"type": "string", "description": "text to scan (else --file)"}}},
        "cmd": lambda a: [sys.executable, script("content-scan", "scan.py"),
                          *flags(a, skip=("stdin",))],
        "stdin_arg": "stdin"},
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
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _manifest_path(args):
    """Resolve the engaged program's roe-manifest on the same path
    wrap.py's --manifest takes: an explicit `manifest` argument wins,
    then T2D_MANIFEST, then a single engaged program under
    memory/targets/. None when absent or ambiguous — the adjudicator
    fails closed on it."""
    m = args.get("manifest") or os.environ.get("T2D_MANIFEST")
    if isinstance(m, str) and m.strip():
        p = Path(m).expanduser()
        return str(p if p.is_absolute() else ROOT / p)
    cands = sorted(ROOT.glob("memory/targets/*/roe-manifest.*"))
    return str(cands[0]) if len(cands) == 1 else None


def _action_argv(name, args):
    """Logical argv of the proposed call — the object guardian judges.
    wrap's action is the wrapped binary, its argv, and the piped target
    lines; every other tool is its name plus its flags. Local path
    operands (PATH_ARGS) are repo files, not remote targets, and stay
    out of the action — as does the python-interpreter/script plumbing
    of the real subprocess, which would only be misread as a file of
    targets."""
    if name == "wrap":
        argv = [args["tool"]] + [str(x) for x in args.get("tool_args") or []]
        argv += [l.strip() for l in (args.get("stdin") or "").splitlines()
                 if l.strip()]
        return argv
    return [name] + flags(args, skip=PATH_ARGS | {"stdin"})


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
        mpath = _manifest_path(args)
        if mpath is None:
            v = {"verdict": "escalate", "rule": "manifest_unresolved",
                 "reason": "no engaged-program manifest: pass 'manifest', "
                           "set T2D_MANIFEST, or leave exactly one "
                           "memory/targets/<program>/roe-manifest.*"}
        else:
            try:
                mf = guardian.load_manifest(mpath)
            except (OSError, ValueError, KeyError) as e:
                v = {"verdict": "deny", "rule": "manifest_unreadable",
                     "reason": "cannot load manifest %s: %s" % (mpath, e)}
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
    return {"content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": True}


def run_tool(name, args):
    t = TOOLS.get(name)
    if t is None:
        return err("unknown tool: %s" % name)
    validate_args(t["inputSchema"], args)
    try:
        cmd = t["cmd"](args)
    except (KeyError, TypeError) as e:
        return err("%s: bad arguments: %s" % (name, e))
    v = adjudicate(name, args)
    if v["verdict"] != "allow":
        return _blocked(v)
    try:
        # stdin must never reach the child: tools like wrap.py read piped
        # stdin and would swallow the JSON-RPC channel. DEVNULL, or an
        # explicit "stdin" argument for tools that take piped targets.
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=t.get("timeout", 60),
                           stdin=subprocess.DEVNULL if "stdin_arg" not in t else None,
                           input=(args.get(t["stdin_arg"]) or "")
                           if "stdin_arg" in t else None)
    except subprocess.TimeoutExpired:
        return err("%s timed out after %ss" % (name, t.get("timeout", 60)))
    except OSError as e:
        return err("%s failed to run: %s" % (name, e))
    if p.returncode != 0:
        return err(p.stderr or p.stdout or "%s exited %d" % (name, p.returncode))
    return {"content": [{"type": "text", "text": p.stdout}]}


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
                            "error": {"code": -32602, "message": str(e)}}))
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
