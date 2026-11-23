#!/usr/bin/env python3
"""MCP server exposing the tokens-to-dollars tools over stdio JSON-RPC.

Hand-rolled, stdlib only: one JSON-RPC message per line. Each tool shells out
to the repo CLI script of the same name — same behavior as running it by hand.
Run: python3 tools/mcp-server.py   (or point a client's .mcp.json at it)
"""
import json
import os
import subprocess
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("T2D_ROOT") or TOOLS_DIR.parent).resolve()
PATH_ARGS = {"log", "sidecar", "out_dir", "file"}
_TYPES = {"string": str, "boolean": bool, "integer": int,
          "number": (int, float), "array": list, "object": dict}


class InvalidParams(Exception):
    pass


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
        "description": "Append to the hash-chained audit log (kinds: intent|fact|finding|dispatch|settle).",
        "inputSchema": {"type": "object", "required": ["log", "kind"], "properties": {
            "log": {"type": "string"},
            "kind": {"type": "string", "enum": ["intent", "fact", "finding", "dispatch", "settle"]},
            "data": {}, "sidecar": {"type": "string"}}},
        "cmd": audit_cmd},
}


def err(text):
    return {"content": [{"type": "text", "text": text}], "isError": True}


def run_tool(name, args):
    t = TOOLS.get(name)
    if t is None:
        return err("unknown tool: %s" % name)
    validate_args(t["inputSchema"], args)
    try:
        cmd = t["cmd"](args)
    except (KeyError, TypeError) as e:
        return err("%s: bad arguments: %s" % (name, e))
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
        elif method == "tools/list":
            resp = {"tools": [{"name": n, "description": t["description"],
                               "inputSchema": t["inputSchema"]}
                              for n, t in TOOLS.items()]}
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
