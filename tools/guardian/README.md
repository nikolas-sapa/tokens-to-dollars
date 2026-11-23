# tools/guardian — action-level adjudicator

Second enforcement layer behind `wrap/`. wrap checks the *string* of a
command line against the manifest; guardian adjudicates a proposed
**action** (one http request, one shell invocation) as a structured
object — method, url, headers, body, argv — before it is dispatched.

Blind by design: the agent's stated reason is never an input. A hijacked
worker can argue; the action cannot.

## Usage

```
python3 guardian.py --manifest <roe-manifest.md|json>
                    (--action-file action.json | --stdin) [--json]
```

Action shapes:

```json
{"type": "http",  "method": "GET", "url": "https://h/x",
 "headers": {"Authorization": "Bearer t"}, "body": "...", "rate": 2}
{"type": "shell", "argv": ["httpx", "-u", "https://h"], "cwd": "/tmp"}
```

Verdicts: `allow` / `deny` / `escalate` (ask a human — deny-porosity:
anything scope cannot prove is never silently allowed). Output is one
line `<verdict> [<rule>] <reason>`, or the verdict object under `--json`.

| code | verdict |
|---|---|
| 0 | allow |
| 2 | escalate |
| 3 | deny |

## Rule table (evaluation order)

| rule | verdict | condition |
|---|---|---|
| `scope_engine_unavailable` | deny | `wrap/wrap.py` cannot be loaded — host matching is delegated to it |
| `manifest_unreadable` | deny | manifest missing/unparseable (fail closed) |
| `malformed_action` | deny | action JSON unreadable, not an object, or missing required fields |
| `unknown_type` | deny | `type` is not `http` or `shell` |
| `exfil_shape` | deny | secret-bearing headers (Authorization, X-Api-Key, Cookie…) to a non-authorized host |
| `secret_material` | deny | `NAME=value` secret-shaped material (…SECRET/TOKEN/KEY/PASSWD…) in argv or body |
| `denylisted` | deny | host matches `hard_denylist` (subdomains inherit; `eligible_for_bounty: false` counts as denied) |
| `out_of_scope` | deny | host not covered by `authorized_assets`; mutating methods note it explicitly |
| `destructive_shell` | deny | `rm -rf`, `mkfs`, `dd of=`, `shred`, fork bombs, `curl\|sh` pipes — unless the manifest opts in via `allow_g3: true` |
| `ambiguous_scope` | escalate | host underivable (template URL, unreadable file arg, target-bearing argv with no extractable hosts) |
| `forbidden_action` | escalate | action string matches a `## forbidden_actions` entry |
| `mutation_rate` | escalate | POST/PUT/DELETE/PATCH on an in-scope host with no declared `rate`, or `rate` > `rps_cap` (unstated cap = 1) |
| `g3_destructive` | escalate | destructive shape the manifest explicitly allowed — still never silent |
| `in_scope_readonly` | allow | GET/HEAD/OPTIONS/TRACE on an authorized host |
| `in_scope_mutation` | allow | mutating method on an authorized host with `rate` <= `rps_cap` |
| `in_scope_argv` | allow | shell argv whose extracted hosts are all authorized |
| `safe_argv` | allow | argv with no remote targets at all |

## Manifest

`.md` manifests use the scope-parser schema verbatim (parsed by
`wrap.parse_manifest`, so `authorized_assets` / `hard_denylist` /
`rate_limits.rps_cap` behave identically). Guardian adds two optional
keys: a `## forbidden_actions` section (`- "substring"` items matched
against `METHOD url` or the argv string) and `allow_g3: true` anywhere
(also accepted: `g3:` / `destructive_shell:` with `true|yes|allowed|g3`).

`.json` manifests mirror the same sections:

```json
{"authorized_assets": [{"asset": "*.example.com"},
                       {"asset": "map.example.com", "eligible_for_bounty": false}],
 "hard_denylist": ["status.example.com"],
 "forbidden_actions": ["wp-admin"],
 "rate_limits": {"rps_cap": 5},
 "allow_g3": false}
```

## Integration point

Adjudicate before dispatch, never instead of it:

1. **Before `wrap.py`** — build the action object from the intended call,
   run guardian, dispatch only on `allow` (exit 0); `escalate` (2) goes to
   a human, `deny` (3) stops the run.
2. **Inside the mcp-server tool path** — insert the same check in
   `run_tool` (`tools/mcp-server.py`) ahead of `subprocess.run`, so every
   `tools/call` is adjudicated with the manifest of the engaged program.

Guardian judges the action object; wrap still enforces scope on the real
command line — the two layers disagree only when one of them is being
bypassed, which is the point.

## Examples

```bash
echo '{"type":"http","method":"GET","url":"https://api.example.com/x"}' \
  | python3 tools/guardian/guardian.py --manifest memory/targets/acme/roe-manifest.md --stdin --json
# {"verdict": "allow", "rule": "in_scope_readonly", ...}   exit 0

echo '{"type":"shell","argv":["rm","-rf","/"]}' \
  | python3 tools/guardian/guardian.py --manifest memory/targets/acme/roe-manifest.md --stdin
# deny [destructive_shell] ...                              exit 3
```
