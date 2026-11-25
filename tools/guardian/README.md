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
                    [--operator-overrides PATH] [--log PATH] [--no-log]
```

Every verdict is appended to a hash-chained audit log (kind `decision`,
`tools/audit-log`; default `memory/audit.jsonl`, `--no-log` disables) —
`sha256(prev_hash ‖ entry)` per entry, verifiable with
`audit_log.py verify`. The log stores the action's `action_sha256`
digest, not its body, so denied secret material never lands on disk.

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
| `manifest_unreadable` | deny | manifest missing/unparseable, operator overrides present but invalid, or either file contains an unknown/out-of-domain key (fail closed) |
| `malformed_action` | deny | action JSON unreadable, not an object, or missing required fields |
| `unknown_type` | deny | `type` is not `http` or `shell` |
| `exfil_shape` | deny | secret-bearing headers (Authorization, X-Api-Key, Cookie…) to a non-authorized host |
| `secret_material` | deny | `NAME=value` secret-shaped material (…SECRET/TOKEN/KEY/PASSWD…) in argv or body |
| `denylisted` | deny | host matches `hard_denylist` (subdomains inherit; `eligible_for_bounty: false` counts as denied) |
| `out_of_scope` | deny | host not covered by `authorized_assets`; mutating methods note it explicitly |
| `destructive_shell` | deny | `rm -rf`, `mkfs`, `dd of=`, `shred`, fork bombs, `curl\|sh` pipes — unless the hand-written operator overrides opt into G3 |
| `destructive_payload` | deny | a destructive shape found inside an embedded payload body (`-c` code, heredoc, decoded base64 blob) — the judge classifies payload content, not just the wrapping argv |
| `opaque_payload` | escalate | a payload channel exists that cannot be decoded/classified: pipe into an interpreter, undecodable blob, empty/unparseable body — fail closed |
| `payload_<class>` | per class | a Harmless Mode class hit inside an embedded payload body |
| `ambiguous_scope` | escalate | host underivable (template URL, unreadable file arg, target-bearing argv with no extractable hosts) |
| `forbidden_action` | escalate | action string matches a `## forbidden_actions` entry |
| `mutation_rate` | escalate | POST/PUT/DELETE/PATCH on an in-scope host with no declared `rate`, or `rate` > `rps_cap` (unstated cap = 1) |
| `g3_destructive` | escalate | destructive shape the operator overrides explicitly permit — the hard floor is escalate, never allow |
| `payload_g3_destructive` | escalate | the same hard floor for a destructive shape inside an embedded payload body |
| `in_scope_readonly` | allow | GET/HEAD/OPTIONS/TRACE on an authorized host |
| `in_scope_mutation` | allow | mutating method on an authorized host with `rate` <= `rps_cap` |
| `in_scope_argv` | allow | shell argv whose extracted hosts are all authorized |
| `safe_argv` | allow | argv with no remote targets at all |

## Harmless Mode

Scope gating decides **where** an action may land; Harmless Mode
adjudicates **what** the action is — six high-risk classes fired even
on authorized targets (VenusTech/Ethiack pattern). Each hit emits the
class name as the rule.

| class | verdict | fires on | operator-only escape |
|---|---|---|---|
| `persistence` | deny | `crontab`, `systemctl enable`, `launchctl`/`schtasks`/`at`, `useradd`/`usermod -G`/`net user /add`, writes to cron/init.d/systemd/LaunchAgents/`authorized_keys`/shell-rc paths | `harmless_allow: persistence` |
| `tunneling` | deny / escalate | forwarders (`ssh -L/-R/-D/-W/-w`, socat, ngrok, chisel, frp, cloudflared, gost, ligolo, sshuttle, proxychains…) deny; `nc`-family listeners/exec relays escalate | `tunneling` |
| `dos_shaped` | deny / escalate | flood tools (`hping3`, `slowloris`, `t50`, `hulk`, `stress`) and declared `rate` > 10×`rps_cap` or 50 rps deny; shell loops over http clients, `xargs -P≥20`, `seq\|xargs`, `yes\|`, and generic load tools (`wrk`, `vegeta`, `ab`, `k6`) escalate | `dos_shaped` |
| `brute_force` | deny / escalate | credential-attack tools (`hydra`, `medusa`, `ncrack`, `patator`, `crowbar`…) deny; POST to credential-shaped path (`/login`, `/auth`, `/otp`…) without an `attempts` bound escalates, >5 declared attempts denies | `brute_force` |
| `file_write_delete` | deny / escalate | `rm`/`unlink`/`rmdir`/`truncate`/`find -delete`/`find -exec` deletes outside the approved workspace deny; `tee`/`cp`/`mv`/`install`/`rsync`/`sed -i`/`>`/`>>`/`curl -o`/`tar -x -C` writes outside it escalate; `xargs` invoking a delete op escalates because its stdin operands cannot be scoped. Approved roots come only from operator-overrides `workspace` entries; a caller-supplied `cwd` outside them escalates by itself, and paths are compared after symlink resolution | `file_write_delete:<path-prefix>` (e.g. `file_write_delete:/tmp/uploads` on a file-upload scope) |
| `destructive_request` | deny / escalate | mutating verbs on mass/account-shaped paths (`/users`, `/accounts`, `/bulk-*`, `/admin`…) deny; bare `DELETE`/`PUT` on unmarked endpoints escalate | `destructive_request:<path>` |

Allow-list entries are read only from `memory/operator-overrides.md`.
They are `class` (whole class) or `class:qualifier` (qualifier `*` or a
substring of the hit detail — path prefix, `METHOD url`, tool name).
First non-allow-listed hit wins.

## Boundary: tripwire, not sandbox

Guardian is a token-level tripwire. It catches common destructive shapes,
but it cannot make an unsandboxed shell command safe: reflective or
language-native file APIs (`getattr(os, "remove")`, `File.delete` and
equivalents), operands produced by command substitution (`$(<paths)`),
and executable-name homoglyph shims are invisible or indistinguishable at
this layer. Archive member paths and interpreter semantics are likewise
outside a token scan. Treat escalation as the fail-closed boundary and use
an OS sandbox/approved workspace for execution that must be robust against
a determined evader.

## Manifest trust split

Policy-derived `.md` manifests use the scope-parser schema verbatim
(parsed by `wrap.parse_manifest`, so `authorized_assets` /
`hard_denylist` / `rate_limits.rps_cap` behave identically). Guardian
adds one tightening-only extension: a `## forbidden_actions` section
(`- "substring"` items matched against `METHOD url` or the argv string).

A policy page is target-controlled content, so a policy-derived manifest
can declare scope and tighter limits only. `workspace`,
`harmless_allow`, `allow_g3`, `g3`, and `destructive_shell` are invalid
there in every form. Unknown keys and sections are invalid too: the load
fails closed with `manifest_unreadable` rather than silently ignoring a
typo or a control-plane injection. `.json` manifests mirror the same
scope sections and validation:

```json
{"authorized_assets": [{"asset": "*.example.com"},
                       {"asset": "map.example.com", "eligible_for_bounty": false}],
 "hard_denylist": ["status.example.com"],
 "forbidden_actions": ["wp-admin"],
 "rate_limits": {"rps_cap": 5}}
```

## Operator overrides

Local gate-loosening exceptions live only in
`memory/operator-overrides.md` (override the path with
`--operator-overrides` for direct CLI use). The operator writes this
file by hand; it is never extracted, generated, or copied from fetched
content. If the file is absent, no loosening exists. Canonical form:

```markdown
# Operator overrides — local, hand-written

## workspace
- "/tmp/t2d-work"

## harmless_allow
- "file_write_delete:/tmp/t2d-work"

## g3
allow_g3: true
```

`workspace` roots must be absolute. `harmless_allow` entries use the
`class` / `class:qualifier` grammar above. `g3` accepts one boolean key:
`allow_g3`, `g3`, or `destructive_shell` (the key names differ, the
meaning is the same). Single-line `workspace: "/path"` and
`harmless_allow: "class:qualifier"` spellings are also accepted, but
unknown keys, duplicate G3 keys, malformed lines, and out-of-section
entries fail closed.

Hard invariant: G3 permission lowers destructive shell/payload shapes
only from `deny` to `escalate`. Nothing in either file can make them
`allow`; a value such as `destructive_shell: allow` is rejected.

## Integration point

Adjudicate before dispatch, never instead of it:

1. **Before `wrap.py`** — build the action object from the intended call,
   run guardian, dispatch only on `allow` (exit 0); `escalate` (2) goes to
   a human, `deny` (3) stops the run.
2. **Inside the mcp-server tool path** — wired: `run_tool`
   (`tools/mcp-server.py`) adjudicates every `tools/call` ahead of
   `subprocess.run` with the manifest of the engaged program.

Guardian judges the action object; wrap still enforces scope on the real
command line — the two layers disagree only when one of them is being
bypassed, which is the point.

### MCP dispatch path

`mcp-server.py` loads `guardian.py` in-process (the same importlib
pattern guardian uses for `wrap.py`) and builds a `shell` action from
the *logical* argv of each call: for `wrap` that is the wrapped binary
plus its `tool_args` and piped `stdin` target lines; for every other
tool it is the tool name plus its flags. Local path operands (`log`,
`sidecar`, `out_dir`, `file`) and the python-interpreter/script
plumbing stay out of the action — they are repo files, not targets.

Manifest resolution follows the path wrap.py's `--manifest` takes: an
explicit `manifest` argument wins, then `T2D_MANIFEST`, then a single
engaged program discovered at `memory/targets/<program>/roe-manifest.*`
(zero or several is unresolvable). `.md` scope fields still parse through
`wrap.parse_manifest`; guardian then applies the trust-split validation
and reads only `memory/operator-overrides.md` under the same root for
local exceptions.

Verdict semantics at the dispatch boundary:

| verdict | tool result | executed? |
|---|---|---|
| `allow` | normal tool output | yes |
| `escalate` | `{"status":"escalated","hold":<action_sha256>,"rule","reason"}` | no — pending approval |
| `deny` | `{"status":"denied","rule","class","reason"}` | no |

`class` names the Harmless Mode class when the deny came from one
(`payload_*` rules report the inner class), else null. `hold` is the
canonical action digest — the same `action_sha256` the decision log
stores — so an escalation's hold names its audit entry.

Fail closed: a missing/unloadable guardian, a crashed adjudicator, or an
unresolvable manifest is an `escalate` (`guardian_unavailable`,
`guardian_error`, `manifest_unresolved`), never an `allow`; guardian's
own fail-closed denies (`scope_engine_unavailable`,
`manifest_unreadable`) pass through. Every verdict, allowed or not, is
appended to the decision chain via `record_decision` (default
`memory/audit.jsonl` under `T2D_ROOT`).

Example flow:

```
tools/call wrap {tool:"httpx", tool_args:["-u","https://api.example.com"],
                 manifest:"memory/targets/acme/roe-manifest.md"}
  -> action {"type":"shell","argv":["httpx","-u","https://api.example.com"]}
  -> allow [in_scope_argv]          -> subprocess runs wrap.py
tools/call wrap {tool:"hydra"}
  -> deny [brute_force]             -> {"status":"denied","class":"brute_force",...}
tools/call ledger {}                (no manifest anywhere)
  -> escalate [manifest_unresolved] -> {"status":"escalated","hold":"sha256:...",...}
```

## Examples

```bash
echo '{"type":"http","method":"GET","url":"https://api.example.com/x"}' \
  | python3 tools/guardian/guardian.py --manifest memory/targets/acme/roe-manifest.md --stdin --json
# {"verdict": "allow", "rule": "in_scope_readonly", ...}   exit 0

echo '{"type":"shell","argv":["rm","-rf","/"]}' \
  | python3 tools/guardian/guardian.py --manifest memory/targets/acme/roe-manifest.md --stdin
# deny [destructive_shell] ...                              exit 3
```
