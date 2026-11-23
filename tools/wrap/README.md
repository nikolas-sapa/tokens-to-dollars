# tools/wrap — thin adapters

Wrap the atomic tools hunters already trust. Never reinvent scanning —
the value is the fleet's judgment, not another port scanner.

## Design note (3 lines)

1. Translate our inputs into the tool's native flags, invoke the binary, normalize stdout back out. Nothing more.
2. If a capability exists as a maintained binary, we shell out — no crawl/fuzz/scan logic is reimplemented in Python.
3. The RoE manifest is enforced at the wrapper, so every skill downstream inherits the same scope authority.

## Usage

```
python3 wrap.py <tool> [tool args...] -- [--manifest M] [--budget N] [--rate N] [--json] [--allow-unmanifested]
```

Everything before `--` goes to the wrapped tool verbatim (plus the injected
flags below). Everything after `--` is a wrapper flag:

| flag | effect |
|---|---|
| `--manifest <path>` | `roe-manifest.md` produced by `skills/scope-parser`. Required unless `--allow-unmanifested`. |
| `--budget N` | refuse (exit 3) when the run would touch more than N distinct targets |
| `--rate N` | req/sec cap, mapped to the tool's native flag; overrides the manifest's `rps_cap` |
| `--json` | wrap **every** stdout line as `{"tool": ..., "line": ...}` (non-JSON lines become the string value) |
| `--allow-unmanifested` | run with no manifest after a loud stderr warning |

## Manifest gate (load-bearing)

- No `--manifest` → loud stderr warning, and the run proceeds **only** with
  `--allow-unmanifested` (exit 2 otherwise).
- A candidate host matching `## hard_denylist` → refused, exit 3. Exact
  denylist entries cover their subdomains; `*.` wildcards and CIDRs work.
- A candidate host not covered by `## authorized_assets` → refused, exit 3.
  `wildcard-domain` assets cover subdomains; `domain` assets are exact-only.
  Assets marked `eligible_for_bounty: false` are mapped-only: they are moved
  to the denylist and refused like any other denied target.
- Candidates are extracted from the tool's target flags (below), from list
  files those flags point at, from bare positional targets, and from piped
  stdin — stdin is then replayed to the child unchanged.
- `rps_cap` under `## rate_limits` is injected as the tool's rate flag
  unless you pass `--rate` or set the flag yourself.

## Scope-check coverage

Extracted as candidate targets (all checked against deny + authorized):

- values of known target flags, space- or `=`-joined (`-u x`, `-l=x.txt`)
- contents of declared file flags (`-l`/`-list`/`-dL`/`-request`, trufflehog
  positional files): every hostname/IPv4 literal in every line — bare lists,
  URLs, and `Host:`/`Referer:` headers in raw request files all count
- `=`-joined values on *unknown* flags (`--opt=https://evil.com`)
- bare positional tokens that parse as host/IP/URL and do not exist on disk
- piped stdin lines (then replayed to the child)

Not extracted (deliberately, would over-match or is unknowable):

- space-separated values of unknown flags that exist on disk and aren't
  declared file flags (e.g. `ffuf -w wordlist.txt`) — but they mark the run
  target-bearing, so under a manifest a run that yields zero candidates is
  **refused** (exit 3) rather than warn-and-go
- files the wrapper cannot read: refused outright (exit 3) — can't
  scope-check what we can't read
- denylist entries that can never match a host (`third-party:*`) — warned
  about at manifest load, still inert for matching
- the tool/wrapper split is the **last** `--`; a `--` inside tool args
  cannot smuggle `--allow-unmanifested` into the wrapper

## Per-tool table

| tool | JSON flag injected | rate flag | target flags checked |
|---|---|---|---|
| `subfinder` | `-json` | `-rl` | `-d`/`-domain`, `-dL` (file) |
| `httpx` | `-json` | `-rl` | `-u`/`-target`, `-l`/`-list` (file), stdin |
| `nuclei` | `-jsonl` | `-rl` | `-u`/`-target`, `-l`/`-list`/`-request` (file) |
| `katana` | `-jsonl` | `-rl` | `-u`/`-url`, `-list` (file) |
| `ffuf` | `-json` | `-rate` | `-u`, `-request` (file) |
| `trufflehog` | `--json` | none (`--rate` warns) | positional URLs + existing positional files (scanned) |
| `dnsx` | `-json` | `-rl` | `-d`/`-domain`, `-l`/`-list` (file), stdin |

The JSON flag is skipped when you already passed an output-format flag
(`-json`, `-jsonl`, `--json`, `-oJ`, `-j`); the tool then emits its own
format and non-JSON lines pass through raw.

## Output shape

Each stdout line: JSON-parseable → `{"tool": "<name>", "line": <parsed
object>}`; anything else → passthrough (or `{"tool": ..., "line": "<raw>"}`
under `--json`). Tool stderr streams to your stderr untouched. Exit code is
the tool's own.

## Exit codes

| code | meaning |
|---|---|
| tool's | pass-through of the wrapped binary |
| 2 | usage error or unmanifested run without `--allow-unmanifested` |
| 3 | scope (denylist / not authorized), unreadable manifest, or `--budget` exceeded |
| 127 | unknown tool name, or binary not on `PATH` (prints an install hint) |

## Examples

```bash
# scoped subdomain enum, JSONL out, manifest rate cap enforced
python3 tools/wrap/wrap.py subfinder -d acme.example -- --manifest memory/targets/acme/roe-manifest.md

# alive-check a vetted list, capped at 50 targets
python3 tools/wrap/wrap.py httpx -l memory/targets/acme/hosts.txt -- --manifest memory/targets/acme/roe-manifest.md --budget 50

# lab work with no program: allowed, but loud
python3 tools/wrap/wrap.py nuclei -u http://localhost:8080 -- --allow-unmanifested
```
