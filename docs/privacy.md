# Privacy

tokens-to-dollars is local-first. It sends nothing to the project's
authors by default — usage analytics are **opt-in** (`t2d analytics on`),
and the CLI ships with no endpoint configured.

## What stays on your machine

- `~/.config/tokens-to-dollars/config.json` (mode 0600) holds the API keys
  you enter during `t2d setup` (`GITHUB_TOKEN`, `SOLODIT_API_KEY`, custom
  `KEY=val` pairs), your analytics preference (`analytics.enabled`, an
  optional `analytics.endpoint`), and `analytics.install_id` — a random
  UUID generated once on first run, not derived from you or your machine.
  It is never committed, and `env` keys are only read into tool
  processes' environment when you invoke `t2d run`.
- `~/.config/tokens-to-dollars/stats.jsonl` (mode 0600) appends one line
  per `t2d` invocation — always, even with analytics off. It is local
  stats only and is never sent anywhere automatically.
- Hunt output (`memory/`, `data/`, `out/`, session files, evidence) is
  written under paths you choose and gitignored by default.

## Usage analytics (opt-in)

Default: **off**. Control it with:

```
t2d analytics status    # show setting, endpoint, install_id, stats path
t2d analytics on        # opt in
t2d analytics off       # opt out — local stats.jsonl keeps appending
```

Each `t2d` invocation records exactly one event — the strict allowlist:

```json
{"v": "<cli version>", "ts": <unix seconds>, "cmd": "<subcommand>",
 "dur_ms": <milliseconds>, "install_id": "<random uuid>",
 "os": "darwin|linux|win32"}
```

- `cmd` is only ever a known verb (`setup`, `list`, `install`, `run`,
  `analytics`, `help`); anything else is recorded as `"unknown"`.
  `t2d run <tool>` records `cmd: "run"` — never the tool name.
- **Never collected:** program names, target names, tool names, argument
  values, paths, env vars, tool output, findings — nothing outside the
  allowlist above.
- Every event appends to `~/.config/tokens-to-dollars/stats.jsonl`
  regardless of the setting. When analytics is on **and**
  `analytics.endpoint` in `config.json` is non-empty (default: empty — no
  endpoint is shipped), the same event is POSTed there as JSON. POSTs are
  fire-and-forget: ≤3s timeout, no retries, silent on failure, and they
  never break or delay the CLI beyond that bound.
- Inspect what's recorded: `cat ~/.config/tokens-to-dollars/stats.jsonl`
- To erase: `t2d analytics off` stops any POSTing; delete `stats.jsonl`
  and the `analytics` object in `config.json` to remove the history and
  the install identity.

## What leaves your machine

Only traffic you initiate: the tools fetch public feeds (arkadiyt,
lissy93, diodb, Immunefi, bbscope, algora, opire, sherlock, crt.sh,
GitHub API, `/.well-known/security.txt` on program hosts) and, when you
run a hunt, send requests to in-scope targets plus your LLM provider's
API. If you opt in to analytics and configure an endpoint yourself, the
allowlisted event above is also POSTed to that endpoint. Otherwise no
usage data, identifiers, or findings are transmitted to the project's
authors — there is no such endpoint.

## Reports you file

Content you submit to bug bounty programs or publish yourself is between
you and the platform/program. Keep evidence and secrets out of report
bodies — `tools/evidence-store` and `tools/content-scan` exist to help
with that.

## Deleting data

Delete `~/.config/tokens-to-dollars/` and the working directories you
used; nothing else persists.
