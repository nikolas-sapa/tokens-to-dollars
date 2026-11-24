# Privacy

tokens-to-dollars collects **no telemetry** and phones home nowhere.

## What stays on your machine

- `~/.config/tokens-to-dollars/config.json` (mode 0600) holds the API keys
  you enter during `t2d setup` (`GITHUB_TOKEN`, `SOLODIT_API_KEY`, custom
  `KEY=val` pairs). It is created only when you run the wizard, is never
  committed, and is only read into tool processes' environment when you
  invoke `t2d run`.
- Hunt output (`memory/`, `data/`, `out/`, session files, evidence) is
  written under paths you choose and gitignored by default.

## What leaves your machine

Only traffic you initiate: the tools fetch public feeds (arkadiyt,
lissy93, diodb, Immunefi, bbscope, algora, opire, sherlock, crt.sh,
GitHub API, `/.well-known/security.txt` on program hosts) and, when you
run a hunt, send requests to in-scope targets plus your LLM provider's
API. No usage data, identifiers, or findings are transmitted to the
project's authors — there is no such endpoint.

## Reports you file

Content you submit to bug bounty programs or publish yourself is between
you and the platform/program. Keep evidence and secrets out of report
bodies — `tools/evidence-store` and `tools/content-scan` exist to help
with that.

## Deleting data

Delete `~/.config/tokens-to-dollars/` and the working directories you
used; nothing else persists.
