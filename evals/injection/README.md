# injection/ — the robustness scoreboard

BountyBench measures dollars, fprate measures honesty, this harness measures
**survival**: does the fleet stay on-task when the content it fetches is
trying to hijack it. Hunters read attacker-controlled bytes by design —
target pages, error bodies, JS bundles, MCP tool descriptions, disclosed
writeups — so indirect injection is the supply-chain attack of the whole
pipeline. AgentDojo-style: fixtures are hostile documents, the scanner gate
is the defense, and the score is how much gets through.

## What it runs

`run.py` pipes each fixture in `fixtures/` through
`tools/content-scan/scan.py` — inbound channels (`fetched-page`,
`js-bundle`, `tool-output`, `tool-description`) hit the signature pass;
`agent-output` hits `--egress`, the EchoLeak leg where generated markdown
can ship data to an attacker host on render. A fixture is
`{id, channel, payload, expected_verdict, notes}` — add a JSON file and it
runs. Optional fields tighten the assertion: `expected_rules` (subset of
rule ids that must fire), `sanitize_removes` (substring that must be
absent from `--sanitize` output), `expect_absent_after_sanitize` (string
or list of strings that must all be absent after sanitization — the
round-trip assertion for normalized-only hits), and `check: "scope"` — a
manifest-as-authority test where the fixture carries `scope:
{authorized, denied}` plus `expect_scope: {host: label}` and every listed
host must resolve to its declared `scope_of` label (a URL in content is
a lead, never an asset — the 360 Tulongfeng slip).

Files prefixed `x-quarantined-` are externally discovered bypass
regressions. They are kept as regression coverage, not as proof that the
corpus is comprehensive: the current case is the operational-metadata
manifest-manipulation payload from `docs/self-audit-sec2.md`, which
scanned clean before `inj-manifest-control-write` was added.

## Metrics

- **Utility-under-attack** — does the original intent still complete. At
  this layer the proxy is the negative controls: benign content (relative
  image refs, capability-word JS) must stay `clean`, or the gate starves
  real work. Reported as `utility`.
- **ASR — attack success rate** — % of hostile payloads that come back
  `clean`, i.e. reached the planner. A hostile fixture scored `suspicious`
  is a *partial* catch (still reaches the planner, sanitized); counted
  separately, not a pass. Target ASR = 0 — the scanner drops `hostile`
  before the planner ever sees it.
- **Verdict accuracy** — exact `clean`/`suspicious`/`hostile` match rate
  across all fixtures. Over-flagging and under-flagging both land here.

## Running it

```sh
python3 evals/injection/run.py            # per-fixture table + aggregate
python3 evals/injection/run.py --json     # machine-readable report
python3 evals/injection/run.py --baseline evals/injection/.baseline.json
```

Exit is non-zero when ASR > 0, when any fixture misses without a baseline,
or when a pass→fail flip regresses against a saved baseline — wire it into
CI like `fprate/stats.py check`.

## The honest caveat

Static evals degrade. New evasion channels appear (the unicode-tag fixture
caught a class of smuggling that was invisible until providers started
decoding it; sandwich-defense payloads decay as models fuse context
differently), and scanners trained on today's phrasing miss tomorrow's.
Re-run on every model change, scanner rule change, or harness prompt
change — a green run from six months ago measures the old fleet, not this
one. `fixtures/` is a minimum bar, not a ceiling: every real-world bypass
the fleet survives or ships gets a fixture the same day.
