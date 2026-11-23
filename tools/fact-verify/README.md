# fact-verify

Mechanical claim verification — verdicts come from grep, not judgment.
Python 3.9+, stdlib only. See `skills/hunt/references/verification.md`.

## Usage

```sh
# Soliloquy check: every fact's payload must grep the raw worker trace
python3 verify_claims.py --facts facts.md --trace memory/targets/<host>/traces/I-4.md
python3 verify_claims.py --facts facts.md --trace traces/ --summary

# POE check: every receipt quote must appear verbatim in stored evidence
python3 verify_claims.py --facts evidence/int-042-a/ --verbatim
```

Output: one JSONL verdict per node/receipt. Exit `1` if any
`soliloquy` / `no-payload` / `missing-quote` — safe to gate graph writes on.

## Default mode — soliloquy check

`--facts` is a markdown file of exploration-graph fact/finding nodes
(`[F-n]`, `[FD-n]`), one per line. Each node's asserted payload is:

- a `payload:` or `quote:` field (`payload: "HTTP/2 200"` or
  `` payload: `X-RateLimit-Remaining: 0` ``), else
- every inline backtick/quoted span on the line — so mark asserted strings
  with backticks and keep prose unquoted.

Each payload is searched verbatim in `--trace` (a trace file, or a dir whose
files are concatenated). All payloads present => `grounded`; any missing =>
`soliloquy` with the absent strings named. A node with no extractable
payload is `no-payload` and fails — an unverifiable claim is not grounded.

## --verbatim mode — POE invariant

`--facts` points at finding/receipt files (`.md`/`.json`, or a dir scanned
for both). Every JSON object with a `quotes[]` field is treated as an
evidence receipt: each quote string (or `{"quote"|"text": ...}` item) must
appear verbatim in a body referenced by `body` / `file` / `path` /
`body_file` / `artifacts[].path`, resolved relative to the receipt file.

All quotes found => `poe-verified`; otherwise `missing-quote` with the
absent quote strings named. This is the BaaRai POE invariant enforced as a
check: a finding is `verified` only when every quoted evidence string is
verbatim-present in stored evidence.

## Where it fits

Workers write raw traces before formalizing facts
(`skills/orchestrator` §5). Before the orchestrator writes an `[F-n]` node
it runs the soliloquy check — no trace match, the node stays a `[H-n]`
hint. Before a finding is called `verified` the verifier runs `--verbatim`
on its receipt — the ten gates judge, this tool greps.
