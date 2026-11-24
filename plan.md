# tokens→dollars — Build Plan v1

## Concept
Open-source "bounty desk": a harness-agnostic agent skill-pack + thin CLI that
turns LLM token spend into validated, submission-ready bug bounty reports.
Not a new agent runtime — the economics + memory + validation layer that sits
on top of whatever agent harness the user runs (Devin, Claude Code, Codex).

Tagline: "Convert tokens to dollars. Agent finds, validates, writes the PoC —
you review and hit submit."

## Repo shape (SKILL.md-standard, MIT or Apache-2.0)
```
README.md              # positioning, EV math, receipts wall
LICENSE                # permissive (Apache-2.0 recommended)
skills/
  orchestrator/        # ARTEX-style: planner/worker, dual-graph memory,
                       #   intent packets, trace sharing, learning ledger
  hunt/                # playbooks PB-1..11 (port from private engine)
  scope-parser/        # program policy -> machine RoE (skill gap #1)
  dedupe-check/        # disclosed-corpus + program-changelog check (#2)
  reporter/            # per-platform calibrated report writer (#3)
  evidence/            # req/resp capture + redaction standard (#4)
  coverage-ledger/     # fleet anti-collision (#5)
  injection-defense/   # hostile-content hardening for hunters (#6)
  safety-gates/        # rate limits, data-handling, depth limits (#7)
  token-ledger/        # $-per-intent spend accounting (#8)
tools/
  ingest-scope         # nightly pull: arkadiyt + lissy93 + diodb + immunefi
                       #   + ywh/intigriti APIs -> programs.db (ranked)
  ingest-knowledge     # bugskill-ai, ajaysenr, reddelexc, immunefi reviews,
                       #   c4 findings -> knowledge/ (RAG, payout-labeled)
                       #   [stale: c4 winding down — historical corpus only]
  wrap                 # thin adapters: subfinder/httpx/nuclei/katana/
                       #   trufflehog/ffuf/burp-mcp (hexstrike pattern)
  ledger               # token-spend -> findings -> payout scoreboard
evals/
  bountybench/         # dollar-mapped scoreboard (Stanford BountyBench)
  fprate/              # FP-rejection harness (ARE-MCP baseline to beat:
                       #   105 false CONFIRMED -> $1,100)
docs/
  responsible-use.md   # authorization gates, per-program RoE, human-submit
  threat-model.md      # why gates exist (ARTEX precedent)
knowledge/             # ingested corpora (gitignored mirror, fetch scripts)
memory/                # user-local dual-graph memory root (gitignored)
```

## Build order (speed-first, parallelizable)
1. **Scaffold + positioning** — README with EV math ($8.80/exploit -> $3k
   median -> $20k Immunefi; XBOW receipts), license, responsible-use.md.
2. **Port the crown jewels** — adapt our existing private playbooks
   (PB-1..11) + orchestrator skill -> skills/. Sanitize provenance notes,
   clean-room the ARTEX-derived parts (it's already a reimplementation).
3. **ingest-scope** — programs.db: ranked by max_payout, filtered by
   excluded_methods/safe_harbor. Keyless feeds only.
4. **scope-parser + dedupe-check** — the two marquee differentiator skills.
5. **reporter + evidence** — per-platform templates + what-triagers-reject
   lists; PoC-required gate (GitHub/H1 policy alignment).
6. **wrap** — tool adapters (PD suite first, Burp MCP optional).
7. **token-ledger + evals** — spend accounting, BountyBench runner, FP-rate
   harness as CI scoreboard.
8. **ingest-knowledge** — RAG seed (payout-labeled corpora).

## Non-goals (v1)
- No custom agent runtime / sandbox (Strix/ARTEX territory)
- No autonomous submission (ToS violation; human hits submit)
- No live-target automation beyond passive/G0-G1 in defaults
- No web3-only depth in v1 unless chosen (Immunefi lane is the payout tail)

## Kill risks designed in
- Human-in-loop submit = headline feature, not a footnote
- Per-program RoE gate before any active step (Visa vs Goldman divergence)
- Authorization manifest required before workers dispatch (ARTEX lesson)
- Honest EV math; power-law disclaimer in README
