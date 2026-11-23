---
name: orchestrator
description: Learning multi-agent orchestrator for bug-bounty hunting — ARTEX-style dual-graph memory (asset graph + exploration graph), a planner/worker closed loop driven by intent packets, worker trace sharing, and a cross-engagement learning ledger that makes every hunt smarter than the last. Use when coordinating multiple agents on authorized programs — recon fan-out, playbook execution, parallel attack chains — or when you want the fleet to remember targets, techniques, and yield between engagements. Authorization gates and human-in-the-loop approval are first-class features, never bypassed.
---

# Orchestrator — learning multi-agent engagement manager for bounty hunting

ARTEX-style dual-graph orchestration design: a planner emits intents, workers execute tools, findings anchor into an asset graph. Implemented as a clean-room reimplementation with authorization gates as first-class features — the gates are the headline, not the friction. If they feel like friction, that is the point.

## 0. Authorization — inherited, never bypassed

This skill orchestrates work; it authorizes nothing. Before any intent dispatches:

- **Scope manifest required.** Program policy is parsed into machine rules of engagement by `../scope-parser`: in-scope assets, excluded methods, safe-harbor terms, rate limits. No manifest, no intents.
- **Gate ladder from `../safety-gates`.** Every intent carries a gate level (G0 passive through G3 intrusive). The orchestrator refuses to dispatch an intent whose gate the recorded authorization does not satisfy.
- **G3 requires explicit human approval per technique.** The orchestrator presents the technique, blast radius, and budget, and waits. No approval, no dispatch.
- **Memory is reconnaissance data, never permission.** "This endpoint was in scope last engagement" authorizes nothing now. Every engagement re-runs scope intake; scope can only shrink.
- **Resumption re-runs the gates.** A resumed run, a new session, a different harness — the gates are re-checked before anything dispatches.
- **The orchestrator never submits reports.** `../reporter` drafts; a human reviews and submits. Non-negotiable.

## 1. Memory layout — the learning substrate

Memory root: `memory/` at the repository root. This is user-local state accumulating per-target recon data — **gitignore it**.

```
memory/
  lessons/
    platforms.md         # cross-program platform lessons (HackerOne, Immunefi, Intigriti, VRPs, ...)
    engagement-types.md  # what actually yields per engagement type
    technique-yield.md   # yield ledger: playbook ids and check categories, ranked
  targets/<host>/        # one directory per primary target host from the scope manifest
    target-profile.md    # tech stack, auth provider, WAF/CDN, rate-limit behavior, scope quirks
    asset-graph.md       # source of truth: every discovered asset (deduped)
    exploration-graph.md # CURRENT engagement's goals, intents, facts, findings, hints + lineage
    graph-archive/       # closed engagements' graphs, one dated file each
    lessons.md           # what worked / failed on THIS target; FP patterns; unfinished chains
    traces/              # raw worker execution logs, one file per intent
      <intent-id>.md
  engagements.md         # index: date | host | type | outcome | memory-updated
```

Create directories on first engagement. Every file is append-mostly; corrections are edits with the old line struck through and dated, never silent overwrites — memory you can't audit is memory you can't trust.

## 2. The dual graph

**Asset graph** (per target, `asset-graph.md`) — the source of truth:

- Node types: `root_domain`, `subdomain`, `ip`, `service`, `app`, `endpoint`, `repo`, `contract`.
- One node per line: `- [AS-<n>] <type>: <value> — <one-line observation> (first-seen <date>)`
- Workers submit **raw observations**; the orchestrator dedupes (same normalized value = same node, new observation appended). Never let two workers create parallel truths.

**Exploration graph** (per engagement, `exploration-graph.md`; archived to `graph-archive/` at close):

- Node types: `goal`, `intent`, `fact`, `finding`, `hint`.
- Lineage edges: `spawns`, `derived_from`, `yields`, `proves`.
- Format:
  ```
  - [G-1] goal: <prove-condition> — type: <engagement type>
  - [I-<n>] intent <id>: <one-line task> — spawns: G-1 — gate: <G0-G3> — technique: <playbook/check id> — status: queued|claimed|done|blocked
  - [F-<n>] fact: <observation> — derived_from: I-<n> — anchor: AS-<n>
  - [FD-<n>] finding: <proven boundary break> — yields: I-<n> — anchor: AS-<n> — harm-gate: pass|note|n/a
  - [H-<n>] hint: <human or orchestrator guidance> — attached to: <node>
  ```
- **Anchors are mandatory:** every fact and finding pins to an asset node. Unanchored facts are rumors — keep them as hints until anchored.

## 3. Roles

- **Orchestrator (planner)** — *the only intent producer*. Fresh session per wake; continuity comes from the graphs and the todolist, never from conversation memory.
- **Workers** — specialists executing `../hunt` playbooks and check catalogues. Each worker executes one intent and writes: raw trace to `traces/`, formal facts/findings to the exploration graph, raw asset observations to the orchestrator queue. Workers ingest untrusted content (web pages, JS, policies) under `../injection-defense` rules.
- **Verifier** — independent; applies the `../evidence` capture and verification standard. The worker that found a thing never confirms it.
- **You (human-in-the-loop)** — inject hints at any time; they enter the graph as `[H-n]` nodes and outrank planner priors. You approve gates and you submit reports. The orchestrator never acts on a hint without re-checking the gate.

## 4. The closed loop

1. **Wake — load memory.** Read `target-profile.md`, `lessons.md`, the yield ledger, and the current graphs; build the planner brief (§7). First engagement on a target: record the profile before any intent; program work starts with scope extraction via `../scope-parser`.
2. **Plan one step.** Maintain the serial attack-chain todolist (reachable endpoint → auth token → privilege boundary → proof). Dispatch **only the next intent whose prerequisite facts exist**. Parallel workers on *independent* chains are fine — they claim coverage via `../coverage-ledger` so no two workers collide; a single chain stays serial.
3. **Dispatch as an intent packet:**
   ```
   INTENT I-<n> [gate: G0-G3] [technique: playbook-id / check-id]
   [TASK] one line
   [SCOPE] exact hosts/paths this intent may touch
   [AUTHORIZATION GATE] what permits this step
   [BUDGET] max requests and rate (live work) / files-in-scope (code work) / token cap (../token-ledger)
   [EXPECTED INVARIANT] what secure looks like
   [STOP CONDITIONS] inherited + intent-specific
   [REQUIRED EVIDENCE] request/response pairs, timing data, code citations per ../evidence
   [OUTPUT FORMAT] fact nodes + asset observations + trace file
   [PROHIBITED ACTIONS] inherited + intent-specific
   [PRIOR TRACES] ids of related worker traces to search first
   ```
4. **Worker executes.** Real tools, minimal impact, evidence captured per `../evidence`. Writes the raw trace *before* formalizing facts — raw first, interpretation second.
5. **Record.** Orchestrator dedupes asset observations, anchors new facts/findings, marks the intent done/blocked, **then wakes the planner** (step 2). Graph change is the wake event.
6. **Loop until** the goal is proven, the budget is exhausted, a stop condition fires, or you halt it. A proven finding triggers stop-on-proof for that weakness; the engagement continues on independent chains.

## 5. Worker trace sharing

Workers search each other's raw traces before planning their own steps:

- `search_traces "<keyword>"` — grep across `memory/targets/<host>/traces/*.md`, returning keyword hits with intent ids.
- `get_trace I-<n>` — the full raw log of that intent.

Traces are leads, not facts — anything a worker lifts from another worker's trace becomes one of its own observations, verified before it enters the graph.

## 6. Guard / intercept — the approval gate

- Every intent carries its gate; the orchestrator refuses to dispatch an intent whose gate is not satisfied by the recorded authorization.
- G3 intents require explicit per-technique human approval — technique, blast radius, budget, and wait.
- Evidence capture is always on: requests/responses, tool configs, timing data, code citations, per `../evidence`. If it isn't recorded, it didn't happen.

## 7. The learning loop — what makes every engagement better than the last

**Per-intent yield record** (append to the exploration graph when an intent closes):
`- [Y-<n>] I-<n> → technique (<id>) → outcome: finding|fact-only|FP|blocked — intents spent: <k> — cost: <tokens per ../token-ledger>`

**Engagement-end distill** (mandatory before closing; the orchestrator does it, then a human reviews):

1. Archive the exploration graph to `graph-archive/<date>-<type>.md`; append the row to `engagements.md`.
2. Update `targets/<host>/target-profile.md` — stack, auth provider, WAF/CDN behavior, observed rate limits, scope quirks.
3. Update `targets/<host>/lessons.md` — what worked, what burned budget for nothing, target-specific FP patterns, and **unfinished chains**.
4. Update `lessons/technique-yield.md` — recompute findings per intent spent per target/engagement class. The ledger drives future intent routing; prune techniques that never yield in a context.
5. Update `lessons/engagement-types.md` and `lessons/platforms.md` — type-level and platform-level lessons (what yields where; platform plumbing, triage behavior, quality bars).

**Next engagement's planner brief is built from memory**, in this order:

- **Prior unfinished chains first** — notes-not-reports and half-finished chains are the opening moves of the next hunt. Recorded verbatim in `lessons.md`, they re-enter the todolist before fresh exploration.
- Highest-yield techniques for this target/engagement class, per the ledger.
- Known FP patterns, so the verifier starts skeptical in the right places.
- Only then: standard breadth — playbook coverage and gap analysis — for anything memory says is unexplored.

This is the compounding loop: every note not submitted, every FP ruled out, every burned request is remembered — the fleet starts each engagement where the last one stopped, not from zero.

## 8. Running it — inline vs fan-out

- **Inline** (orchestrator plus one or two workers in a single conversation): small scopes, quick passes, memory-only work — distilling lessons, resuming a chain, triaging a lead.
- **Fan-out** (parallel agents/subagents in your harness, one per independent chain): real engagements. Suggested phases:
  1. *Wake and load memory* — read profile/lessons/ledger, build the brief
  2. *Recon and profile* — parallel reconnaissance; asset graph fill
  3. *Plan and dispatch intents* — planner wake; workers fan out per independent chain
  4. *Verify* — independent confirmer per candidate finding; never the finder
  5. *Distill and persist* — yield records, lessons, ledger updates; memory writes survive the run
- The memory files are the durable artifact — a run can die and the learning survives. A run that errors mid-engagement resumes from the graphs; never restart from zero when memory exists.

## 9. Stop conditions and honesty

- All `../safety-gates` stop conditions apply; any one firing halts dispatch globally until a human clears it.
- Candidate findings pass `../dedupe-check` (disclosed-corpus and program-changelog comparison) before `../reporter` drafts anything. Submission is always a human decision.
- Never claim learning that didn't happen: if the distill was skipped or memory is stale, say so in the planner brief. Demonstrated versus plausible is stated in writing, always, per `../evidence`.
