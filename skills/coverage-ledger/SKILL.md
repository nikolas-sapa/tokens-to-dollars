---
name: coverage-ledger
description: Fleet anti-collision ledger — a per-program coverage map so parallel worker agents claim surfaces instead of duplicating work. Claim protocol, heartbeat windows, exactly-once settlement and fenced-claim semantics, exhaustion semantics, handoff notes.
---

# Coverage Ledger

When more than one worker hunts the same program, the ledger is the shared
answer to "who is where". It claims surfaces before work starts, not after
workers collide. One file per program: `memory/targets/<program>/coverage.md`.

The ledger is a coverage map, not knowledge. Findings, hypotheses, and
technique detail live in the exploration graph; the ledger records only
that a surface exists, who holds it, and what state it is in.

## File format

```markdown
# Coverage — <program>
updated: <UTC> by <intent-id>

| surface | claimed-by | status | technique tried | notes | AS-node |
|---|---|---|---|---|---|
| api.acme.com/v1/users/{id} | int-012 | exhausted | idor, param-pollution, method-override | numeric ids only, no uuids | AS-1042 |
| acme.com/settings | int-007 | in-progress | access-control | MFA-disable flow open | AS-0871 |
| cdn.acme.com | — | untouched | — | — | AS-0900 |

## Log
<UTC> int-007 CLAIM acme.com/settings
<UTC> int-012 CLAIM api.acme.com/v1/users/{id}
<UTC> int-012 RELEASE api.acme.com/v1/users/{id} status=exhausted
```

Column rules:

- **surface** — endpoint pattern, asset class, or contract. Coarse enough
  to dedupe (one row per route group), fine enough to claim (not per host).
- **claimed-by** — intent id of the holding worker, `—` when free.
- **status** — `untouched` | `in-progress` | `exhausted` | `finding-found`.
- **technique tried** — comma-list of distinct techniques actually executed.
- **notes** — one-line state for the next worker: dead ends, params tried,
  blocked-by. Longer content goes to the graph; `see <AS-id>` here.
- **AS-node** — anchor into the asset graph. The graph holds full node
  detail; the ledger never duplicates it. Rows without anchors are pruned
  at close-out.

## Claiming protocol

1. **Check before work.** Read `coverage.md` before planning any intent.
   If the surface's latest log line is an unpaired `CLAIM`, it is held —
   pick a different surface or offer the planner a different surface class.
2. **Claim atomically.** A claim is one appended `## Log` line:
   `<UTC> <intent-id> CLAIM <surface>`. Appends only — never batch
   read-modify-rewrite the file; append-only is what keeps concurrent
   workers from tearing each other's writes.
3. **First worker to enumerate a surface adds its table row** (with
   AS-node anchor) before claiming it.
4. **Heartbeat while held.** Per heartbeat window (default 30 min; the
   program manifest may override) the holding worker appends
   `<UTC> <intent-id> HEARTBEAT <surface>`. A heartbeat proves liveness,
   never progress — it keeps the claim alive; it does not make the work
   done.
5. **Release on close, always** — including aborts and timeouts:
   `<UTC> <intent-id> RELEASE <surface> status=<final> techniques=<list>`.
   Table row status is updated at release; last log line wins.
6. **Stale claims.** A `CLAIM` goes stale the moment one heartbeat window
   passes with no `HEARTBEAT` or other activity line from the holder —
   heartbeats are how a claim stays alive; when they stop, the claim
   starts dying. A stale claim may be taken: append
   `STEAL <surface> from <intent-id>` and continue.

## Settlement rules

- **Exactly-once settle.** One `RELEASE` per claim, ever — the settlement
  line, carrying final status and techniques tried. A crashed worker
  leaves an unpaired `CLAIM`; it settles through the stale-claim path
  above, never through a second release written by someone else.
- **Fenced claims cannot write.** `STEAL` revokes the old holder's
  ownership, not just its priority: a fenced worker's late `RELEASE`,
  `HEARTBEAT`, or graph write is ignored — its surviving contribution is
  its raw trace and the notes column. Silence never means fenced; only a
  logged `STEAL` (or explicit orchestrator revocation) does.
- **Re-claim after fencing.** A fenced worker that is actually still
  alive and wants the surface re-claims it under a new intent-id — it
  never resumes writing under the stolen one.
- **STEAL is for the dead, not the slow.** A heartbeating claim is held,
  full stop.

## Exhaustion semantics

- `exhausted` is earned, not declared. A surface is exhausted only after
  **N distinct techniques** (default N=3; program manifest may override)
  or every technique the planner assigned to that surface class.
- Distinct means a different attack primitive: idor ≠ param-pollution ≠
  method-override. Re-running one scanner with a bigger wordlist is the
  same technique.
- `finding-found`: at least one confirmed finding is recorded. The row
  stays claimed until the `reporter` draft is filed; put the
  `<finding-id>` in notes, nothing more.

## Handoff notes

Unfinished chains are recorded verbatim — they are the most valuable
thing a dying run can leave behind:

```
notes: chain: admin-reset token leaks via Referer on /oauth/cb →
       blocked: can't mint victim token → next: try oauth state fixation
```

Write notes for the next worker, not prose for humans. On program
close-out the orchestrator aggregates exhausted-row technique lists into
per-surface-class priors ("what worked / what failed here") that feed the
learning loop for the next engagement. Keep them factual.

## Ledger vs exploration graph

- **Ledger** = coverage map. Shallow, per-program, resettable per
  engagement window. Answers "what has been covered and by whom".
- **Graph** = knowledge. AS-nodes, relationships, findings. Durable
  across engagements. Answers "what do we know".
- No duplication: every ledger row anchors to an `AS-<id>`; node detail,
  hypotheses, and finding bodies never live in the ledger. One
  `finding-id` pointer in notes is the maximum.

## Deny rules are porous

Pattern-matched deny rules are necessarily incomplete — ARTEX's own
changelog documents a GET-to-delete bypass its v1 rules missed. Any
ambiguous action a deny check can't cleanly classify resolves to
human-ask, never silent allow. Deny rules are a first filter, never the
authorization boundary: the manifest allowlist is (`../scope-parser`).
