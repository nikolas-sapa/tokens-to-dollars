# Finding format — companion to `reporter`

Skeleton for multi-finding audit output, adapted from cinder's
`docs/BUG-REPORT.md`. Use for code reviews, audit passes, and internal
digests. Single-finding bounty submissions keep the universal skeleton
in `../SKILL.md`; the status tags and the cleared-cleanly section apply
there too when the platform accepts them.

## Skeleton

```markdown
# <target> — <review scope> report

<2-3 lines: what was reviewed, read-only or exercised, focus areas.>
Status tags: CONFIRMED = exact path traced end to end. SUSPECTED =
strong evidence, trigger plausible but not fully exercised.
All line numbers refer to <tree/commit under review>.

## Findings, ranked by likelihood × severity

### 1. CONFIRMED — <one-line defect statement>

<the code path, quoted where it earns its keep:>

```lang
<smallest excerpt that shows the defect>   // path/file.ext:LINE
```

Trigger: <input or sequence that fires it, and where that input comes
from — attacker, peer, race, operator>.
Blast radius: <what else breaks/leaks/permanently wedges when it fires;
what recovery looks like>.
`path/file.ext:NNN`, `path/other.ext:NNN`. Severity: <level + one clause
why>.

### 2. SUSPECTED — <one-line defect statement>

<same anatomy; the SUSPECTED tag says the trigger was reasoned, not run>

## Findings — one line each

1. <defect — mechanism — `file:line` (+ collaborators)>
2. <...>

## Top suspected

1. **SUSPECTED — <title>.** <2-3 sentences: mechanism, why plausible,
   what would confirm it — `file:line`>

## Areas cleared cleanly

- **<component (`file.ext:NNN-NNN`)>:** <the checks that were verified
  and held — bounds enforced, ordering correct, fail-closed behavior>.
- **<component>:** <...>

## Notes on fix direction (non-binding)

- `<symbol>`: <the smallest change that closes the hole; no code was
  changed by this report>
```

## Conventions

- **Heading grammar:** `### <rank>. <TAG> — <defect as a statement of
  mechanism>`. The mechanism statement names what is wrong, not the
  symptom: "`mailbox_drain` self-deadlocks `op_lock`", not "messages
  sometimes don't arrive".
- **Every citation greppable.** `file:line` anchors each load-bearing
  claim; a reviewer should reach any cited line in one search.
- **Severity is one clause, argued.** "high integrity (history
  falsification), trivial trigger for any contact" — level + the reason
  it earned the level. Not an adjective parade.
- **Mixed-confidence findings split the tag.** "listed CONFIRMED as a
  code defect, trigger SUSPECTED" — defect certainty and trigger
  certainty are separate claims.
- **Cleared-cleanly entries name the check, not the absence.** "X holds
  because Y was verified at Z" — a cleared line is itself a claim with
  evidence behind it.
- **Resolution updates append, not rewrite.** A later pass adds a
  dated "resolution status" block above the findings; the original
  findings stay as filed (append-once, same as evidence).
