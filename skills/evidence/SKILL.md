---
name: evidence
description: The evidence standard for findings — required captures, directory format, redaction, append-once integrity, per-class PoC norms, and what invalidates a finding.
---

# Evidence

Rule zero: if it isn't recorded, it didn't happen. A finding without an
evidence directory does not exist — `reporter` refuses to draft without
one, `dedupe-check` can't match it, and fleet peers can't verify it.

## Required evidence per finding

Every finding must carry all five:

1. **Raw request/response pairs, verbatim** — full headers + body, exactly
   as sent and received. Tool-based findings substitute verbatim tool
   output (nuclei JSONL, ffuf output, fork-test trace). No paraphrasing.
2. **Reproduction steps executed, not assumed** — the commands/session as
   actually run. "This should work" is not evidence.
3. **Account context** — which test account, role, and permission set
   (e.g. `Role A: free-tier user` vs `Role B: org admin` for IDOR).
4. **Scope citation** — the manifest line covering this asset + bug class.
5. **Timestamps** — UTC ISO-8601 on every file.

## Directory format

One directory per finding:

```
evidence/<finding-id>/
  request.txt     # raw HTTP request (or tool invocation), verbatim
  response.txt    # raw response, verbatim
  notes.md        # dated log: context, scope line, what was run
  receipt.json    # verification receipt — schema in references/receipt-format.md
  evidence.json   # store manifest: verifier, ts, sha256 per file (tools/evidence-store)
  poc.*           # optional — minimal reproducer, see PoC norms
```

`<finding-id>` = intent id + counter (e.g. `int-042-a`). Header block on
every file:

```
# finding: <id>
# program: <handle>
# captured: <UTC ISO-8601>
# account: <test account + role>
# scope-line: <manifest line id>
```

`notes.md` shape — findings carry a cinder-style status tag, and the log
records what was cleared as well as what fired:

```markdown
# int-042-a — IDOR on /v1/orders/{id}
Status: CONFIRMED   # CONFIRMED = path traced end to end; SUSPECTED =
                    # strong evidence, trigger plausible, not fully exercised
## 2026-11-23T14:02Z
- Scope: api.acme.com, line S-14 (in-scope, IDOR eligible)
- Role A (free user, acct own-test-1) read order 8817 → 200, own order
- Role B (free user, acct own-test-2) read order 8817 → 200, NOT own order
- Post-state: no auth challenge, no log throttle. Finding stands.
## 2026-11-23T14:31Z
- Re-ran from clean session, same result. request-2.txt added.
## Cleared cleanly
- Order create/delete paths: object ids are scoped per-account, no
  cross-tenant read (request-3.txt)
- /v1/orders export endpoint: enforces ownership check server-side
```

## Redaction rules

- **Real user data** (emails, names, tokens, PII) surfacing in a response:
  terminate the test path. Never exfiltrate it, never paste it into
  reports. In evidence files, hash or truncate: `user:[hash:8]@redacted`.
  If the bug only "works" by reading real user data, report the exposure
  without the data — the access is the finding, not the payload.
- **Own test-account tokens/cookies** may appear in evidence but must be
  marked `# test-account credential` and listed in `notes.md` so they can
  be rotated after the engagement.
- **Redact BEFORE truncate.** If a capture is length-capped or excerpted,
  secret patterns are stripped from the full string first — a token
  straddling the cap would otherwise be half-stored: enough to leak,
  not enough to notice (helm `capture.ts` lesson). Redact, then cut.
- **Never copy victim data out of scope.** Record that access was
  possible, not the data itself.

## Integrity: append-once

- Evidence files are append-once. A mistake is corrected with a new dated
  line or section — never by editing or deleting earlier content. The
  original record is what a re-checking triager must see.
- `notes.md` is a dated log, newest entries at the bottom.
- A corrected capture is a new file (`request-2.txt`, `response-2.txt`)
  plus a `notes.md` line explaining why. Never overwrite.

## Deterministic evidence hashing

Hash commitments let a triager re-verify a file without trusting the
filer. The rule (from sac-capital's `verifiability.py`): hash the
*canonical* JSON —

```python
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True)
digest = sha256(canonical.encode("utf-8")).hexdigest()
```

`sorted keys` + `(",", ":")` separators + ASCII mean the same payload
bytes produce the same hash on any machine, in any order of dict
construction. `tools/evidence-store` applies the same commitment
discipline: `path` + `sha256` on every captured file, validated at write
time, plus a digest-pinned `evidence.sha256` sidecar over the manifest
itself — a verifier recomputes and compares, and tampering shows as a
hash mismatch rather than an argument.

**Replay lineage.** When evidence is produced by replaying a recorded
trace, the receipt names it: `replay_of: <trace-id>` (the neatroots
concept — a replay run links to the run it replays). A replayed capture
is evidence of the replay, and its lineage to the original trace is part
of the record, not metadata to drop.

## PoC norms by bug class

| Bug class | PoC form |
|---|---|
| XSS / CSRF / clickjacking | One self-contained HTML file, drop-in openable, trigger marked with a comment |
| IDOR / auth / SSRF / injection | A curl one-liner (or ≤3-step curl sequence) the triager pastes verbatim |
| Race / TOCTOU | Minimal script + observed-outcome line (ran N, won M) |
| Smart contract | Foundry/Hardhat fork test pinned at a stated block + decoded tx trace; chain and fork RPC noted |
| Mobile / native | frida/adb command sequence or minimal patch diff |
| Everything else | The smallest artifact that triggers the bug — nothing more |

The PoC demonstrates, it does not explore. No weaponization, no
persistence, no data staging beyond the proof.

## What invalidates a finding

Evidence that kills the finding — check before filing:

- **Missing committed-state check.** A 200 response with unchanged
  database or chain state is not a bug. Capture the post-state, not just
  the response.
- **Response-only assumptions.** `"deleted": true` in JSON while the
  resource still exists means the response lied — re-fetch the resource.
- **Environment confusion.** Staging vs production, test-mode keys,
  feature flags. Record the environment; a vuln that only exists in test
  config is out.
- **Cached or stale responses.** Prove liveness (nonce, `Date` header)
  before claiming the trigger worked.
- **Self-inflicted state.** The bug only fires because of your own earlier
  change you forgot to record — replay from clean state.
