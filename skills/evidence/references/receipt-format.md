# Verification receipt format — companion to `evidence`

`receipt.json` is the machine-checkable summary of what a finding's
evidence *actually establishes* — and, just as important, what it does
not. Ported from the open-agent-order evidence receipts
(`docs/evidence/*.json`): the pattern that made those records
judge-verifiable was that every claim carried hashes for the files it
relied on and an explicit list of what was not established.

## Core rules

- **One `claim` string** — a single sentence stating exactly what the
  evidence establishes, scoped to what was demonstrated. A narrower true
  claim beats a broader hopeful one.
- **`path` + `sha256` on every referenced file.** Any object the receipt
  leans on (request/response captures, tool output, ground truth, prior
  receipts) is linked by path and digest. A verifier recomputes; a
  mismatch means tampering or drift, not a debate.
- **`notEstablished[]` is mandatory.** Things a reader might assume the
  evidence shows but it does not — listed explicitly. Absence of the
  field is a defect, not a clean bill.
- **Cost and derived numbers carry verification labels.** A figure is
  marked when it is provider-reported rather than independently verified
  (e.g. `costBasis: "provider-reported, not independently verified"`;
  failed calls may have unknown usage). Unverified numbers are labeled,
  never silently asserted.
- **Nulls are honest.** A field that could not be measured is `null`,
  not omitted and not fabricated.

## Schema

```json
{
  "generatedAt": "2026-11-23T14:31:00Z",
  "findingId": "int-042-a",
  "status": "confirmed",
  "claim": "Role B (free-tier acct own-test-2) reads order 8817 owned by own-test-1 — object-level authorization missing on GET /v1/orders/{id}.",
  "verifiedAt": "2026-11-23T14:02:11Z",
  "replay_of": null,
  "replay": {
    "request": "evidence/int-042-a/replay.http",
    "sha256": "<hex>",
    "note": "raw request that re-fires the trigger as captured"
  },
  "artifacts": [
    {
      "path": "evidence/int-042-a/request.txt",
      "sha256": "<hex>",
      "role": "trigger capture"
    },
    {
      "path": "evidence/int-042-a/response.txt",
      "sha256": "<hex>",
      "role": "cross-tenant 200 response"
    }
  ],
  "limitation": "Proves read access only. Write/delete on the same object was not exercised; data was not read beyond the order id used to trigger.",
  "costBasis": "token-ledger reported; not independently verified",
  "notEstablished": [
    "write-path IDOR on the same object",
    "exposure of fields beyond order id in the response",
    "behaviour under the production (non-test) dataset"
  ]
}
```

## Field notes

- `status` mirrors the notes.md tag: `confirmed` (path traced end to
  end) or `suspected` (strong evidence, trigger not fully exercised).
- `replay_of` carries the trace id when the capture was produced by
  replaying a recorded trace — lineage, not decoration.
- `replay` carries a re-issuable request-level artifact (raw HTTP, curl
  snippet, or replayable trace) that fires the trigger exactly as
  captured — evidence is a thing a verifier can re-run, not prose about
  a thing that ran. `null` when the trigger is not safely replayable;
  say why in `limitation`.
- `limitation` (or per-artifact `association`/`meaning` fields like
  `referenceCheckMeaning` in the source receipts) states the boundary of
  what the linked file proves.
- `notEstablished` doubles as the triager's "what's left" list and the
  verifier's next-intent seed. If it is empty because everything really
  was established, say so in `limitation` — an empty list reads as an
  incomplete receipt.
