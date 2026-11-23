# evidence-store

Integrity plumbing for `evidence/<finding-id>/` dirs (see
`skills/evidence` for the capture standard). Two stdlib CLIs: `store.py`
pins a finding's context and file digests into a tamper-evident manifest;
`redact.py` strips known secret shapes out of captures before they're
stored or quoted. Python 3.9+.

## store.py — manifest write + verify

```sh
python3 store.py digest evidence/int-042-a/request.txt   # sha256 for authoring
python3 store.py write  evidence/int-042-a < manifest.json
python3 store.py verify evidence/int-042-a
```

The manifest is a strict-JSON binding — a port of clone-attack-security's
`RunBinding` (every field digest-bound) adapted to our dir layout. Exact
key set required:

```json
{
  "schema_version": 1,
  "finding_id": "int-042-a",
  "workspace": "local",
  "target": "acme",
  "intent": "int-042",
  "rule": "PB-1",
  "verifier": "validation-worker",
  "captured_at": "2026-11-23T14:02:00Z",
  "files": {"request.txt": "<sha256>", "response.txt": "<sha256>", "notes.md": "<sha256>"}
}
```

- `finding_id` must equal the directory name — the binding can't be moved.
- `files` maps each evidence file to its sha256 (get them via
  `store.py digest`). Filenames must be plain basenames — no separators,
  no `..`.
- Parser is fail-closed: ≤16KB, strict UTF-8, duplicate keys rejected,
  `NaN`/`Infinity` rejected, exact key-set match, `schema_version==1`,
  id grammar `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, strict `...Z` timestamp.
- `write` refuses if `evidence.json` already exists — append-once, same
  rule as the skill. It writes the manifest verbatim plus an
  `evidence.sha256` sidecar in `sha256sum` format (`shasum -c` works on it).
- `verify` re-binds: sidecar digest vs `evidence.json` bytes, strict
  re-parse, finding_id vs dir name, and a live re-hash of every file in
  `files`. Emits a per-check JSON report.

Exit codes: `0` ok, `1` validation/verification failure, `2` usage/IO.

## redact.py — secrets out of captures

```sh
python3 redact.py < response.txt > response.redacted.txt
python3 redact.py --max-bytes 4096 < tool-output.log > excerpt.txt
```

Ports helm's `capture.ts` contract: **redact first, truncate second** — a
token straddling a length cap must not be half-stored. Patterns:

| shape | regex sketch |
|---|---|
| PEM private-key blocks | `-----BEGIN ... PRIVATE KEY----- … -----END` |
| generic Bearer | `Bearer <token68>` |
| Anthropic | `sk-ant-…` |
| generic `sk-` (OpenAI etc.) | `sk-<16+>` |
| GitHub `ghp_`/`gho_` | `gh[pos]_<20+>` |
| JWTs (incl. admin keys) | `eyJ…​.…​.…` |
| AWS access keys | `AKIA<16>` |

Replacement is `[redacted]`; `--max-bytes` truncates the UTF-8 output
*after* redaction (decode-side `ignore` so no dangling half-codepoint).
Input is decoded UTF-8 with `replace` — a binary capture still flows
through rather than crashing the pipeline.

Best-effort only: novel secret shapes pass through untouched. Evidence
policy still applies — real user data ends the test path; own test tokens
are marked `# test-account credential` in `notes.md`.

## Where it fits

`skills/evidence` mandates append-once, verbatim captures; `store.py` is
how a verifier proves the dir it re-checked is the dir the finder wrote —
context fields bound, every file digest-bound, manifest itself digest-
pinned. `redact.py` runs on the way *in*: capture → `redact.py` →
evidence dir → `store.py write` → verifier runs `store.py verify` before
`skills/reporter` may draft.
