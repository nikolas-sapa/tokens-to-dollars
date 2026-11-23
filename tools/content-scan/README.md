# content-scan

Deterministic pre-planner scanner for fetched, attacker-influenced content —
HTTP bodies, JS bundles, tool output, disclosed writeups. The worker pipes
content through `scan.py` *before* it reaches the planner so known-bad
instruction patterns become trace warnings, not model input. Python 3.9+,
stdlib only.

## Usage

```sh
python3 scan.py < fetched-body.html          # JSON verdict to stdout
python3 scan.py --file bundle.js             # same, from a path
python3 scan.py --sanitize < fetched.html    # marked-up copy to stdout
```

Output: `{"verdict": "clean|suspicious|hostile", "hits": [{"rule",
"severity", "label", "match", "context", "normalized"}]}`.

Exit codes: `0` clean, `1` suspicious, `2` hostile — safe to gate pipes on.

Verdict mapping: any hit at high/critical → hostile; medium/low →
suspicious; info-only (`cap-*` capability notes) or none → clean.
Capability hits are awareness for the planner, not an alarm — a JS bundle
that merely *mentions* `fetch url` stays clean.

`--sanitize` prints the content with zero-width/bidi characters stripped
and every literal rule match wrapped in `[REDACTED-<rule>]...[/REDACTED]`
markers (nested where rules overlap). Verdict + hit count go to stderr;
exit code still reflects the verdict. Sanitized copy is for the planner —
the untouched original goes to the evidence dir.

## Detection passes

Each rule fires once: first on the raw text, then — for text rules — on a
*folded* copy (NFKC → strip invisibles → Cyrillic/Greek confusables →
Latin, whitespace-collapsed). Folded hits carry `"normalized": true` so a
payload split by zero-width chars (`Ig<ZWSP>nore`) or written in lookalike
glyphs is still reported, with the folded snippet as `match`. This is a
keyword net, not a control: it catches copy-paste payloads. The real
defense stays `skills/injection-defense` — content is data, provenance
labels, human-hint verification.

## Ported rules

| rule | sev | source | catches |
|---|---|---|---|
| `sig-tool-poison-readfile-secrets` | critical | toolfence signatures.ts | "read/cat … .ssh, id_rsa, .aws/credentials, .env, mcp.json" |
| `sig-rug-pull-conditional` | high | toolfence signatures.ts | "after N uses/calls/days" delayed activation |
| `sig-cross-tool-shadow` | high | toolfence signatures.ts | "instead of / override the X tool" shadowing |
| `sig-data-to-external` | critical | toolfence signatures.ts | "send/post/forward … to URL or email" exfil |
| `sig-base64-blob-instruction` | high | toolfence signatures.ts | ≥120-char base64 blob (smuggled instruction) |
| `sig-jailbreak-language` | high | toolfence signatures.ts | developer mode / DAN / unfiltered framing |
| `sig-coercive-trust` | medium | toolfence signatures.ts | "this is safe, ignore warnings, no need to confirm" |
| `sig-mcp-config-target` | high | toolfence signatures.ts | claude_desktop_config / .cursor/mcp / mcp.json |
| `inj-override-ignore` / `inj-override-disregard` | critical | toolfence checks/index.ts | "ignore/disregard previous instructions" |
| `inj-system-prompt-extract` | critical | toolfence checks/index.ts | "reveal/print your system prompt" |
| `inj-credential-exfil` | critical | toolfence checks/index.ts | "read/send … .env, api keys, credentials" |
| `inj-exfil-instruction` | critical | toolfence checks/index.ts | exfiltrate / leak / "send contents to a@b" |
| `inj-hidden-markup` | critical | toolfence checks/index.ts | `<system>`, `<secret>`, `[[system`, `<!-- inject` |
| `inj-user-concealment` | critical | toolfence checks/index.ts | "do not tell/inform the user" |
| `inj-coercive-preinstruction` | critical | toolfence checks/index.ts | "before using this tool, you must…" |
| `grip-role-prefix` | high | grip injection.py | line/sentence-anchored `System:`/`Assistant:`/`User:` |
| `grip-ignore-instructions` | critical | grip injection.py | bare "ignore instructions" (no "previous" needed) |
| `grip-forget-instructions` | critical | grip injection.py | "forget (your) instructions" |
| `grip-new-instructions` | critical | grip injection.py | "new instructions:" re-issue marker |
| `grip-ai-agent-notice` | high | grip injection.py | "notice/instructions for AI agents" |
| `grip-task-changed` | critical | grip injection.py | "your (real) task has changed" |
| `grip-everything-above` | critical | grip injection.py | "everything written above" |
| `grip-inst-markup` | high | grip injection.py | `[inst]`, `## instruction`, `<\|im_start\|>`, `<<sys>>` |
| `cap-filesystem` / `cap-code-exec` / `cap-secrets` / `cap-network` / `cap-destructive` | info | toolfence checks/index.ts | sensitive-capability nouns (planner awareness) |
| `uni-zero-width` | critical | toolfence checks/index.ts | `U+200B–200D`, `U+2060`, `U+FEFF` in content |
| `uni-bidi` | high | toolfence checks/index.ts | `U+202A–202E`, `U+2066–2069` (Trojan Source) |

Deviations from sources: toolfence's tool-metadata checks matched on tool
name+description; here the same patterns scan arbitrary fetched text.
`SENSITIVE` caps are flattened to `info` regardless of danger class.
`--sanitize` strips the union of toolfence's zero-width/bidi classes and
grip's wider format-control range (`U+200B–200F`, `U+2060–206F`, `U+FEFF`,
bidi). Grip's `<system>` and sentence-excision logic are not ported —
`inj-hidden-markup` covers the former and markers replace excision.

## flag_corpus.py

`flag_corpus.py --file <path>` (or `--in a --out b`) annotates each record in
a `.jsonl`/`.json` corpus with `"_untrusted": true`, `"_scan":
"clean|suspicious|hostile"`, `"_scan_hits": [rule ids]`; hostile records are
moved to `<file>.quarantine.jsonl`. Ingest tools call it automatically after
writing `programs.json`, `records.jsonl`, `bounties.jsonl`.

## Where it fits

`skills/injection-defense` rule 2 — instruction-like strings create a
warning, not an action. Wire it in front of the planner: worker fetches →
`scan.py` → hostile content is dropped or sanitized, the hit list lands in
the intent trace, the original lands in `evidence/<finding-id>/` (see
`tools/evidence-store`). It also pairs with the `--sanitize` output when a
page must still be reasoned over — e.g. extracting endpoints from a
poisoned JS bundle without inheriting its instructions.
