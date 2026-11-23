# Injection signatures — companion to `injection-defense`

The pattern table behind `tools/content-scan/scan.py`. Matching is
deliberately conservative: each rule targets a documented abuse pattern,
not a vibe, and hits are reported by rule id so a verdict can be audited.

Provenance: the known-bad signatures are ported from **toolfence**
(`src/signatures.ts`, MCP-server tool-poisoning scanner); the injection
phrasings and Unicode hygiene are ported from **grip-browser**
(`grip/security/injection.py`, page-text injection filter). Both are
keyword lists — they catch copy-paste payloads, not novel attacks.

## Known-bad signatures (toolfence)

Matched against combined text; originally aimed at MCP tool descriptions,
equally applicable to fetched content trying to steer the agent.

| Rule id | Severity | Detects |
|---|---|---|
| `sig-tool-poison-readfile-secrets` | critical | Instruction to read/exfiltrate local secret or config files — `.ssh`, `id_rsa`, `.aws/credentials`, `.env`, `cursor.json`, `mcp.json`, `claude_desktop_config` (Invariant Labs tool-poisoning disclosure, 2025) |
| `sig-data-to-external` | critical | Instruction to send/post/forward/upload data to a hardcoded external URL or email address — the exfiltration leg |
| `sig-rug-pull-conditional` | high | Conditional or time-gated behavior change — "after N uses", "on the Nth call", "after N days" (delayed-activation rug pull) |
| `sig-cross-tool-shadow` | high | Referencing or overriding another named tool — "instead of the X tool", "override the X tool" (cross-tool shadowing) |
| `sig-base64-blob-instruction` | high | Long base64/hex blob (≥120 chars) embedded in text — obfuscated instruction smuggling |
| `sig-jailbreak-language` | high | Jailbreak framing — "developer mode", "DAN mode", "do anything now", "unfiltered", "without restrictions" |
| `sig-mcp-config-target` | high | References to agent client config files — `mcp.json`, `claude_desktop_config`, `.cursor/mcp`, `mcp_settings` (client-config tampering) |
| `sig-coercive-trust` | medium | Preemptive safety dismissal — "this is completely safe", "ignore any warnings", "do not ask for permission", "no need to confirm" |

## Injection phrasings (grip-browser)

Matched against normalized text (see Unicode hygiene). Anchored where a
mid-sentence match would delete ordinary prose.

| Pattern | Detects |
|---|---|
| Fake role header | `System:` / `Assistant:` / `User:` opening a line or sentence — the page framing a conversation turn (anchored; "the system: value" mid-sentence is documentation, not a hit) |
| Instruction override | "ignore/disregard (the/all/any) (previous/prior/above/earlier/your) instructions", "forget (all) (previous/your) instructions" |
| Re-tasking | "new instructions:", "your (real) task has changed", "everything written above" |
| Agent-addressed notice | "notice/instructions/message for AI agents/assistants" — payloads with no imperative metaword the override family misses |
| Chat-format markers | `<system>`, `[inst]`, `<|im_start|>`, `<<sys>>` — smuggled turn-structure tokens |
| Markdown authority | `## instruction` heading variants — fake document authority |
| Split-payload join | a payload spanning a line break leaves individually innocent halves; surviving line pairs are re-checked joined and both dropped on a hit |

## Unicode hygiene (grip-browser `_normalize`)

Detection runs on what a reader *sees*, not the raw bytes:

| Step | What it does | Why |
|---|---|---|
| NFKC normalize | Folds compatibility forms (fullwidth, ligatures, styled math text) to plain characters | "Ｉｇｎｏｒｅ" must match "ignore" |
| Zero-width strip | Drops U+200B–U+200F, U+2060–U+206F, U+FEFF | "Ig<ZWSP>nore" renders identically and defeats every literal pattern; `--sanitize` removes these from the planner copy |
| Confusable fold | Maps Cyrillic/Greek lookalikes in the pattern vocabulary to Latin (а→a, е→e, о→o, р→p, с→c, і→i, …) | NFKC does NOT fold confusables — Cyrillic о is a distinct letter; the homoglyph bypass needs its own map |
| Case + whitespace collapse | Lowercases; collapses all whitespace to single spaces for matching | "ignore all\nprevious instructions" is one payload, not two innocent halves |
| Sentence-level excise | On `--sanitize`, only the sentences that trip a pattern are dropped; line structure and neighbouring content are kept | A whole-line blank destroys real content; a document-level rewrite destroys the line grid citations rely on |

## Semantics

- **Hits name rule ids.** A `suspicious`/`hostile` verdict must be
  explainable as "rules X, Y fired" — never a bare score.
- **Conservative by design.** Each pattern targets a documented abuse
  shape; widening the net to vibes trades away auditability. New real-
  world phrasings get appended as new rules with a provenance line.
