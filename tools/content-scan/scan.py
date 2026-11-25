#!/usr/bin/env python3
"""Deterministic pre-planner content scanner.

Pipes fetched, attacker-influenced content (HTTP bodies, JS bundles, tool
output, disclosed writeups) through ported signature tables before it
reaches the planner. Emits a JSON verdict; --sanitize emits an
invisibles-stripped copy with matched spans excised. --egress flips
direction: the same pass runs on OUTBOUND agent-generated content plus
exfil-channel rules (remote images/auto-fetch links, blob-carrying URLs).
Python 3.9+, stdlib only.

Rules ported from:
  toolfence/src/signatures.ts           8 known-bad tool-poisoning signatures
  toolfence/src/checks/index.ts         injection patterns, sensitive caps,
                                        unicode hygiene
  grip-browser/grip/security/injection.py  role anchors, confusable fold
"""
import argparse
import json
import re
import sys
import unicodedata
from pathlib import Path
from urllib.parse import urlparse

_CTX = 40          # context chars each side of a match
_MAX_MATCH = 120   # truncated match length

# ── Rule tables ───────────────────────────────────────────────────────────
# (id, severity, pattern, label). Severity order: info low medium high critical.

SIGNATURES = [  # toolfence signatures.ts — known-bad MCP/tool patterns
    ("sig-tool-poison-readfile-secrets", "critical",
     r"\b(read|open|cat|load|fetch|access|exfiltrat)\w*\b.{0,60}?"
     r"(\.ssh|id_rsa|\.aws/credentials|\.env\b|cursor\.json|mcp\.json|claude_desktop_config)",
     "instructs agent to read local secret/config files (tool-poisoning)"),
    ("sig-rug-pull-conditional", "high",
     r"\b(after|once|on)\s+(the\s+)?\d+\s*(uses?|calls?|invocations?|times?|days?)\b",
     "conditional/time-gated behavior change (rug-pull)"),
    ("sig-cross-tool-shadow", "high",
     r"\b(instead\s+of|override|replace|shadow|intercept)\s+(the\s+)?\w+\s+tool\b",
     "references/overrides another named tool (cross-tool shadowing)"),
    ("sig-data-to-external", "critical",
     r"\b(send|post|forward|upload|report|transmit)\b.{0,50}?(to\s+)?(https?://|[\w.-]+@[\w.-]+\.\w+)",
     "instructs sending data to a hardcoded external address/URL"),
    ("sig-base64-blob-instruction", "high",
     r"[A-Za-z0-9+/]{120,}={0,2}",
     "long base64/hex blob (obfuscated instruction smuggling)"),
    ("sig-jailbreak-language", "high",
     r"\b(developer\s+mode|jailbreak|DAN\s+mode|do\s+anything\s+now|unfiltered\s+(mode|response)|without\s+(any\s+)?restrictions)\b",
     "jailbreak framing (developer mode / DAN / unfiltered)"),
    ("sig-coercive-trust", "medium",
     r"\b(this\s+is\s+(completely\s+)?safe|ignore\s+(any|all)\s+warnings?|do\s+not\s+ask\s+(for\s+)?(permission|confirmation)|no\s+need\s+to\s+(confirm|verify))\b",
     "preemptively dismisses safety checks"),
    ("sig-mcp-config-target", "high",
     r"\b(claude_desktop_config|cursor\s*\.?\s*json|\.cursor/mcp|\.mcp\.json|mcp_settings)\b",
     "references MCP client config files (config tampering surface)"),
]

INJECTION = [  # toolfence checks/index.ts INJECTION_PATTERNS — all critical
    ("inj-override-ignore", "critical",
     r"ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions|prompts|messages)",
     "instruction override"),
    ("inj-override-disregard", "critical",
     r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules)",
     "instruction override"),
    ("inj-system-prompt-extract", "critical",
     r"(reveal|print|repeat|expose|output)\s+(your|the)\s+(system|developer)\s+prompt",
     "system-prompt extraction"),
    ("inj-credential-exfil", "critical",
     r"(read|load|cat|print|send|exfiltrate)\b[^.]{0,40}\b(\.env|environment\s+variables?|api[_\s-]?keys?|secrets?|credentials?)",
     "credential exfiltration instruction"),
    ("inj-exfil-instruction", "critical",
     r"exfiltrat|leak\s+(the|all)|send\s+(the\s+)?(contents|data|file)\s+to\s+\S+@|email\s+\S+@",
     "exfiltration instruction"),
    ("inj-hidden-markup", "critical",
     r"<\s*(important|secret|system|hidden)\s*>|\[\[\s*system|<!--\s*inject",
     "hidden directive markup"),
    ("inj-user-concealment", "critical",
     r"do\s+not\s+(tell|inform|mention|reveal|notify|show)\s+(this\s+to\s+)?(the\s+)?user",
     "user-concealment instruction"),
    ("inj-coercive-preinstruction", "critical",
     r"before\s+(using|calling)\s+this\s+tool[,.]?\s+(you\s+must|first|always)\b",
     "coercive pre-instruction"),
    ("inj-manifest-control-write", "critical",
     r"(?:^|[\n.!?;:])\s*(?:[-*•]\s+|\d+[.)]\s+)?"
     r"(?:please\s+|you\s+(?:must|should|shall|need\s+to)\s+)?"
     r"(?:copy|write|add|append|insert|paste|merge|place|create)\b"
     r"[\s\S]{0,160}?"
     r"(?:\broe-manifest(?:\.md)?\b|\bharmless_allow\b|\ballow_g3\b"
     r"|[\"'`]workspace[\"'`]|\bworkspace\s*:|#{1,6}\s*workspace\b"
     r"|\bworkspace\b(?=\s+(?:section|key|heading|entry|line)\b)"
     r"|\b(?:section|key|heading|entry|line)\s+workspace\b)",
     "instruction to write guardian-control manifest keys"),
    ("inj-self-concealment", "critical",
     r"\bdo\s+not\s+(?:quote|mention|include|reveal|disclose|show|surface)"
     r"\s+(?:this|these)\s+(?:note|instructions?|messages?|lines?|payload)\b"
     r"[^.]{0,60}?\b(?:human|operator|reviewer|user|summary)\b",
     "self-concealment instruction"),
]

_ROLE_PREFIX = r"(?:^|\n|(?<=[.!?])\s)\s*(?:system|assistant|user)\s*:"
GRIP = [  # grip injection.py — anchored roles + framing payloads it added
    ("grip-role-prefix", "high", _ROLE_PREFIX,
     "anchored role prefix (fake conversation turn)"),
    ("grip-ignore-instructions", "critical",
     r"(ignore|disregard)\s+(?:the\s+|all\s+|any\s+)*(?:previous|prior|above|earlier|your)?\s*instructions?",
     "instruction override (bare form)"),
    ("grip-forget-instructions", "critical",
     r"forget\s+(?:all\s+)?(?:previous|your)\s+instructions?",
     "instruction override (forget)"),
    ("grip-new-instructions", "critical",
     r"new\s+instructions?\s*:",
     "instruction re-issue marker"),
    ("grip-ai-agent-notice", "high",
     r"(?:notice|instructions?|message)\s+for\s+ai\s+(?:agents?|assistants?)",
     "payload addressed at AI agents"),
    ("grip-task-changed", "critical",
     r"your\s+(?:real\s+)?task\s+has\s+changed",
     "task-substitution framing"),
    ("grip-everything-above", "critical",
     r"everything\s+written\s+above",
     "context-override framing"),
    ("grip-inst-markup", "high",
     r"\[inst\]|#{2,}\s*instruction|<\|im_start\|>|<<sys>>",
     "LLM chat-format markup smuggling"),
]

SENSITIVE = [  # toolfence SENSITIVE caps — informational notes, not verdicts
    ("cap-filesystem", "info",
     r"\b(read|write|delete|list)?\s*(file|files|filesystem|directory|directories|folder)\b|\b(read_file|write_file|fs_)\w*",
     "filesystem access capability"),
    ("cap-code-exec", "info",
     r"\b(exec|execute|shell|bash|run\s+code|run_code|subprocess|terminal|spawn)\b|\bcommand\b",
     "code/command execution capability"),
    ("cap-secrets", "info",
     r"\b(secret|secrets|credential|credentials|api[_\s-]?key|password|vault|environment\s+variable|\.env)\b",
     "secret/credential access capability"),
    ("cap-network", "info",
     r"\b(http\s+request|fetch\s+a?\s*url|webhook|web\s+search|scrape|crawl|browse\s+the\s+web|download\s+from|upload\s+to)\b",
     "outbound network capability"),
    ("cap-destructive", "info",
     r"\b(delete|drop\s+table|truncate|destroy|wipe|erase)\b",
     "destructive operation capability"),
]

UNICODE = [  # toolfence unicode hygiene — raw-text only rules
    ("uni-zero-width", "critical",
     "[\u200B-\u200D\u2060\uFEFF]",
     "zero-width/invisible characters (covert poisoning channel)"),
    ("uni-bidi", "high",
     "[\u202A-\u202E\u2066-\u2069]",
     "bidi control characters (Trojan Source reordering)"),
    ("uni-tags", "high",
     "[\U000e0000-\U000e007f]",
     "Unicode tag block (ASCII-smuggling: invisible payloads LLMs decode)"),
    ("uni-varsel", "medium",
     "[\ufe00-\ufe0f\U000e0100-\U000e01ef]",
     "variation selectors (Sneaky Bits covert channel)"),
]

# Union used for stripping in --sanitize: toolfence classes widened to grip's
# broader format-control range (incl. LRM/RLM and invisible operators).
_STRIP_RE = re.compile("[\u200b-\u200f\u2060-\u206f\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f\ufe00-\ufe0f\U000e0100-\U000e01ef]")

# grip _CONFUSABLES: NFKC does NOT fold Cyrillic lookalikes — explicit map.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ν": "v", "ο": "o", "ρ": "p",
    "α": "a", "ϲ": "c", "ѡ": "w", "м": "m", "т": "t", "н": "h", "к": "k",
})

RULES = [
    {"id": i, "sev": s, "re": re.compile(p, re.I), "label": l, "unicode": u}
    for table, u in ((SIGNATURES, 0), (INJECTION, 0), (GRIP, 0),
                     (SENSITIVE, 0), (UNICODE, 1))
    for i, s, p, l in table
]
_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Egress rules (--egress) ──────────────────────────────────────────────
# Outbound-only checks on generated content. Remote markdown images and
# HTML auto-fetch tags are the EchoLeak channel: the renderer fetches the
# URL, shipping whatever data the URL carries. Hosts in
# EGRESS_HOST_ALLOWLIST are exempt; everything else external flags.
EGRESS_HOST_ALLOWLIST = frozenset()
_EG_IMG_URL = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
_EG_IMG_REF = re.compile(r"!\[[^\]]*\]\[([^\]\s]+)\]")
_EG_REF_DEF = re.compile(r"^\s{0,3}\[([^\]]+)\]:[ \t]*(\S+)", re.M)
_EG_AUTOFETCH = re.compile(
    r"<(?:img|iframe|script|source|video|audio|link|image|embed|object|input|body|svg|use|table|td|th)\b"
    r"[^>]{0,500}?(?:src|href|srcset|poster|background|xlink:href)"
    r"\s*=\s*[\"']?\s*(https?://[^\s\"'>]+)", re.I)
_EG_CSS_URL = re.compile(
    r"\burl\(\s*[\"']?\s*(https?://[^\s\"')]+)", re.I)
_EG_META_REFRESH = re.compile(
    r"<meta\b(?=[^>]*\bhttp-equiv\s*=\s*[\"']?refresh\b)"
    r"(?=[^>]*\bcontent\s*=\s*[\"'][^\"']*?\burl\s*=\s*"
    r"(https?://[^\s\"'>;]+))[^>]*>", re.I)
_EG_URL_BLOB = re.compile(
    r"https?://[^\s)\]\"'<>]*[A-Za-z0-9+/=_-]{80,}")
_EG_COOKIE = re.compile(
    r"\b(?:set-)?cookie[\"']?\s*:\s*[^\s,;\r\n]+", re.I)
_EG_AUTHORIZATION = re.compile(
    r"\bauthorization[\"']?\s*[:=]\s*[\"']?\s*"
    r"(?:bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{4,}", re.I)
_EG_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])")
_EG_HOME_PATH = re.compile(
    r"(?<![\w.-])/(?:Users|home)/[^\s\"')\]}]+")
_IP_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_EG_RFC1918 = re.compile(
    r"(?<![\w.])(?:10(?:\." + _IP_OCTET + r"){3}"
    r"|192\.168(?:\." + _IP_OCTET + r"){2}"
    r"|172\.(?:1[6-9]|2[0-9]|3[01])(?:\." + _IP_OCTET + r"){2})(?![\w.])")

EGRESS_PRIVACY = [
    (_EG_COOKIE, "egress-cookie-header",
     "Cookie/Set-Cookie header in outbound content (session exfiltration)"),
    (_EG_AUTHORIZATION, "egress-authorization-header",
     "Authorization Bearer/Basic/token credential in outbound content"),
    (_EG_JWT, "egress-jwt-token",
     "JWT-shaped base64url credential in outbound content"),
    (_EG_HOME_PATH, "egress-local-home-path",
     "absolute local home path in outbound content"),
    (_EG_RFC1918, "egress-rfc1918-ip",
     "RFC1918 internal IP address in outbound content"),
]


_WS_CHAR = re.compile(r"\s")


def _fold_mapped(text):
    """NFKC + strip invisibles + confusable→Latin, with a source index map.

    Most compatibility folds are per-codepoint, and for those every folded
    character can point back at the raw character it came from. Canonical
    reordering/composition can make NFKC many-to-one; when the per-codepoint
    fold differs from real NFKC the map is absent and sanitize() must fail
    closed rather than pretend it knows the source span.
    """
    out = []
    index = []
    for i, ch in enumerate(text):
        for folded_ch in unicodedata.normalize("NFKC", ch):
            if _STRIP_RE.match(folded_ch):
                continue
            for mapped_ch in folded_ch.translate(_CONFUSABLES):
                out.append(mapped_ch)
                index.append(i)
    mapped = "".join(out)
    exact = _STRIP_RE.sub("", unicodedata.normalize("NFKC", text)).translate(
        _CONFUSABLES)
    cross_char = any(
        unicodedata.combining(ch) or
        (0x1100 <= ord(ch) <= 0x11ff) or  # Hangul jamo compose across chars
        (0x3130 <= ord(ch) <= 0x318f) or  # compatibility jamo
        (0xac00 <= ord(ch) <= 0xd7a3)     # Hangul syllables
        for ch in text)
    if mapped == exact and not cross_char:
        return mapped, index
    return exact, None


def _collapse_ws_mapped(text, index):
    """Whitespace-collapse like re.sub(r"\\s+", " ", text), keeping the map."""
    if index is None:
        return re.sub(r"\s+", " ", text), None
    out = []
    out_index = []
    in_ws = False
    for i, ch in enumerate(text):
        if _WS_CHAR.match(ch):
            if not in_ws:
                out.append(" ")
                out_index.append(index[i])
            in_ws = True
        else:
            out.append(ch)
            out_index.append(index[i])
            in_ws = False
    return "".join(out), out_index


def _fold(text):
    """NFKC + strip invisibles + confusable→Latin (what a reader actually sees)."""
    return _fold_mapped(text)[0]


def _normalized_views(text):
    folded, folded_index = _fold_mapped(text)
    flat, flat_index = _collapse_ws_mapped(folded, folded_index)
    return folded, folded_index, flat, flat_index


def _source_span(m, index):
    if index is None or m.end() == m.start() or m.end() > len(index):
        return None
    return index[m.start()], index[m.end() - 1] + 1


def _snippet(m, text):
    match = m.group(0)
    if len(match) > _MAX_MATCH:
        match = match[:_MAX_MATCH] + "...(%d chars)" % len(m.group(0))
    s, e = m.span()
    ctx = text[max(0, s - _CTX):e + _CTX]
    return re.sub(r"\s+", " ", match), re.sub(r"\s+", " ", ctx).strip()


def _scan(text, want_spans=False):
    """One hit per rule: raw text first, folded text as fallback."""
    folded, folded_index, flat, flat_index = _normalized_views(text)
    hits = []
    for r in RULES:
        m = r["re"].search(text)
        if m:
            match, ctx = _snippet(m, text)
            hit = {"rule": r["id"], "severity": r["sev"],
                   "label": r["label"], "match": match,
                   "context": ctx, "normalized": False}
            if want_spans:
                hit["_span"] = m.span()
            hits.append(hit)
            continue
        if r["unicode"]:
            continue
        # Anchor-sensitive rules keep the unfolded line structure; everything
        # else runs on the whitespace-collapsed fold so "ignore all\nprevious
        # instructions" and "Ig<ZWSP>nore" land as one payload.
        if r["id"] in ("grip-role-prefix", "inj-manifest-control-write"):
            targets = ((folded, folded_index),)
        else:
            targets = ((flat, flat_index), (folded, folded_index))
        for src, index in targets:
            m = r["re"].search(src)
            if m is None:
                continue
            match, ctx = _snippet(m, src)
            hit = {"rule": r["id"], "severity": r["sev"],
                   "label": r["label"], "match": match,
                   "context": ctx, "normalized": True}
            if want_spans:
                span = _source_span(m, index)
                if span is not None:
                    hit["_span"] = span
            hits.append(hit)
            break
    return hits


def scan(text):
    return _scan(text)


def verdict(hits):
    top = max((_SEV_RANK[h["severity"]] for h in hits), default=-1)
    if top >= _SEV_RANK["high"]:
        return "hostile"
    if top >= _SEV_RANK["low"]:
        return "suspicious"
    return "clean"


def scan_text(text):
    """One-call helper for corpus flaggers: {"verdict", "hits"}."""
    hits = scan(text)
    return {"verdict": verdict(hits), "hits": hits}


def _allowlisted(url):
    try:
        h = urlparse(url).hostname
    except ValueError:
        return False
    return bool(h) and h.lower() in EGRESS_HOST_ALLOWLIST


def _egress_matches(text):
    for rx, rule, label in EGRESS_PRIVACY:
        for m in rx.finditer(text):
            yield m, rule, "high", label
    refdefs = {m.group(1).lower(): m.group(2)
               for m in _EG_REF_DEF.finditer(text)}
    checks = (
        (_EG_IMG_URL, "egress-external-image", "high",
         "markdown image fetching a remote URL (EchoLeak exfil channel)",
         lambda m: m.group(1)),
        (_EG_IMG_REF, "egress-external-image-ref", "high",
         "reference-style markdown image, off-allowlist or unresolved",
         lambda m: refdefs.get(m.group(1).lower())),
        (_EG_AUTOFETCH, "egress-autofetch-tag", "high",
         "HTML auto-fetch tag loading a remote URL", lambda m: m.group(1)),
        (_EG_CSS_URL, "egress-css-url", "high",
         "CSS url() fetching a remote URL", lambda m: m.group(1)),
        (_EG_META_REFRESH, "egress-meta-refresh", "high",
         "meta refresh navigating to a remote URL", lambda m: m.group(1)),
        (_EG_URL_BLOB, "egress-url-blob", "high",
         "long base64/hex blob inside URL (data smuggling)",
         lambda m: None),
    )
    for rx, rule, sev, label, geturl in checks:
        for m in rx.finditer(text):
            url = geturl(m)
            if url and not url.lower().startswith(("http://", "https://")):
                continue  # relative/internal target — no exfil channel
            if url and _allowlisted(url):
                continue
            yield m, rule, sev, label


def egress_scan(text):
    """Outbound-only checks layered on scan(): remote images/auto-fetch
    tags (EchoLeak), blob-carrying URLs, and session/local-path material."""
    hits = []
    for m, rule, sev, label in _egress_matches(text):
        match, ctx = _snippet(m, text)
        hits.append({"rule": rule, "severity": sev, "label": label,
                     "match": match, "context": ctx,
                     "normalized": False})
    return hits


def _rule_spans(r, text, views):
    """All raw and normalized source spans for one rule in text."""
    spans = [(m.start(), m.end(), r["id"])
             for m in r["re"].finditer(text)]
    if r["unicode"]:
        return spans, False
    folded, folded_index, flat, flat_index = views
    if r["id"] in ("grip-role-prefix", "inj-manifest-control-write"):
        targets = ((folded, folded_index),)
    else:
        targets = ((flat, flat_index), (folded, folded_index))
    unmapped = False
    seen = set()
    for src, index in targets:
        for m in r["re"].finditer(src):
            span = _source_span(m, index)
            if span is None:
                unmapped = unmapped or r["sev"] != "info"
                continue
            if span in seen:
                continue
            seen.add(span)
            spans.append((span[0], span[1], r["id"]))
    return spans, unmapped


def _merge_spans(spans):
    merged = []
    for start, end, rule in sorted(spans):
        if end <= start:
            continue
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
            if rule not in merged[-1][2]:
                merged[-1][2].append(rule)
        else:
            merged.append([start, end, [rule]])
    return merged


def sanitize(text, egress=False):
    """Strip invisibles, then excise raw and normalized-only rule matches.

    Normalized-only hits are mapped back to their source spans. If a hit
    cannot be mapped, or a non-info hit survives the rewrite, the output
    fails closed instead of emitting attacker instructions verbatim. With
    egress=True, outbound privacy/exfil hits are excised under the same
    fail-closed rule.
    """
    s = _STRIP_RE.sub("", text)
    views = _normalized_views(s)
    spans = []
    unmapped = False
    for r in RULES:
        rule_spans, rule_unmapped = _rule_spans(r, s, views)
        spans.extend(rule_spans)
        unmapped = unmapped or rule_unmapped
    if unmapped:
        return "[unsafe: normalized-only content could not be redacted]"

    out = s
    for start, end, rules in sorted(_merge_spans(spans),
                                    key=lambda x: x[0], reverse=True):
        out = (out[:start] + "[removed:%s]" % "+".join(rules) +
               out[end:])
    if egress:
        egress_spans = [(m.start(), m.end(), rule)
                        for m, rule, _sev, _label in _egress_matches(out)]
        for start, end, rules in sorted(_merge_spans(egress_spans),
                                        key=lambda x: x[0], reverse=True):
            out = (out[:start] + "[removed:%s]" % "+".join(rules) +
                   out[end:])
    residual = [h for h in scan(out) if h["severity"] != "info"]
    egress_residual = egress_scan(out) if egress else []
    if residual or egress_residual:
        return "[unsafe: matched content survived sanitization]"
    return out


def scan_text(s):
    """Importable API: {verdict, hits:[{rule, severity}]}."""
    hits = scan(s)
    return {"verdict": verdict(hits),
            "hits": [{"rule": h["rule"], "severity": h["severity"]}
                     for h in hits]}


def main():
    ap = argparse.ArgumentParser(
        description="Pre-planner content scanner (tools/content-scan). "
                    "Reads stdin or --file, emits JSON verdict; "
                    "exit 0=clean 1=suspicious 2=hostile.")
    ap.add_argument("--file", default=None, help="read from path instead of stdin")
    ap.add_argument("--sanitize", action="store_true",
                    help="print sanitized copy (invisibles stripped, matched "
                         "spans excised to [removed:rule]) instead of JSON")
    ap.add_argument("--egress", action="store_true",
                    help="scan OUTBOUND content (agent-generated markdown, "
                         "URLs): full pass plus remote-image/auto-fetch/"
                         "blob-URL exfil rules")
    args = ap.parse_args()

    if args.file:
        text = Path(args.file).read_bytes().decode("utf-8", "replace")
    else:
        text = sys.stdin.buffer.read().decode("utf-8", "replace")

    hits = scan(text)
    if args.egress:
        hits += egress_scan(text)
    v = verdict(hits)
    if args.sanitize:
        out = sanitize(text, egress=args.egress)
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
        print("verdict=%s hits=%d" % (v, len(hits)), file=sys.stderr)
    else:
        print(json.dumps({"verdict": v, "hits": hits},
                         indent=2, ensure_ascii=False))
    return {"clean": 0, "suspicious": 1, "hostile": 2}[v]


if __name__ == "__main__":
    sys.exit(main())
