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
    r"<(?:img|iframe|script|source|video|audio|link)\b[^>]{0,300}?"
    r"(?:src|href)\s*=\s*[\"']?\s*(https?://[^\s\"'>]+)", re.I)
_EG_URL_BLOB = re.compile(
    r"https?://[^\s)\]\"'<>]*[A-Za-z0-9+/=_-]{80,}")


def _fold(text):
    """NFKC + strip invisibles + confusable→Latin (what a reader actually sees)."""
    t = unicodedata.normalize("NFKC", text)
    return _STRIP_RE.sub("", t).translate(_CONFUSABLES)


def _snippet(m, text):
    match = m.group(0)
    if len(match) > _MAX_MATCH:
        match = match[:_MAX_MATCH] + "...(%d chars)" % len(m.group(0))
    s, e = m.span()
    ctx = text[max(0, s - _CTX):e + _CTX]
    return re.sub(r"\s+", " ", match), re.sub(r"\s+", " ", ctx).strip()


def scan(text):
    """One hit per rule: raw text first, folded text as fallback."""
    folded = _fold(text)
    flat = re.sub(r"\s+", " ", folded)
    hits = []
    for r in RULES:
        m = r["re"].search(text)
        if m:
            match, ctx = _snippet(m, text)
            hits.append({"rule": r["id"], "severity": r["sev"],
                         "label": r["label"], "match": match,
                         "context": ctx, "normalized": False})
            continue
        if r["unicode"]:
            continue
        # Role prefix keeps its anchors; everything else runs on the
        # whitespace-collapsed fold so "ignore all\nprevious instructions"
        # and "Ig<ZWSP>nore" land as one payload.
        target = folded if r["id"] == "grip-role-prefix" else flat
        src = target
        m = r["re"].search(src)
        if m is None and src is not folded:
            src = folded
            m = r["re"].search(src)
        if m:
            match, ctx = _snippet(m, src)
            hits.append({"rule": r["id"], "severity": r["sev"],
                         "label": r["label"], "match": match,
                         "context": ctx, "normalized": True})
    return hits


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


def egress_scan(text):
    """Outbound-only checks layered on scan(): remote images/auto-fetch
    tags (EchoLeak) and blob-carrying URLs in generated output."""
    hits = []
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
            match, ctx = _snippet(m, text)
            hits.append({"rule": rule, "severity": sev, "label": label,
                         "match": match, "context": ctx,
                         "normalized": False})
    return hits


def sanitize(text):
    """Strip invisible/format chars, then excise each rule match."""
    s = _STRIP_RE.sub("", text)
    for r in RULES:
        if r["unicode"]:
            continue
        s = r["re"].sub("[removed:%s]" % r["id"], s)
    return s


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
        out = sanitize(text)
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
