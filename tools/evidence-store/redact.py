#!/usr/bin/env python3
"""Secret redactor for evidence captures.

Ports helm/packages/runtime/src/capture.ts: SECRET_RES plus the ordering
that matters — redact BEFORE truncate, so a token straddling the byte cap
can't be half-stored. Best-effort, defense in depth; never a guarantee.

Usage: redact.py [--max-bytes N] < in > out
"""
import argparse
import re
import sys

SECRET_RES = [
    # PEM-style private key blocks first — a block contains base64 lines
    # that could otherwise be half-matched by the generic shapes below.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
               r"-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*"),          # generic Bearer
    re.compile(r"sk-ant-[A-Za-z0-9_-]+"),                     # Anthropic keys
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),                   # generic sk- keys
    re.compile(r"\bgh[pos]_[A-Za-z0-9]{20,}"),                # GitHub ghp_/gho_
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),  # JWTs
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                      # AWS access keys
]
_PLACEHOLDER = "[redacted]"


def redact(text):
    for r in SECRET_RES:
        text = r.sub(_PLACEHOLDER, text)
    return text


def main():
    ap = argparse.ArgumentParser(
        description="Redact known secret shapes, then optionally truncate. "
                    "Redaction always runs before --max-bytes truncation.")
    ap.add_argument("--max-bytes", type=int, default=None,
                    help="truncate UTF-8 output to N bytes after redaction")
    args = ap.parse_args()

    text = sys.stdin.buffer.read().decode("utf-8", "replace")
    out = redact(text)
    if args.max_bytes is not None and args.max_bytes >= 0:
        out = out.encode("utf-8")[: args.max_bytes].decode("utf-8", "ignore")
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
