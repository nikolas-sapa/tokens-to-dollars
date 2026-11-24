#!/usr/bin/env python3
import argparse
import shutil
from pathlib import Path

FILES = {
    "memory/lessons/platforms.md": """# lessons/platforms - cross-program platform lessons
# What yields and what burns per platform (HackerOne, Immunefi, Intigriti, VRPs, ...).
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/lessons/engagement-types.md": """# lessons/engagement-types - what actually yields per engagement type
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/lessons/technique-yield.md": """# lessons/technique-yield - yield ledger: playbook ids and check categories, ranked
# Recomputed from memory/ledger.md via tools/ledger/ledger.py; drives intent routing.
# Append-dominant: correct by striking through the old line, never silent edits.
""",
    "memory/engagements.md": """# engagements - index of closed engagements
# Row format: | date | host | type | outcome | memory-updated |

| date | host | type | outcome | memory-updated |
|------|------|------|---------|----------------|
""",
    "memory/ledger.md": """# ledger - append-only token spend + payout accounting (see skills/token-ledger)
# Intent rows: one per closed intent. est-$ bare = from real usage, 'e' suffix = estimated.
# Payout rows: one per finding status change. Never edit rows; corrections are new rows.

| date | program | intent-id | worker | model | in-tokens | out-tokens | est-$ | outcome | finding-id |
|------|---------|-----------|--------|-------|-----------|------------|-------|---------|------------|

| date | program | finding-id | status | amount |
|------|---------|------------|--------|--------|
""",
}

DIRS = ["memory/targets", "reports", "data", "knowledge"]

RECON_TOOLS = ("subfinder", "nuclei", "katana", "ffuf", "dnsx", "gau",
               "trufflehog")


def main():
    ap = argparse.ArgumentParser(description="Create the gitignored local-state skeleton.")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]),
                    help="repo root (default: parent of tools/)")
    args = ap.parse_args()
    root = Path(args.root)

    for rel, content in FILES.items():
        p = root / rel
        if p.exists():
            print("skipped  %s (exists)" % rel)
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        print("created  %s" % rel)
    for rel in DIRS:
        p = root / rel
        if p.exists():
            print("skipped  %s/ (exists)" % rel)
        else:
            p.mkdir(parents=True, exist_ok=True)
            print("created  %s/" % rel)
    missing = [t for t in RECON_TOOLS if shutil.which(t) is None]
    if missing:
        print("warning: recon tools not on PATH "
              "(tools/wrap shells out to these): %s" % ", ".join(missing))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
