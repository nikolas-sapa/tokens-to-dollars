#!/usr/bin/env python3
"""Purge one engagement's local artifacts — the "one-time bounty" mode.

Distills the target's lessons into memory/lessons/ (identifiers stripped),
then moves every target-specific artifact to macOS Trash. What stays:

- memory/lessons/         — scrubbed technique lessons (knowledge, not identity)
- memory/engagements.md   — row kept, program name masked to <purged>
- memory/ledger.md        — payout row kept, program name masked to <purged>
- tools/audit-log chain   — append-only by design; never touched. It is
                            tamper-evident proof of authorized work and
                            deleting entries would break the chain anyway.

Usage:
  clean.py --program h1-example [--keep-lessons] [--dry-run] [--root DIR]
"""
import argparse, json, re, shutil, subprocess, sys
from pathlib import Path

STRIP_HOST = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def scrub(text: str, program: str) -> str:
    out = text.replace(program, "<purged>")
    out = STRIP_HOST.sub("<host>", out)
    return out


def trash(path: Path, dry: bool) -> bool:
    if not path.exists():
        return False
    if dry:
        print("dry-run  trash %s" % path)
        return True
    for cmd in (["trash"], ["/usr/bin/trash"]):
        if shutil.which(cmd[0]) or Path(cmd[0]).exists():
            r = subprocess.run(cmd + [str(path)], check=False)
            if r.returncode == 0:
                print("trashed  %s" % path)
                return True
            print("WARN trash rc=%d on %s — left in place"
                  % (r.returncode, path), file=sys.stderr)
            return False
    print("WARN no trash binary; left %s (delete manually)" % path, file=sys.stderr)
    return False


def name_hit(name: str, prog: str) -> bool:
    """Exact-name match: prog 'acme' hits 'acme', 'acme.md', and dated
    graph-archive rows 'YYYY-MM-DD-acme.*' — never 'acme-corp'/'acme2'.
    ('-' is a program-name char, so only a full tail segment matches.)"""
    stem = Path(name).stem
    if stem == prog:
        return True
    m = re.match(r"^\d{4}-\d{2}-\d{2}-(.+)$", stem)
    return bool(m and m.group(1) == prog)


def mask_line(path: Path, program: str, dry: bool) -> bool:
    if not path.exists():
        return False
    txt = path.read_text()
    # word-boundary on the program charset: masking 'acme' must not also
    # rewrite the 'acme' inside a neighbor program's 'acme-corp' rows
    pat = re.compile(r"(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_-])"
                     % re.escape(program))
    if not pat.search(txt):
        return False
    if dry:
        print("dry-run  mask %s" % path)
        return True
    path.write_text(pat.sub("<purged>", txt))
    print("masked   %s (kept for accounting)" % path)
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--program", required=True)
    ap.add_argument("--keep-lessons", action="store_true",
                    help="distill target lessons to memory/lessons/ first")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[2]))
    args = ap.parse_args()
    prog = args.program
    if not re.fullmatch(r"[A-Za-z0-9_-]+", prog):
        print("error: bad --program %r (allowed: A-Z a-z 0-9 _ -)" % prog,
              file=sys.stderr)
        return 2
    root = Path(args.root).resolve()
    mem = root / "memory"

    target = mem / "targets" / prog
    if mem not in target.resolve().parents:
        print("error: target %s escapes memory/ — refusing to trash"
              % target, file=sys.stderr)
        return 2
    if not target.exists():
        print("nothing found for program %s" % prog)
        return 1

    if args.keep_lessons and not args.dry_run:
        src = target / "lessons.md"
        if src.exists():
            dest = root / "memory" / "lessons" / "distilled.md"
            dest.parent.mkdir(parents=True, exist_ok=True)
            note = "\n## distilled engagement\n\n"
            body = scrub(src.read_text(), prog)
            with open(dest, "a") as f:
                f.write(note + body)
            print("distilled lessons -> %s (identifiers scrubbed)" % dest)

    trashed = []
    victims = {target, root / "reports" / prog}
    if (root / "reports").exists():
        victims |= {p for p in (root / "reports").iterdir()
                    if name_hit(p.name, prog)}
    if (root / "memory" / "graph-archive").exists():
        victims |= {p for p in (root / "memory" / "graph-archive").iterdir()
                    if name_hit(p.name, prog)}
    for p in victims:
        if trash(p, args.dry_run):
            trashed.append(str(p))

    for f in [root / "memory" / "engagements.md", root / "memory" / "ledger.md"]:
        mask_line(f, prog, args.dry_run)

    print(json.dumps({"program": prog, "trashed": trashed, "dry_run": args.dry_run}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
