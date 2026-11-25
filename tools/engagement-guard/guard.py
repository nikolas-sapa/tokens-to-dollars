#!/usr/bin/env python3
"""engagement-guard — fail if engagement intelligence leaks into tracked files.

Engagement data (target names, findings, manifests, notes) lives ONLY in
gitignored state: memory/, reports/, knowledge/, out/. Tracked files —
including docs/ — are project documentation. This guard is the tripwire:
it scans `git ls-files` content for markers of live engagement state and
exits 1 if any are found. Run in CI and as a local pre-commit hook.

Markers checked:
  1. Directory names of memory/targets/*/ (engagement handles) appearing
     in any tracked file outside the guard's own fixtures.
  2. Literal strings 'memory/targets/', 'reports/<name>/' paths.
  3. 'roe-manifest' outside skills/tools documentation that defines the
     concept (allowlisted paths).

Exit 0 clean, 1 leak found, 2 usage/environment error.
"""
import os
import re
import subprocess
import sys

# Handles that collide with ordinary English need stronger evidence:
# capitalized usage or path-shaped context. Exact handle matches that are
# rare strings (walletconnect, hastra) flag case-insensitively anywhere.
COMMON_WORDS = {"across", "global", "metric", "origin", "sky", "jackal"}

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Files allowed to mention engagement-shaped concepts (they define the
# mechanism, never carry live engagement data).
ALLOWED_PATHS = {
    "tools/engagement-guard/guard.py",
    "AGENTS.md", "README.md", "docs/first-hunt.md", "docs/threat-model.md",
    "docs/responsible-use.md", "docs/install-matrix.md",
    "docs/mcp-integrations.md", "docs/submitting-programs.md",
    "docs/privacy.md", "docs/terms-of-use.md", "CONTRIBUTING.md",
}
ALLOWED_PREFIXES = ("skills/", "tools/", "evals/", "drills/", ".github/")


def tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True,
                         text=True)
    if out.returncode != 0:
        sys.stderr.write("engagement-guard: git ls-files failed\n")
        sys.exit(2)
    return [l for l in out.stdout.splitlines() if l.strip()]


def engagement_handles():
    tdir = os.path.join(ROOT, "memory", "targets")
    if not os.path.isdir(tdir):
        return []
    return sorted(d for d in os.listdir(tdir)
                  if os.path.isdir(os.path.join(tdir, d)) and len(d) >= 4)


def allowed(path):
    return path in ALLOWED_PATHS or path.startswith(ALLOWED_PREFIXES)


def main():
    handles = engagement_handles()
    findings = []
    for path in tracked_files():
        if allowed(path):
            continue
        full = os.path.join(ROOT, path)
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except (OSError, UnicodeError):
            continue
        for h in handles:
            if h.lower() in COMMON_WORDS:
                cap = re.search(r"\b%s\b" % re.escape(h.capitalize()), text)
                pathy = re.search(r"[/`\s]%s/|targets/%s\b|reports/%s\b"
                                  % (re.escape(h),) * 3, text)
                if cap or pathy:
                    findings.append((path, "engagement handle %r" % h))
            elif re.search(r"\b%s\b" % re.escape(h), text, re.IGNORECASE):
                findings.append((path, "engagement handle %r" % h))
        for marker in ("memory/targets/", "roe-manifest"):
            if marker in text:
                findings.append((path, "engagement-state path %r" % marker))
    if findings:
        seen = set()
        for path, why in findings:
            if (path, why) in seen:
                continue
            seen.add((path, why))
            sys.stderr.write("LEAK: %s — %s\n" % (path, why))
        sys.stderr.write(
            "engagement-guard: %d leak(s). Engagement data belongs in "
            "gitignored memory/ reports/ — never in tracked files.\n"
            % len(seen))
        return 1
    print("engagement-guard: clean (%d tracked files, %d live handles)"
          % (len(tracked_files()), len(handles)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
