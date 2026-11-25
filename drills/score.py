#!/usr/bin/env python3
"""score.py — drill scorer for the hunt skill's vault-target fixture.

Stdlib only, no network. Reads the agent's findings markdown plus the
fixture's expected-findings.md, matches findings against drill bugs/traps
using the keyword grammar documented in the scoring block, and prints:

  precision        found-real / total findings the agent reported
  recall           found-real / total planted bugs (6)
  trap-discipline  traps avoided / total planted traps (4)
  hints            one per missed bug

Usage:
  python3 drills/score.py <findings.md> [--expected drills/vault-target/expected-findings.md]

The findings file is expected to carry one markdown heading (## or deeper)
per finding, with anything the auditor rejected under a heading matching
"ruled out" / "not flagged" / "false positive" / "excluded" / "rejected".
Everything before such a heading is positive space; trap keywords found in
positive space count as flagged traps. Matching is deterministic substring,
not semantic — treat the scorecard as a lower bound, not ground truth.
"""

import os
import re
import sys

RULED_OUT_HEADING = re.compile(
    r"^#{1,6}\s.*(ruled[ -]?out|not[ -]?flag|false[ -]?positive|rejected|excluded|non[ -]?finding)",
    re.IGNORECASE,
)
FINDING_HEADING = re.compile(r"^#{2,6}\s+\S", re.MULTILINE)


def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def parse_expected(text):
    """Extract the fenced ```scoring block into bug/trap expectation dicts."""
    match = re.search(r"```scoring\n(.*?)```", text, re.DOTALL)
    if not match:
        raise ValueError("no ```scoring block found in expected-findings.md")
    bugs, traps = {}, {}
    for raw in match.group(1).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        kind = parts[0]
        if kind == "bug":
            if len(parts) != 7:
                raise ValueError("malformed bug line (want 7 fields): %s" % line)
            _, ident, sev, path, lineno, keys, note = parts
        elif kind == "trap":
            if len(parts) != 6:
                raise ValueError("malformed trap line (want 6 fields): %s" % line)
            _, ident, path, lineno, keys, note = parts
            sev = "n/a"
        else:
            raise ValueError("unknown scoring kind %r in line: %s" % (kind, line))
        clauses = []
        for clause in keys.split(","):
            groups = [g.strip().lower().split("/") for g in clause.strip().split("+")]
            clauses.append(groups)
        entry = {
            "id": ident,
            "severity": sev,
            "path": path,
            "line": lineno,
            "clauses": clauses,
            "note": note,
        }
        if kind == "bug":
            bugs[ident] = entry
        else:
            traps[ident] = entry
    if not bugs or not traps:
        raise ValueError("scoring block parsed to empty bugs/traps")
    return bugs, traps


def split_positive(text):
    """Split findings into positive space and ruled-out space at the first
    ruled-out-style heading."""
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        if RULED_OUT_HEADING.match(line):
            return "\n".join(lines[:idx]), "\n".join(lines[idx:])
    return text, ""


def clause_hit(clauses, haystack):
    """A clause is ANDed groups of ORed synonyms; any single fully-matching
    clause scores a hit. Synonyms are lowercase substrings."""
    for clause in clauses:
        if all(any(syn in haystack for syn in group) for group in clause):
            return True
    return False


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return 2
    findings_path = argv[1]
    expected_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "vault-target", "expected-findings.md")
    if "--expected" in argv:
        idx = argv.index("--expected")
        if idx + 1 >= len(argv):
            print("error: --expected needs a path", file=sys.stderr)
            return 2
        expected_path = argv[idx + 1]

    for path, label in ((findings_path, "findings"), (expected_path, "expected")):
        if not os.path.isfile(path):
            print("error: %s file not found: %s" % (label, path), file=sys.stderr)
            return 2

    bugs, traps = parse_expected(load(expected_path))
    findings_text = load(findings_path)
    positive, ruled_out = split_positive(findings_text)
    pos = positive.lower()
    out = ruled_out.lower()

    found, missed = [], []
    for ident, bug in bugs.items():
        (found if clause_hit(bug["clauses"], pos) else missed).append(bug)

    flagged, avoided = [], []
    for ident, trap in traps.items():
        row = dict(trap)
        row["ruled_out_explicitly"] = clause_hit(trap["clauses"], out) or trap["path"].lower() in out
        (flagged if clause_hit(trap["clauses"], pos) else avoided).append(row)

    headings = len(FINDING_HEADING.findall(positive))
    total_found = max(headings, len(found) + len(flagged))
    precision = (len(found) / total_found) if total_found else None
    recall = len(found) / len(bugs)
    discipline = len(avoided) / len(traps)

    print("=" * 60)
    print("DRILL SCORECARD — vault-target")
    print("=" * 60)
    print("findings file : %s" % findings_path)
    print("expected      : %s" % expected_path)
    print("positive space: %d chars, %d finding headings" % (len(positive), headings))
    print("")
    print("bugs found     : %d/%d   recall          %.2f" % (len(found), len(bugs), recall))
    if precision is None:
        print("precision      : n/a (no findings reported)")
    else:
        print("precision      : %.2f   (%d real / %d reported)" % (precision, len(found), total_found))
    print("trap-discipline: %.2f   (%d/%d traps avoided)" % (discipline, len(avoided), len(traps)))
    print("")
    print("--- per-bug ---")
    for ident in sorted(bugs):
        bug = bugs[ident]
        state = "FOUND " if bug in found else "MISSED"
        print("  %s [%s] %-8s %s:%s" % (bug["id"], state, bug["severity"], bug["path"], bug["line"]))
        if bug in missed:
            print("       hint: %s" % bug["note"])
    print("")
    print("--- per-trap ---")
    for ident in sorted(traps):
        trap = traps[ident]
        if any(t["id"] == ident for t in flagged):
            print("  %s [FLAGGED]  false positive — %s" % (ident, trap["note"]))
        else:
            extra = " (explicitly ruled out — good)" if any(
                t["id"] == ident and t["ruled_out_explicitly"] for t in avoided) else ""
            print("  %s [avoided]%s" % (ident, extra))
    print("")
    if len(found) == len(bugs) and not flagged:
        print("VERDICT: clean sweep — full recall, zero false positives.")
    elif not found:
        print("VERDICT: nothing found. Run the drill per drills/RUN.md.")
    else:
        print("VERDICT: partial — %d missed, %d trap(s) flagged." % (len(missed), len(flagged)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
