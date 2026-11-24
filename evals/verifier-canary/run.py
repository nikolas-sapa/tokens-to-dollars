#!/usr/bin/env python3
"""Verifier-canary harness — verify the verifier.

Each fixture in fixtures/*.json is a canary agent output: a claimed
finding plus the artifacts it would have produced (facts line, worker
trace, receipt, stored bodies, dedupe record). run.py materializes each
canary into a temp dir and pushes it through the repo's real gates:

  no-tool-calls   claims_finding with an empty tool_calls list
  receipt-schema  receipt-format invariants: claim/status/artifacts/
                  notEstablished + sha256 match on every artifact
  dedupe-novelty  dedupe-check rules: novel requires a searched list;
                  non-novel verdicts kill or reroute the finding
  soliloquy       tools/fact-verify/verify_claims.py --facts --trace
  verbatim-poe    verify_claims.py --verbatim on the evidence dir
  content-scan    tools/content-scan/scan.py over the evidence bundle

A canary's expected verdict is rejected or flagged; the fixture also
declares the expected outcome of every gate, so a gate that quietly
stops rejecting (or starts rejecting everything) fails the run. A null
canary scoring >0 means the verifier is broken, not that the canary got
smarter. Exit 1 on any pass-through or expectation mismatch.

Usage:
  run.py            # table, exit 1 on any unexpected outcome
  run.py --json     # machine-readable report
Python 3.9+, stdlib only.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE_DIR = HERE / "fixtures"
VERIFY = HERE.parent.parent / "tools" / "fact-verify" / "verify_claims.py"
SCAN = HERE.parent.parent / "tools" / "content-scan" / "scan.py"


def load_fixtures():
    out = []
    for p in sorted(FIXTURE_DIR.glob("*.json")):
        fx = json.loads(p.read_text(encoding="utf-8"))
        fx["_file"] = p.name
        out.append(fx)
    return out


def materialize(fx, wd):
    """Write the canary's artifacts to wd. `sha256: "AUTO"` in a receipt
    artifact resolves to the real digest of the materialized body file."""
    if fx.get("facts_md") is not None:
        (wd / "facts.md").write_text(fx["facts_md"], encoding="utf-8")
    (wd / "trace.txt").write_text(fx.get("trace") or "", encoding="utf-8")
    for name, text in (fx.get("bodies") or {}).items():
        p = wd / "bodies" / name
        p.parent.mkdir(exist_ok=True)
        p.write_text(text, encoding="utf-8")
    rec = fx.get("receipt")
    if isinstance(rec, dict):
        rec = json.loads(json.dumps(rec))
        for art in rec.get("artifacts") or []:
            if isinstance(art, dict) and art.get("sha256") == "AUTO":
                ap = wd / art.get("path", "")
                art["sha256"] = (hashlib.sha256(ap.read_bytes()).hexdigest()
                                 if ap.is_file() else "0" * 64)
        (wd / "receipt.json").write_text(
            json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")


# ── Gates ────────────────────────────────────────────────────────────
# Each returns (outcome, detail); outcome in reject | flag | pass | skip.

def gate_tool_calls(fx, wd):
    out = fx.get("agent_output") or {}
    calls = out.get("tool_calls") or []
    if out.get("claims_finding") and not calls:
        return "reject", "finding claimed with zero tool calls"
    return "pass", "%d tool call(s)" % len(calls)


def _materialized_receipt(fx, wd):
    rp = wd / "receipt.json"
    if rp.is_file():
        return json.loads(rp.read_text(encoding="utf-8"))
    return fx.get("receipt")


def gate_receipt_schema(fx, wd):
    rec = _materialized_receipt(fx, wd)
    if not isinstance(rec, dict):
        if not (fx.get("agent_output") or {}).get("claims_finding"):
            return "skip", "no finding claimed"
        return "reject", "no verification receipt"
    missing = [k for k in ("claim", "status", "artifacts", "notEstablished")
               if k not in rec]
    if missing:
        return "reject", "receipt missing %s" % ", ".join(missing)
    if rec.get("status") not in ("confirmed", "suspected"):
        return "reject", "status %r" % rec.get("status")
    if not rec.get("claim"):
        return "reject", "empty claim"
    arts = rec.get("artifacts")
    if not isinstance(arts, list) or not arts:
        return "reject", "artifacts not a non-empty list"
    for i, a in enumerate(arts):
        if not isinstance(a, dict) or not a.get("path") or not a.get("sha256"):
            return "reject", "artifact %d lacks path/sha256" % i
        p = wd / a["path"]
        if not p.is_file():
            return "reject", "artifact %s absent" % a["path"]
        if hashlib.sha256(p.read_bytes()).hexdigest() != a["sha256"]:
            return "reject", "sha256 mismatch on %s" % a["path"]
    if not isinstance(rec.get("notEstablished"), list):
        return "reject", "notEstablished not a list"
    return "pass", "receipt schema + digests ok"


def gate_dedupe(fx, wd):
    d = fx.get("dedupe")
    if not isinstance(d, dict):
        if not (fx.get("agent_output") or {}).get("claims_finding"):
            return "skip", "no finding claimed"
        return "reject", "no dedupe record"
    v = d.get("verdict")
    if v == "novel":
        if not d.get("searched"):
            return "reject", "novel with empty searched list"
        return "pass", "novel, %d source(s) searched" % len(d["searched"])
    if v in ("duplicate", "partial-overlap", "known-accepted-risk"):
        return "reject", "verdict %s%s" % (
            v, " without citations" if not d.get("matches") else "")
    return "reject", "unknown verdict %r" % v


def gate_soliloquy(fx, wd):
    if not fx.get("facts_md"):
        if not (fx.get("agent_output") or {}).get("claims_finding"):
            return "skip", "no finding claimed"
        return "reject", "no grounded facts recorded"
    proc = subprocess.run(
        [sys.executable, str(VERIFY), "--facts", str(wd / "facts.md"),
         "--trace", str(wd / "trace.txt")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = [json.loads(l) for l in proc.stdout.decode("utf-8").splitlines()
             if l.strip()]
    if proc.returncode != 0:
        bad = sorted({v.get("verdict", "?") for v in lines}) or ["crash"]
        return "reject", "verify_claims: %s" % ",".join(bad)
    if not lines:
        return "reject", "verify_claims emitted no verdicts"
    return "pass", "%d node(s) grounded" % len(lines)


def gate_verbatim(fx, wd):
    rec = _materialized_receipt(fx, wd)
    if not isinstance(rec, dict) or not rec.get("quotes"):
        return "skip", "no receipt quotes to check"
    proc = subprocess.run(
        [sys.executable, str(VERIFY), "--facts", str(wd), "--verbatim"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        return "reject", "verify_claims --verbatim: missing-quote"
    return "pass", "poe-verified"


def gate_content_scan(fx, wd):
    bundle = "\n".join([
        (fx.get("agent_output") or {}).get("claim_text") or "",
        fx.get("facts_md") or "",
        fx.get("trace") or "",
        json.dumps(fx.get("receipt") or {}, ensure_ascii=False),
        "\n".join((fx.get("bodies") or {}).values()),
    ])
    proc = subprocess.run([sys.executable, str(SCAN)],
                          input=bundle.encode("utf-8"),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    v = json.loads(proc.stdout.decode("utf-8"))["verdict"]
    return ("flag" if v in ("hostile", "suspicious") else "pass"), "scan: %s" % v


GATES = [
    ("no-tool-calls", gate_tool_calls),
    ("receipt-schema", gate_receipt_schema),
    ("dedupe-novelty", gate_dedupe),
    ("soliloquy", gate_soliloquy),
    ("verbatim-poe", gate_verbatim),
    ("content-scan", gate_content_scan),
]


def evaluate(fx):
    with tempfile.TemporaryDirectory(prefix="canary-") as d:
        wd = Path(d)
        materialize(fx, wd)
        observed = {}
        for name, fn in GATES:
            outcome, detail = fn(fx, wd)
            observed[name] = {"outcome": outcome, "detail": detail}
    ocs = [o["outcome"] for o in observed.values()]
    verdict = ("rejected" if "reject" in ocs
               else "flagged" if "flag" in ocs
               else "accepted")
    exp = fx["expect"]
    mismatches = [{"gate": g, "want": want,
                   "got": observed[g]["outcome"],
                   "detail": observed[g]["detail"]}
                  for g, want in exp["gates"].items()
                  if observed[g]["outcome"] != want]
    passed = verdict == exp["verdict"] and not mismatches
    return {"id": fx["id"], "file": fx["_file"],
            "expected": exp["verdict"], "observed": verdict,
            "gates": observed, "mismatches": mismatches,
            "pass": passed}


def print_table(results):
    gates = [g for g, _ in GATES]
    print("%-11s %-9s %-9s %s" % ("fixture", "expected", "observed", "gates"))
    print("-" * 78)
    for r in results:
        cells = " ".join("%s=%s" % (g.split("-")[0],
                                    r["gates"][g]["outcome"][:4])
                         for g in gates)
        tag = "pass" if r["pass"] else "PASS-THROUGH"
        print("%-11s %-9s %-9s %s  %s"
              % (r["id"], r["expected"], r["observed"], cells, tag))
        for m in r["mismatches"]:
            print("    ! %s: expected %s, got %s (%s)"
                  % (m["gate"], m["want"], m["got"], m["detail"]))
    print("-" * 78)
    n = len(results)
    ok = sum(1 for r in results if r["pass"])
    print("%d/%d canaries died as designed" % (ok, n))


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true",
                    help="emit the full report as JSON instead of the table")
    args = ap.parse_args()

    for tool in (VERIFY, SCAN):
        if not tool.exists():
            sys.exit("error: gate tool not found at %s" % tool)
    fixtures = load_fixtures()
    if not fixtures:
        sys.exit("error: no fixtures in %s" % FIXTURE_DIR)

    results = [evaluate(fx) for fx in fixtures]
    if args.json:
        print(json.dumps({"fixtures": results,
                          "passed": sum(1 for r in results if r["pass"]),
                          "total": len(results)},
                         indent=2, ensure_ascii=False))
    else:
        print_table(results)

    # Hard fail: any canary accepted, or any gate outcome off-spec. The
    # null canary above all: if it scored >0 the verifier is broken.
    if any(not r["pass"] for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
