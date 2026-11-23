#!/usr/bin/env python3
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

OPEN_STATUSES = {"submitted", "triaged", "resolved"}
OUTCOME_ORDER = ("finding", "fact", "FP", "blocked")


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def is_sep(row):
    return all(not c or re.fullmatch(r":?-+:?", c) for c in row)


def parse_ledger(path):
    intents, payouts = [], []
    kind = hdr = None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not (s.startswith("|") and s.endswith("|")):
            kind = hdr = None
            continue
        row = cells(s)
        low = {c.lower() for c in row}
        if {"intent-id", "est-$"} <= low:
            kind, hdr = "intent", [c.lower() for c in row]
            continue
        if {"finding-id", "status", "amount"} <= low:
            kind, hdr = "payout", [c.lower() for c in row]
            continue
        if is_sep(row):
            continue
        if hdr and len(row) == len(hdr):
            (intents if kind == "intent" else payouts).append(dict(zip(hdr, row)))
    return intents, payouts


def money(s):
    s = (s or "").strip().lstrip("$")
    est = s.endswith("e")
    try:
        return float(s.rstrip("e")), est
    except ValueError:
        return None, est


def usd(x):
    return "$%.2f" % x


def fmt_table(headers, rows):
    rows = [[str(c) for c in r] for r in rows]
    w = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(c))
    out = ["  ".join(h.ljust(w[i]) for i, h in enumerate(headers)),
           "  ".join("-" * x for x in w)]
    out += ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)) for r in rows]
    return out


def main():
    ap = argparse.ArgumentParser(
        description="Scoreboard over memory/ledger.md (see skills/token-ledger).",
        epilog="EV here is realized: paid / spend. Predicted EV per target is "
               "planning-side, not a ledger column: EV = p_find * prec_val * "
               "(1-r_dup) * (1-r_info) * B_ref - (C_scan + p_find*C_HITL) -- "
               "terms in skills/token-ledger and tools/ledger/README.md.")
    ap.add_argument("--ledger", default="memory/ledger.md", help="ledger file (default memory/ledger.md)")
    ap.add_argument("--program", default=None, help="filter to one program")
    ap.add_argument("--ceiling", type=float, default=50.0,
                    help="warn above this spend with 0 findings, USD (default 50)")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of tables")
    args = ap.parse_args()

    if not Path(args.ledger).is_file():
        sys.exit("error: ledger not found: %s" % args.ledger)
    intents, payouts = parse_ledger(args.ledger)
    if args.program:
        pl = args.program.lower()
        intents = [r for r in intents if (r.get("program") or "").lower() == pl]
        payouts = [r for r in payouts if (r.get("program") or "").lower() == pl]

    total_spend = 0.0
    n_est = 0
    spend_prog = defaultdict(float)
    spend_model = defaultdict(float)
    spend_tech = defaultdict(float)
    oc_prog = defaultdict(lambda: defaultdict(int))
    oc_tech = defaultdict(lambda: defaultdict(int))
    for r in intents:
        amt, est = money(r.get("est-$"))
        amt = amt or 0.0
        total_spend += amt
        n_est += 1 if est else 0
        p = r.get("program") or "?"
        o = (r.get("outcome") or "?").strip()
        t = r.get("worker") or "?"
        spend_prog[p] += amt
        spend_model[r.get("model") or "?"] += amt
        spend_tech[t] += amt
        oc_prog[p][o] += 1
        oc_tech[t][o] += 1

    paid_prog = defaultdict(float)
    latest = {}
    for r in payouts:
        fid = r.get("finding-id") or "?"
        status = (r.get("status") or "").strip().lower()
        latest[fid] = (r.get("program") or "?", status)
        if status == "paid":
            amt, _ = money(r.get("amount"))
            paid_prog[r.get("program") or "?"] += amt or 0.0
    total_paid = sum(paid_prog.values())
    pipeline = [{"finding_id": f, "program": p, "status": s}
                for f, (p, s) in sorted(latest.items()) if s in OPEN_STATUSES]

    extra_oc = sorted({o for p in oc_prog.values() for o in p} - set(OUTCOME_ORDER))
    cols = list(OUTCOME_ORDER) + extra_oc

    def oc_cells(oc):
        return [oc.get(c, 0) for c in cols]

    cpf = {p: (spend_prog[p] / oc_prog[p]["finding"] if oc_prog[p]["finding"] else None)
           for p in spend_prog}
    ev_prog = {p: (paid_prog[p] / spend_prog[p] if spend_prog[p] else None)
               for p in set(list(spend_prog) + list(paid_prog))}
    ev_total = total_paid / total_spend if total_spend else None
    flags = [{"program": p, "spend_usd": spend_prog[p],
              "warning": "%s spend with 0 findings (ceiling %s)" % (usd(spend_prog[p]), usd(args.ceiling))}
             for p in sorted(spend_prog)
             if spend_prog[p] > args.ceiling and not oc_prog[p]["finding"]]

    if args.json:
        print(json.dumps({
            "ledger": args.ledger, "program": args.program, "ceiling_usd": args.ceiling,
            "spend": {"total_usd": round(total_spend, 2), "intents": len(intents),
                      "estimated_rows": n_est,
                      "per_program": dict(spend_prog), "per_model": dict(spend_model)},
            "yield": {"per_program": {p: dict(oc_prog[p]) for p in oc_prog},
                      "per_technique": {t: dict(oc_tech[t]) for t in oc_tech}},
            "cost_per_finding_usd": {p: (round(v, 2) if v is not None else None)
                                     for p, v in cpf.items()},
            "ev": {"total": (round(ev_total, 4) if ev_total is not None else None),
                   "payout_usd": round(total_paid, 2),
                   "per_program": {p: (round(v, 4) if v is not None else None)
                                   for p, v in ev_prog.items()}},
            "pipeline": pipeline,
            "flags": flags}, indent=2))
        return 0

    out = ["ledger: %s%s" % (args.ledger, "  (program: %s)" % args.program if args.program else "")]
    out += ["", "== spend ==",
            "total %s across %d intents (%d estimated)" % (usd(total_spend), len(intents), n_est)]
    out += fmt_table(["program", "spend", "paid"],
                     [[p, usd(spend_prog[p]), usd(paid_prog[p])] for p in sorted(spend_prog)] or [["-", "-", "-"]])
    out += [""] + fmt_table(["model", "spend"],
                            [[m, usd(v)] for m, v in sorted(spend_model.items())] or [["-", "-"]])
    out += ["", "== yield (per program) =="]
    out += fmt_table(["program"] + cols,
                     [[p] + oc_cells(oc_prog[p]) for p in sorted(oc_prog)] or [["-"] * (len(cols) + 1)])
    out += ["", "== yield (per technique/worker) =="]
    out += fmt_table(["worker"] + cols + ["spend"],
                     [[t] + oc_cells(oc_tech[t]) + [usd(spend_tech[t])]
                      for t in sorted(oc_tech)] or [["-"] * (len(cols) + 2)])
    out += ["", "== cost per finding =="]
    out += fmt_table(["program", "cost/finding"],
                     [[p, usd(cpf[p]) if cpf[p] is not None else "n/a (0 findings)"]
                      for p in sorted(spend_prog)] or [["-", "-"]])
    out += ["", "== EV (payout / spend) ==",
            "total: %s" % ("%.2f  (%s paid / %s spent)" % (ev_total, usd(total_paid), usd(total_spend))
                           if ev_total is not None else "n/a (no spend recorded)")]
    out += fmt_table(["program", "EV"],
                     [[p, "%.2f" % v if v is not None else "n/a"] for p, v in sorted(ev_prog.items())]
                     or [["-", "-"]])
    out += ["", "== pipeline (open findings: %d) ==" % len(pipeline)]
    out += fmt_table(["finding-id", "program", "status"],
                     [[r["finding_id"], r["program"], r["status"]] for r in pipeline] or [["-", "-", "-"]])
    out += ["", "== flags =="]
    out += ["WARN %s: %s" % (f["program"], f["warning"]) for f in flags] or ["none"]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
