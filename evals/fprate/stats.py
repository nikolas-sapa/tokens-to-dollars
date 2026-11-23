#!/usr/bin/env python3
"""FP-rate regression gate. Stdlib only — no scipy/numpy.

Ported from sigeval (stats.py + core.py). An eval result is a *proportion*
(k submit-worthy out of n flagged), not a boolean; we test the current run's
rate against a saved baseline with a pooled two-proportion z-test per
technique, Holm-corrected across the suite so one marginal drop does not
false-alarm the gate.

  stats.py baseline save results.csv baseline.json
  stats.py check results.csv baseline.json [--alpha 0.05]

results.csv rows: technique,total,submitworthy
"""
import argparse
import csv
import json
import math
import os
import sys
from dataclasses import dataclass


def _validate_positive_integer(value, name):
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("%s must be a positive integer" % name)


def _validate_counts(k, n):
    _validate_positive_integer(n, "n")
    if isinstance(k, bool) or not isinstance(k, int) or not 0 <= k <= n:
        raise ValueError("k must be an integer with 0 <= k <= n")


def _validate_finite(value, name):
    try:
        finite = math.isfinite(value)
    except (TypeError, ValueError, OverflowError):
        finite = False
    if not finite:
        raise ValueError("%s must be finite" % name)


def _validate_z(z):
    _validate_finite(z, "z")
    if z <= 0:
        raise ValueError("z must be > 0")


def _validate_threshold(threshold):
    _validate_finite(threshold, "threshold")
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be in [0, 1]")


def _validate_alpha(alpha):
    _validate_finite(alpha, "alpha")
    if not 0 < alpha < 1:
        raise ValueError("alpha must be in (0, 1)")


def _phi(z):
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def wilson_interval(k, n, z=1.96):
    """Wilson score interval for a binomial proportion (95% at z=1.96)."""
    _validate_counts(k, n)
    _validate_z(z)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))) / denom
    low = 0.0 if k == 0 else max(0.0, center - half)
    high = 1.0 if k == n else min(1.0, center + half)
    return low, high


def two_proportion_pvalue(k1, n1, k2, n2):
    """One-sided p-value that group 2's rate is below group 1's.

    group 1 = saved baseline, group 2 = current. Pooled z-test; returns
    P(observed drop or worse under H0: equal rates).
    """
    _validate_counts(k1, n1)
    _validate_counts(k2, n2)
    p1, p2 = k1 / n1, k2 / n2
    pool = (k1 + k2) / (n1 + n2)
    se = math.sqrt(pool * (1 - pool) * (1 / n1 + 1 / n2))
    if se == 0.0:
        return 1.0
    return _phi((p2 - p1) / se)


@dataclass
class Verdict:
    name: str          # "PASS" | "FAIL" | "INCONCLUSIVE"
    k: int
    n: int
    rate: float
    ci_low: float
    ci_high: float
    threshold: float

    def __bool__(self):
        return self.name == "PASS"

    def __str__(self):
        return ("%s: %d/%d passed (rate=%.2f, CI [%.2f, %.2f], threshold=%.2f)"
                % (self.name, self.k, self.n, self.rate,
                   self.ci_low, self.ci_high, self.threshold))


def decide(k, n, threshold, z=1.96):
    """PASS if CI low > threshold, FAIL if CI high < threshold, else INCONCLUSIVE."""
    _validate_threshold(threshold)
    low, high = wilson_interval(k, n, z)
    if low > threshold:
        name = "PASS"
    elif high < threshold:
        name = "FAIL"
    else:
        name = "INCONCLUSIVE"
    return Verdict(name, k, n, k / n, low, high, threshold)


def _holm_adjusted(p_values):
    """Holm step-down adjusted p-values, aligned to input order.

    Same output as statsmodels multipletests(method="holm"); controls the
    family-wise error rate with no independence assumption.
    """
    m = len(p_values)
    order = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, (m - rank) * p_values[i])
        adjusted[i] = min(1.0, running)
    return adjusted


# ---- baseline save / regression check (core.py port) ----

def read_csv(path):
    rows = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            try:
                n = int(r["total"]); k = int(r["submitworthy"])
            except (KeyError, TypeError, ValueError) as e:
                sys.exit("error: bad row %r in %s (%s)" % (r, path, e))
            if not 0 <= k <= n or n <= 0:
                sys.exit("error: need 0 <= submitworthy <= total, got %r" % r)
            rows[r["technique"]] = {"k": k, "n": n}
    if not rows:
        sys.exit("error: no rows in %s" % path)
    return rows


def save_baseline(results, path):
    data = {t: {"k": r["k"], "n": r["n"]} for t, r in results.items()}
    with open(path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    print("saved baseline: %d techniques -> %s" % (len(data), path))


def check_regression(results, baseline_path, alpha=0.05):
    """Per-technique two-proportion test vs baseline + Holm correction.

    Returns (rows, regressions): rows = (technique, bk, bn, ck, cn, p_raw,
    p_adj, verdict) for table printing; regressions = adjusted-p < alpha
    subset. Techniques absent from the baseline are reported "new".
    """
    _validate_alpha(alpha)
    if not os.path.exists(baseline_path):
        sys.exit("error: baseline not found: %s (run 'baseline save' first)"
                 % baseline_path)
    with open(baseline_path) as f:
        base = json.load(f)
    tested, skipped = [], []
    for t, r in sorted(results.items()):
        b = base.get(t)
        if not b:
            skipped.append((t, r["k"], r["n"]))
            continue
        tested.append((t, b["k"], b["n"], r["k"], r["n"],
                       two_proportion_pvalue(b["k"], b["n"], r["k"], r["n"])))
    adjusted = _holm_adjusted([p for *_, p in tested])
    rows = [(t, bk, bn, ck, cn, p, pa, "REGRESSION" if pa < alpha else "ok")
            for (t, bk, bn, ck, cn, p), pa in zip(tested, adjusted)]
    for t, k, n in skipped:
        rows.append((t, None, None, k, n, None, None, "new (no baseline)"))
    return rows, [r for r in rows if r[-1] == "REGRESSION"]


def fmt_rate(k, n):
    return "%.3f" % (k / n) if n else "-"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline", help="baseline operations")
    bs = b.add_subparsers(dest="bcmd", required=True)
    bsave = bs.add_parser("save", help="record k/n per technique as the baseline")
    bsave.add_argument("results_csv")
    bsave.add_argument("baseline_json")
    c = sub.add_parser("check", help="flag techniques whose submit-worthy rate regressed")
    c.add_argument("results_csv")
    c.add_argument("baseline_json")
    c.add_argument("--alpha", type=float, default=0.05,
                   help="family-wise significance level after Holm (default 0.05)")
    args = ap.parse_args()

    if args.cmd == "baseline" and args.bcmd == "save":
        save_baseline(read_csv(args.results_csv), args.baseline_json)
        return 0

    rows, bad = check_regression(read_csv(args.results_csv),
                                 args.baseline_json, alpha=args.alpha)
    print("%-24s %10s %10s %8s %8s  %s"
          % ("technique", "base k/n", "cur k/n", "p_raw", "p_holm", "verdict"))
    print("-" * 72)
    for t, bk, bn, ck, cn, p, pa, verdict in rows:
        print("%-24s %10s %10s %8s %8s  %s"
              % (t,
                 "%d/%d %s" % (bk, bn, fmt_rate(bk, bn)) if bn is not None else "-",
                 "%d/%d %s" % (ck, cn, fmt_rate(ck, cn)),
                 "%.4f" % p if p is not None else "-",
                 "%.4f" % pa if pa is not None else "-",
                 verdict))
    if bad:
        print("\nFAIL: %d technique(s) regressed at alpha=%.3f (Holm-adjusted)"
              % (len(bad), args.alpha))
        return 1
    print("\nOK: no submit-worthy-rate regression at alpha=%.3f" % args.alpha)
    return 0


if __name__ == "__main__":
    sys.exit(main())
