"""Aggregate P/R/F1 against Kvasir over a whole corpus produced by test.sh.

    python3 scripts/score_suite.py --bins bench/ksuite --inv bench/ksuite_inv --tier 10

For every <name>.exe in --bins with both invariants/<name>.kvasir.txt and
invariants/<name>.tracer.t<N>.txt, scores with score_invariants.score() (DWARF
read only to align names) and prints per-binary rows plus totals. --json writes
the totals and rows for later comparison.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from score_invariants import score  # noqa: E402


def daikon_ok(path):
    """A report Daikon actually produced, not a rejected trace."""
    try:
        txt = open(path, errors="replace").read()
    except OSError:
        return False
    return "Exception" not in txt and "Error at line" not in txt and "===" in txt


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--bins", required=True)
    p.add_argument("--inv", required=True)
    p.add_argument("--tier", required=True)
    p.add_argument("--suffix", default="", help="extra tag in the tracer file name")
    p.add_argument("--json")
    a = p.parse_args(argv)

    rows, tot = [], {"matched": 0, "kvasir": 0, "tracer": 0}
    failed = []
    for f in sorted(os.listdir(a.bins)):
        if not f.endswith(".exe") or f.endswith("_stripped.exe"):
            continue
        name = f[:-4]
        kv = os.path.join(a.inv, f"{name}.kvasir.txt")
        tr = os.path.join(a.inv, f"{name}.tracer.t{a.tier}{a.suffix}.txt")
        if not (os.path.exists(kv) and os.path.exists(tr)):
            continue
        if not daikon_ok(tr):
            failed.append(name)
        _, t = score(kv, tr, os.path.join(a.bins, f))
        rows.append({"binary": name, **t})
        for k in ("matched", "kvasir", "tracer"):
            tot[k] += t[k]
    P = tot["matched"] / tot["tracer"] if tot["tracer"] else 0.0
    R = tot["matched"] / tot["kvasir"] if tot["kvasir"] else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    print(f"{'binary':<26} {'oracle':>6} {'ours':>6} {'match':>6} {'prec':>6} {'rec':>6}")
    for r in rows:
        print(f"{r['binary']:<26} {r['kvasir']:>6} {r['tracer']:>6} {r['matched']:>6} "
              f"{r['precision']:>6.0%} {r['recall']:>6.0%}")
    print(f"\nTOTAL {len(rows)} binaries: oracle {tot['kvasir']}  ours {tot['tracer']}  "
          f"matched {tot['matched']}   precision {P:.1%}  recall {R:.1%}  F1 {F:.1%}")
    if failed:
        print(f"[!] Daikon did not produce a clean report for: {', '.join(failed)}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump({"totals": {**tot, "precision": P, "recall": R, "f1": F},
                       "rows": rows, "daikon_failed": failed}, fh, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
