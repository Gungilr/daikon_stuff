"""Rerank ReSym's beam candidates with evidence from the binary (plan: docs/plans/resym-rerank.md).

Input: resym_infer.py output run with --candidates K on functions listed by
resym_check.py --list-contradicted.  For each parameter whose TOP candidate
the evidence contradicts (static p-code rules or the trace's T-ptr rule):

  rerank     take the first other candidate (beam order) not contradicted; else abstain
  supported  take the first other candidate the evidence supports (PASS); else abstain

Reported for those contradicted parameters:
  alternative of a different type class exists   (the pilot gate: is there anything to pick?)
  replaced / abstained, replacement facts right / exact, fixes vs regressions
DWARF is read only to score.

Usage:
    python3 scripts/rea_eval/resym_rerank.py RUN.jsonl TEST.jsonl TRUTH.jsonl PCODE_DIR [--traces DIR] [--examples N]
"""
import collections
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check import Binary, pct  # noqa: E402
from resym_check import facts_right, judge, load_traces, matched_params  # noqa: E402
from resym_score import category, norm, parse  # noqa: E402


def main(argv):
    run_path, test_path, truth_path, pcode_dir = argv[1:5]
    n_ex = int(argv[argv.index("--examples") + 1]) if "--examples" in argv else 0
    traces = load_traces(argv[argv.index("--traces") + 1]) if "--traces" in argv else {}
    runs = [json.loads(l) for l in open(run_path) if l.strip()]
    want = {r["idx"] for r in runs}
    test = {}
    for i, line in enumerate(open(test_path)):
        if i in want:
            test[i] = json.loads(line)
    bins = {r["bin"] for r in runs}
    truth = {}
    for line in open(truth_path):
        t = json.loads(line)
        h = os.path.basename(t["binary"])
        if h in bins:
            truth[h] = {f["addr"]: f for f in t["functions"]}

    C = collections.Counter()
    ex = []
    cache = {}
    for r in sorted(runs, key=lambda r: r["bin"]):
        h = r["bin"]
        if h not in cache:
            pc = json.load(gzip.open(os.path.join(pcode_dir, h + ".json.gz"), "rt"))
            cache.clear()
            cache[h] = (Binary(pc), pc["functions"])
        B, raw = cache[h]
        cands = r.get("candidates") or [r["predict"]]
        parsed = [parse(c) for c in cands]
        addr, params = matched_params(test[r["idx"]], truth[h], raw)
        if params is None:
            C[addr] += 1
            continue
        C["functions"] += 1
        ttypes = traces[h].get(addr, {}) if h in traces and addr in traces[h] else None
        for ordinal, v, ttrue, label in params:
            types = [p[v][1] if v in p else None for p in parsed]
            if types[0] is None:
                continue
            C["params"] += 1
            top = types[0]
            if judge(B, ttypes, addr, ordinal, top) != "FAIL":
                continue
            C["contradicted"] += 1
            top_ok = facts_right(top, ttrue)
            C["top_ok"] += top_ok
            alts = [t for t in types[1:] if t is not None]
            if any(category(t) != category(top) for t in alts):
                C["alt_other_class"] += 1
            if any(norm(t) != norm(top) for t in alts):
                C["alt_other_type"] += 1
            verdicts = [judge(B, ttypes, addr, ordinal, t) for t in alts]
            for mode, accept in (("rerank", ("PASS", "NO-EVIDENCE")), ("supported", ("PASS",))):
                pick = next((t for t, vd in zip(alts, verdicts) if vd in accept), None)
                if pick is None:
                    C[f"{mode}:abstain"] += 1
                    C[f"{mode}:abstain_top_ok"] += top_ok
                    continue
                ok = facts_right(pick, ttrue)
                C[f"{mode}:replaced"] += 1
                C[f"{mode}:ok"] += ok
                C[f"{mode}:exact"] += norm(pick) == norm(label)
                C[f"{mode}:fix"] += ok and not top_ok
                C[f"{mode}:regress"] += top_ok and not ok
                if mode == "rerank" and len(ex) < n_ex:
                    ex.append(f"{test[r['idx']]['funname']} {v}: top {top!r} -> {pick!r}, "
                              f"truth {ttrue.get('c')!r}, {'right' if ok else 'wrong'}")

    k = C["contradicted"]
    print(f"functions {C['functions']} (skipped: " + ", ".join(
        f"{x} {C[x]}" for x in ("fn_unmatched", "fn_float_params", "fn_param_count_differs") if C[x]) + ")")
    print(f"parameter answers {C['params']}, top candidate contradicted {k}; "
          f"top facts right on those {pct(C['top_ok'], k)}")
    print(f"GATE  an alternative of a different type class exists   {pct(C['alt_other_class'], k)}  "
          f"({C['alt_other_class']} of {k}; any different type string {C['alt_other_type']})")
    for mode in ("rerank", "supported"):
        rep = C[f"{mode}:replaced"]
        print(f"{mode:9s}  replaced {rep} ({pct(rep, k)}), abstained {C[f'{mode}:abstain']}; "
              f"replacement facts right {pct(C[f'{mode}:ok'], rep)}, exact {pct(C[f'{mode}:exact'], rep)}; "
              f"fixes {C[f'{mode}:fix']}, regressions {C[f'{mode}:regress']}; "
              f"abstained-on but top was right {C[f'{mode}:abstain_top_ok']}")
    if ex:
        print("\nexamples:")
        for x in ex:
            print("  " + x)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
