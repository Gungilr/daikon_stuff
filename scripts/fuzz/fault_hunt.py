"""Daikon -> fuzzer: hunt for faults in a changed binary with the loop's invariants.

The trusted invariants of a loop campaign on the reference v0 (those that
survived the fuzzer's own challenges) are the oracle. Each faulty version vN is
then fuzzed for BUDGET executions from v0's corpus, in two configurations:

    diff    reference point: coverage-guided, and the reference v0 run on EVERY
            input with outputs compared (differential testing; needs v0 per input)
    cov     coverage-guided havoc; the invariants only judge each run
    guided  as cov, but half the inputs are built to break a trusted invariant
            (the challenge mutations, on the input fields learned for its
            variables)

A violation counts as a DEVIATION only if the same input does NOT violate that
invariant on v0 (confirmation against the reference, never DWARF). A deviation
is also an output FAILURE when the native stdout of vN and v0 differ.

Usage:
    python3 scripts/fuzz/fault_hunt.py --versions DIR --loop-result RESULT.json \\
        --budget 300 --out OUT.json [--only v1,v2]
"""
import argparse
import json
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fault_eval as FE  # noqa: E402
import invariants as I  # noqa: E402
import runner  # noqa: E402
from loop import Fuzzer, Mapping  # noqa: E402


def native(exe, argv):
    return subprocess.run([exe, *map(str, argv)], capture_output=True, text=True,
                          timeout=10).stdout


def hunt(vexe, v0exe, oracle, mapping, corpus, config, budget, rng, work):
    f = Fuzzer(vexe, [corpus[0]], "cov", rng, work)
    f.corpus = [list(c) for c in corpus]
    f.invs = oracle
    f.map = mapping
    found = {"deviation_at": None, "failure_at": None, "violations": 0}
    confirmed = set()
    for k in range(1, budget + 1):
        base = rng.choice(f.corpus)
        x = None
        if config == "guided" and rng.random() < 0.5:
            inv = rng.choice(oracle)
            c = f.challenges(inv, base)
            if c:
                x = rng.choice(c)
        if x is None:
            x = f.havoc(base)
        edges, dt, _ = runner.trace_one(vexe, x, work, tag="v")
        if edges - f.edges:
            f.edges |= edges
            f.corpus.append(x)
        if config == "diff":
            # Reference point, not an invariant method: run the reference on
            # EVERY input and compare outputs (needs v0 at test time).
            found["reference_runs"] = found.get("reference_runs", 0) + 1
            if native(vexe, x) != native(v0exe, x):
                found["deviation_at"] = found["failure_at"] = k
                found["failure_input"] = x
                break
            continue
        bad = I.violations(oracle, I.rows_by_ppt(dt))
        if not bad:
            continue
        found["violations"] += 1
        found["reference_runs"] = found.get("reference_runs", 0) + 1
        _, dt0, _ = runner.trace_one(v0exe, x, work, tag="v0")
        still = {v.key for v in I.violations(bad, I.rows_by_ppt(dt0))}
        real = [v for v in bad if v.key not in still]
        if not real:
            continue
        if found["deviation_at"] is None:
            found["deviation_at"] = k
            found["deviation_input"] = x
            found["deviation_invariant"] = list(real[0].key)
        confirmed.add(tuple(x))
        if found["failure_at"] is None and native(vexe, x) != native(v0exe, x):
            found["failure_at"] = k
            found["failure_input"] = x
            break
    return found


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--versions", required=True)
    p.add_argument("--loop-result", required=True)
    p.add_argument("--budget", type=int, default=300)
    p.add_argument("--configs", default="cov,guided")
    p.add_argument("--only")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    d = json.load(open(a.loop_result))
    v0 = os.path.abspath(os.path.join(a.versions, "v0.exe"))
    with tempfile.TemporaryDirectory() as w:
        invs, _ = FE.learn(d["corpus"], v0, w, conditional=d["config"] == "loopcond")
    keep = {tuple(k) for k in d["trusted"]}
    oracle = [v for v in invs if v.key in keep]
    mapping = Mapping(len(d["corpus"][0]))
    for var, fld in d["mapping"].items():   # the loop's learned map, reused
        mapping.cand[var] = {fld}
        mapping.vals[var] = {0, 1}
        mapping.obs[var] = 99
    versions = [v for v in FE.version_names(a.versions) if v != "v0"]
    if a.only:
        versions = [v for v in versions if v in a.only.split(",")]
    results = {"oracle_invariants": len(oracle), "budget": a.budget, "runs": {}}
    for v in versions:
        vexe = os.path.abspath(os.path.join(a.versions, v + ".exe"))
        for c in a.configs.split(","):
            with tempfile.TemporaryDirectory() as w:
                r = hunt(vexe, v0, oracle, mapping, d["corpus"], c, a.budget,
                         random.Random(a.seed + int(v[1:])), w)
            results["runs"].setdefault(v, {})[c] = r
            print(f"{v:4s} {c:6s} deviation@{r['deviation_at']}  failure@{r['failure_at']}  "
                  f"raw violations {r['violations']}", flush=True)
        json.dump(results, open(a.out, "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
