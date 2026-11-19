"""Does Daikon give the fuzzer an oracle, and does fuzzing make that oracle better?

Setting (regression testing of a black-box binary): invariants are learned on the
reference version v0 from some training inputs. Every test of an independent
test universe is then run, traced by the black-box tracer, on v0 and on each
faulty version vN, and FLAGGED when its trace violates a learned invariant.

Ground truth (evaluation only, never seen by the loop):
    output-revealing   native stdout of vN differs from v0 on that test
    state-revealing    the traced values differ from v0's on that test
Metrics per invariant set:
    false alarms       tests flagged on v0 itself (caused only by spurious invariants)
    faults detected    versions with >= 1 flagged output-revealing test
    alarm precision    flagged tests on faulty versions that are output-revealing
Coverage alone flags nothing: none of these faults crashes.

Steps (cached under CACHE):
    native  run every version natively on every test -> outputs
    trace   trace every version on every test -> rows (multiprocessing)
    score   for each training set: Daikon on v0, then flag and score

Usage:
    python3 scripts/fuzz/fault_eval.py --versions DIR --universe FILE --cache DIR \\
        --train RESULT.json [...] [--sets corpus,executed,trusted] --out RESULTS.json
"trusted": learned on the corpus, restricted to the invariants the loop's
challenge phase tried to break and could not.
"""
import argparse
import collections
import glob
import json
import multiprocessing as mp
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import invariants as I  # noqa: E402


def version_names(vdir):
    vs = sorted((os.path.basename(p)[:-4] for p in glob.glob(os.path.join(vdir, "v*.exe"))),
                key=lambda v: int(v[1:]))
    return vs


def load_universe(path):
    return [l.split() for l in open(path) if l.strip()]


def native_outputs(vdir, tests, cache):
    p = os.path.join(cache, "native.json")
    if os.path.exists(p):
        return json.load(open(p))
    out = {}
    for v in version_names(vdir):
        exe = os.path.abspath(os.path.join(vdir, v + ".exe"))
        out[v] = [subprocess.run([exe, *t], capture_output=True, text=True, timeout=10).stdout
                  for t in tests]
    json.dump(out, open(p, "w"))
    return out


_work = None


def _init():
    global _work
    _work = tempfile.mkdtemp()


def _trace(job):
    import runner
    exe, argv = job
    _edges, dt, _ = runner.trace_one(exe, argv, _work)
    rows = I.rows_by_ppt(dt)
    # keep ints only, compactly
    return {p: [{k: v for k, v in r.items() if isinstance(v, int)} for r in rs]
            for p, rs in rows.items()}


def traced_rows(vdir, tests, cache, procs=4):
    os.makedirs(os.path.join(cache, "rows"), exist_ok=True)
    out = {}
    for v in version_names(vdir):
        p = os.path.join(cache, "rows", v + ".json")
        if not os.path.exists(p):
            exe = os.path.abspath(os.path.join(vdir, v + ".exe"))
            with mp.Pool(procs, initializer=_init) as pool:
                rows = pool.map(_trace, [(exe, t) for t in tests], chunksize=16)
            json.dump(rows, open(p, "w"))
            print(f"  traced {v}", flush=True)
        out[v] = p
    return out


def learn(train_inputs, v0_exe, workdir, conditional=False):
    """Daikon on v0 over the training inputs - with the same derived splitting
    conditions as the loop's conditional relearn when `conditional`."""
    import runner
    import splitters as SP
    dt = runner.trace_batch(v0_exe, train_inputs, workdir, tag="train")
    spinfo = None
    if conditional:
        spinfo = SP.write_spinfo(SP.conditions(I.rows_by_ppt(dt)),
                                 os.path.join(workdir, "train.spinfo"))
    txt = runner.daikon(dt, os.path.join(workdir, "train"), spinfo=spinfo)
    invs, skipped = I.load(txt)
    invs = [v for v in invs if "condition" not in v.ppt and ";" not in v.ppt]
    return invs, skipped


def flagged(invs, rows):
    by_ppt = collections.defaultdict(list)
    for inv in invs:
        by_ppt[inv.ppt].append(inv)
    for ppt, rs in rows.items():
        for inv in by_ppt.get(ppt, ()):
            for r in rs:
                if inv.holds(r) is False:
                    return True
    return False


def score(invs, row_files, native, versions):
    v0_rows = json.load(open(row_files["v0"]))
    n = len(v0_rows)
    fa = sum(flagged(invs, r) for r in v0_rows)
    per = {}
    for v in versions:
        if v == "v0":
            continue
        rows = json.load(open(row_files[v]))
        tp = fl = rev = st = fl_state = 0
        for i in range(n):
            out_diff = native[v][i] != native["v0"][i]
            state_diff = rows[i] != v0_rows[i]
            f = flagged(invs, rows[i])
            rev += out_diff
            st += state_diff
            fl += f
            tp += f and out_diff
            fl_state += f and state_diff
        per[v] = {"revealing_tests": rev, "state_diff_tests": st, "flagged": fl,
                  "flagged_revealing": tp, "flagged_state_diff": fl_state,
                  "detected": tp > 0}
    det = sum(1 for x in per.values() if x["detected"])
    detectable = sum(1 for x in per.values() if x["revealing_tests"] > 0)
    flags = sum(x["flagged"] for x in per.values())
    return {"invariants": len(invs), "false_alarm_tests_v0": fa, "tests": n,
            "false_alarm_rate": fa / n, "faults_detected": det, "faults_detectable": detectable,
            "alarm_precision_output": (sum(x["flagged_revealing"] for x in per.values()) / flags)
            if flags else None,
            "alarm_precision_state": (sum(x["flagged_state_diff"] for x in per.values()) / flags)
            if flags else None,
            "per_version": per}


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--versions", required=True)
    p.add_argument("--universe", required=True)
    p.add_argument("--cache", required=True)
    p.add_argument("--train", nargs="*", default=[])
    p.add_argument("--seeds")
    p.add_argument("--sets", default="corpus,executed")
    p.add_argument("--out", required=True)
    p.add_argument("--procs", type=int, default=4)
    a = p.parse_args(argv)
    os.makedirs(a.cache, exist_ok=True)
    tests = load_universe(a.universe)
    versions = version_names(a.versions)
    native = native_outputs(a.versions, tests, a.cache)
    row_files = traced_rows(a.versions, tests, a.cache, a.procs)
    v0 = os.path.abspath(os.path.join(a.versions, "v0.exe"))
    results = []
    jobs = []
    if a.seeds:
        jobs.append(("seeds", None, "seeds", [json.loads(l) for l in open(a.seeds) if l.strip()]))
    for f in a.train:
        d = json.load(open(f))
        for s in a.sets.split(","):
            if s == "trusted":
                if d.get("trusted"):
                    jobs.append((d["config"], d["trial"], s, d["corpus"],
                                 {tuple(k) for k in d["trusted"]}))
                continue
            jobs.append((d["config"], d["trial"], s, d[s], None))
    jobs = [j if len(j) == 5 else (*j, None) for j in jobs]
    for config, trial, set_name, inputs, keep in jobs:
        with tempfile.TemporaryDirectory() as w:
            invs, skipped = learn(inputs, v0, w, conditional=config == "loopcond")
        if keep is not None:
            # the oracle: only invariants that survived the fuzzer's challenges
            invs = [v for v in invs if v.key in keep]
        r = score(invs, row_files, native, versions)
        r.update(config=config, trial=trial, set=set_name, train_inputs=len(inputs),
                 uncompiled=skipped)
        results.append(r)
        print(f"{config:7s} t{trial} {set_name:9s} train {len(inputs):5d}  invs {len(invs):5d}  "
              f"false alarms {r['false_alarm_tests_v0']:4d}/{r['tests']}  "
              f"faults detected {r['faults_detected']}/{r['faults_detectable']}  "
              f"precision(out) {r['alarm_precision_output']}", flush=True)
        json.dump(results, open(a.out, "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
