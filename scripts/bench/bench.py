#!/usr/bin/env python3
"""Benchmark: the Daikon fuzz loop vs. learn-once vs. AFL++ on planted bugs.

    python3 scripts/bench/bench.py --budget 180 --seeds 3 --jobs 3

Three tools, same targets, same seed inputs, same wall-clock budget:

  loop        scripts/fuzz_loop.py: Daikon re-learns every round
  learn-once  scripts/fuzz_loop.py --learn-once: Daikon learns from the seeds
              once and the fuzzer attacks that fixed set (InvsCov-style)
  afl         AFL++ 4.21c, afl-clang-fast, persistent mode, ASan + UBSan,
              CmpLog (-c): the standard strong configuration

Scoring uses ground truth no tool sees. Every planted bug is marked
FUZZ_BUG(id, condition) in the target. A separate oracle build
(-DFUZZ_ORACLE) prints the id whenever an input meets the condition. Every
input a tool KEPT (its corpus or queue, plus its bug or crash files) is
replayed through the oracle, which gives two numbers per bug:

  triggered  some kept input makes the bug happen, whether or not the tool
             noticed
  reported   the tool said so:
               - a sanitizer bug or AFL++ crash whose input triggers it, or
               - (Daikon modes only) a refuted rule in the bug's own function
                 whose counterexample triggers it

Times are seconds from the start of fuzzing (after compiling).
"""
import argparse
import concurrent.futures as cf
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "scripts"))
from fuzzloop import runner                     # noqa: E402
from fuzzloop.mutate import parse_seed_file     # noqa: E402

TARGETS = ["arith", "buffer", "packet", "stack", "stats"]
TOOLS = ["loop", "learn-once", "afl"]
AFL = os.path.join(REPO, "AFLplusplus")


def planted_bugs(target):
    """{bug id: (kind, function)} from the FUZZ_BUG markers and comments."""
    src = open(os.path.join(REPO, "fuzz", "targets", target + ".c")).read()
    kinds = dict(re.findall(r"^ \*\s+(\w+)\s+\((memory|logic|UB)\)", src, re.M))
    out, func = {}, None
    for line in src.split("\n"):
        m = re.match(r"^\w[\w\s\*]*?\b(\w+)\(.*\)\s*\{", line)
        if m:
            func = m.group(1)
        for bid in re.findall(r'FUZZ_BUG(?:_FATAL)?\("(\w+)"', line):
            out[bid] = (kinds.get(bid, "UB"), func)
    return out


# --- running ----------------------------------------------------------------

def run_loop(target, outdir, seed, budget, learn_once):
    cmd = [sys.executable, os.path.join(REPO, "scripts", "fuzz_loop.py"),
           os.path.join(REPO, "fuzz", "targets", target + ".c"), "-o", outdir,
           "--rounds", "100000", "--patience", "100000", "--time-limit", str(budget),
           "--batch-size", "1000", "--seed", str(seed)]
    if learn_once:
        cmd.append("--learn-once")
    with open(outdir + ".log", "w") as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=REPO,
                       timeout=budget * 3 + 600)


def build_afl(target, workdir):
    os.makedirs(workdir, exist_ok=True)
    src = [os.path.join(REPO, "fuzz", "targets", target + ".c"),
           os.path.join(REPO, "fuzz", "runtime", "afl_harness.c")]
    main = os.path.join(workdir, target + ".afl")
    cmplog = os.path.join(workdir, target + ".cmplog")
    env = dict(os.environ, AFL_USE_ASAN="1", AFL_USE_UBSAN="1", AFL_QUIET="1")
    subprocess.run([os.path.join(AFL, "afl-clang-fast"), "-O0", "-g"] + src + ["-o", main],
                   env=env, check=True, capture_output=True)
    env = dict(os.environ, AFL_LLVM_CMPLOG="1", AFL_QUIET="1")
    subprocess.run([os.path.join(AFL, "afl-clang-fast"), "-O0", "-g"] + src + ["-o", cmplog],
                   env=env, check=True, capture_output=True)
    return main, cmplog


def run_afl(target, outdir, seed, budget, bins):
    main, cmplog = bins
    seeds_dir = outdir + ".in"
    os.makedirs(seeds_dir, exist_ok=True)
    with open(os.path.join(REPO, "fuzz", "targets", target + ".seeds")) as f:
        for i, s in enumerate(parse_seed_file(f.read())):
            with open(os.path.join(seeds_dir, "seed%02d" % i), "wb") as g:
                g.write(s)
    env = dict(os.environ, AFL_SKIP_CPUFREQ="1", AFL_NO_UI="1", AFL_NO_AFFINITY="1",
               AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1", AFL_SKIP_BIN_CHECK="0")
    with open(outdir + ".log", "w") as log:
        subprocess.run([os.path.join(AFL, "afl-fuzz"), "-i", seeds_dir, "-o", outdir,
                        # 2000+: generous per-input limit (three runs share
                        # four cores), not applied to the seeds' dry run.
                        "-t", "2000+",
                        "-V", str(budget), "-s", str(seed), "-c", cmplog, "--", main],
                       env=env, stdout=log, stderr=subprocess.STDOUT,
                       timeout=budget * 3 + 600)


# --- scoring ----------------------------------------------------------------

def build_oracle(target, workdir):
    os.makedirs(workdir, exist_ok=True)
    exe = os.path.join(workdir, target + ".oracle")
    subprocess.run(["gcc", "-O0", "-fwrapv", "-fno-stack-protector", "-DFUZZ_ORACLE",
                    "-DFUZZ_SAN", os.path.join(REPO, "fuzz", "targets", target + ".c"),
                    os.path.join(REPO, "fuzz", "runtime", "harness.c"), "-o", exe],
                   check=True, capture_output=True)
    return exe


def triggers(oracle, inputs, workdir):
    """[set of planted ids] per input."""
    if not inputs:
        return []
    found = runner.run_san(oracle, inputs, workdir)
    return [{b.kind for b in found.get(i, []) if b.sanitizer == "oracle"}
            for i in range(len(inputs))]


def afl_inputs(outdir, sub):
    out = []
    d = os.path.join(outdir, "default", sub)
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        if not name.startswith("id:"):
            continue
        m = re.search(r"time:(\d+)", name)
        with open(os.path.join(d, name), "rb") as f:
            out.append((f.read(), int(m.group(1)) / 1000.0 if m else 0.0))
    return out


def score_run(tool, target, outdir, oracle, bugs, workdir):
    trig, rep = {}, {}

    def note(table, ids, t):
        for b in ids:
            if b in bugs and (b not in table or t < table[b]):
                table[b] = t

    stats = {}
    if tool == "afl":
        kept = afl_inputs(outdir, "queue") + afl_inputs(outdir, "crashes")
        crashes = afl_inputs(outdir, "crashes")
        for (data, t), ids in zip(kept, triggers(oracle, [d for d, _ in kept], workdir)):
            note(trig, ids, t)
        for (data, t), ids in zip(crashes, triggers(oracle, [d for d, _ in crashes], workdir)):
            note(rep, ids, t)
        try:
            for line in open(os.path.join(outdir, "default", "fuzzer_stats")):
                k, _, v = line.partition(":")
                if k.strip() in ("execs_done", "corpus_count", "saved_crashes"):
                    stats[k.strip()] = int(v.strip())
        except OSError:
            pass
    else:
        h = json.load(open(os.path.join(outdir, "history.json")))
        kept = [(bytes.fromhex(e["input"]), e["time"]) for e in h["corpus"]]
        kept += [(bytes.fromhex(b["input"]), b["time"]) for b in h["bugs"]]
        for (data, t), ids in zip(kept, triggers(oracle, [d for d, _ in kept], workdir)):
            note(trig, ids, t)
        sb = [(bytes.fromhex(b["input"]), b["time"]) for b in h["bugs"]]
        for (data, t), ids in zip(sb, triggers(oracle, [d for d, _ in sb], workdir)):
            note(rep, ids, t)
        # Logic bugs: a refuted rule in the bug's own function, refuted by an
        # input that triggers the bug.
        ref = [r for r in h["invariants"] if r["refuted_round"] is not None
               and r.get("violated_by") is not None]
        rins = [bytes.fromhex(r["violated_by"]) for r in ref]
        for r, ids in zip(ref, triggers(oracle, rins, workdir)):
            fn = r["ppt"].split("(")[0].lstrip(".")
            note(rep, [b for b in ids if bugs.get(b, (None, None))[1] == fn],
                 r.get("refuted_time") or h["stats"]["seconds_total"])
        stats = {"execs_done": h["stats"]["execs"], "corpus_count": h["corpus_size"]}
    return {"triggered": trig, "reported": rep, "stats": stats}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=180, help="seconds per run")
    ap.add_argument("--seeds", type=int, default=3, help="random seeds per cell")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--targets", default=",".join(TARGETS))
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--out", default=os.path.join(REPO, "bench-out"))
    ap.add_argument("--score-only", action="store_true")
    args = ap.parse_args(argv)
    targets, tools = args.targets.split(","), args.tools.split(",")
    os.environ.setdefault("DAIKONDIR", os.path.join(REPO, "daikon"))

    afl_bins = {}
    if "afl" in tools and not args.score_only:
        for t in targets:
            afl_bins[t] = build_afl(t, os.path.join(args.out, "_build", t))
    jobs = [(t, tool, s) for t in targets for tool in tools for s in range(args.seeds)]
    if not args.score_only:
        def go(job):
            t, tool, s = job
            od = os.path.join(args.out, t, tool, "seed%d" % s)
            shutil.rmtree(od, ignore_errors=True)
            os.makedirs(os.path.dirname(od), exist_ok=True)
            t0 = time.time()
            if tool == "afl":
                run_afl(t, od, s, args.budget, afl_bins[t])
            else:
                run_loop(t, od, s, args.budget, tool == "learn-once")
            return "%-7s %-10s seed %d  %.0fs" % (t, tool, s, time.time() - t0)
        with cf.ThreadPoolExecutor(args.jobs) as ex:
            for line in ex.map(go, jobs):
                print(line, flush=True)

    results = {}
    for t in targets:
        bugs = planted_bugs(t)
        work = os.path.join(args.out, "_score", t)
        oracle = build_oracle(t, work)
        for tool in tools:
            for s in range(args.seeds):
                od = os.path.join(args.out, t, tool, "seed%d" % s)
                try:
                    r = score_run(tool, t, od, oracle, bugs, work)
                except (OSError, ValueError, KeyError) as e:
                    r = {"error": str(e)}
                results.setdefault(t, {}).setdefault(tool, []).append(r)
        results[t]["_bugs"] = {b: list(v) for b, v in bugs.items()}
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump({"budget": args.budget, "seeds": args.seeds, "results": results}, f, indent=1)
    print_tables(results, tools, args.seeds, args.budget)


def fmt_times(ts, n):
    got = [t for t in ts if t is not None]
    if not got:
        return "0/%d" % n
    return "%d/%d (%s s)" % (len(got), n, "%.0f" % statistics.median(got))


def print_tables(results, tools, n, budget):
    print("\nper bug: runs that found it out of %d, median seconds (budget %ds)\n" % (n, budget))
    print("| target | bug | kind | " + " | ".join(
        "%s triggered | %s reported" % (t, t) for t in tools) + " |")
    print("|---|---|---|" + "---|---|" * len(tools))
    for target, per in results.items():
        for bid, (kind, func) in per["_bugs"].items():
            cells = []
            for tool in tools:
                runs = per.get(tool, [])
                for key in ("triggered", "reported"):
                    cells.append(fmt_times([r.get(key, {}).get(bid) for r in runs], n))
            print("| %s | %s | %s | %s |" % (target, bid, kind, " | ".join(cells)))
    print("\ntotals (bug-runs found, out of bugs x seeds):\n")
    print("| tool | triggered | reported | reported: memory/UB | reported: logic | median executions |")
    print("|---|---|---|---|---|---|")
    for tool in tools:
        tr = rp = rpm = rpl = tot = 0
        execs = []
        for target, per in results.items():
            for r in per.get(tool, []):
                execs.append(r.get("stats", {}).get("execs_done", 0))
                for bid, (kind, _) in per["_bugs"].items():
                    tot += 1
                    tr += bid in r.get("triggered", {})
                    if bid in r.get("reported", {}):
                        rp += 1
                        if kind == "logic":
                            rpl += 1
                        else:
                            rpm += 1
        print("| %s | %d/%d | %d/%d | %d | %d | %s |" % (
            tool, tr, tot, rp, tot, rpm, rpl,
            "%d" % statistics.median(execs) if execs else "-"))


if __name__ == "__main__":
    sys.exit(main())
