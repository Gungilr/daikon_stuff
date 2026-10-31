#!/usr/bin/env python3
"""Benchmark: the Daikon fuzz loop vs. learn-once vs. AFL++ on planted bugs.

    python3 scripts/bench/bench.py --budget 180 --seeds 3 --jobs 3
    python3 scripts/bench/bench.py --targets tcas,replace --out bench-out/siemens

Three tools, same targets, same seed inputs, same wall-clock budget:

  loop        scripts/fuzz_loop.py: Daikon re-learns every round
  learn-once  scripts/fuzz_loop.py --learn-once: Daikon learns from the seeds
              once and the fuzzer attacks that fixed set (InvsCov-style)
  afl         AFL++ 4.21c, afl-clang-fast, persistent mode, ASan + UBSan,
              CmpLog (-c): the standard strong configuration

A target is any fuzz/targets/**/<name>.c with a <name>.seeds beside it.

Scoring uses ground truth no tool sees. Planted bugs are marked in the
source, and the marks print only in a separate oracle build (-DFUZZ_ORACLE):

  FUZZ_BUG(id, cond) / FUZZ_BUG_FATAL(id, cond)
      the bug happens when `cond` holds (UB and memory bugs).
  FAULT(id, k, original, mutant)
      a seeded logic fault (scripts/bench/make_siemens.py). An input
      triggers it when the fault both INFECTS the state (original != mutant)
      AND changes the program's output: the scorer compares against a build
      with only fault k reverted (-DFUZZ_REVERT=k).

Every input a tool KEPT (its corpus or queue, plus its bug or crash files) is
replayed through the oracle. That gives, per bug:

  triggered  some kept input makes the bug happen, whether or not the tool
             noticed
  reported   the tool said so:
               - a sanitizer report or AFL++ crash whose input triggers it, or
               - (Daikon modes only) the triggering input broke a live Daikon
                 rule in the bug's own function when it was kept

Separately, every distinct sanitizer report location counts as a finding
whether or not it was planted (the original programs have real bugs too).
Times are seconds from the start of fuzzing (after compiling).
"""
import argparse
import concurrent.futures as cf
import glob
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
from fuzzloop.mutate import pack_batch, parse_seed_file   # noqa: E402

TARGETS = ["arith", "buffer", "packet", "stack", "stats"]
TOOLS = ["loop", "learn-once", "afl"]
AFL = os.path.join(REPO, "AFLplusplus")
_PLANT = re.compile(r'(FUZZ_BUG_FATAL|FUZZ_BUG|FAULT)\("(\w+)"(?:,\s*(\d+))?')


def target_src(target):
    """Path of a target's source: fuzz/targets/<t>.c or any <t>/<t>.c below."""
    cands = [os.path.join(REPO, "fuzz", "targets", target + ".c")]
    cands += sorted(glob.glob(os.path.join(REPO, "fuzz", "targets", "**", target + ".c"),
                              recursive=True))
    for c in cands:
        if os.path.exists(c):
            return c
    raise SystemExit("no source for target %r" % target)


def planted_bugs(target):
    """{bug id: {"kind", "fault"}}. Kind comes from the header comment
    (`id (memory|UB|logic)`); `fault` is k for FAULT(...) sites, else None."""
    path = target_src(target)
    src = open(path, errors="replace").read()
    kinds = dict(re.findall(r"^ \*\s+(\w+)\s+\((memory|logic|UB)\)", src, re.M))
    # A bundle target (juliet) keeps its markers in files it #includes.
    for inc in re.findall(r'#include "(cases/[^"]+)"', src):
        src += open(os.path.join(os.path.dirname(path), inc), errors="replace").read()
    out = {}
    for macro, bid, k in _PLANT.findall(src):
        if macro == "FAULT":
            out[bid] = {"kind": "logic", "fault": int(k)}
        else:
            out[bid] = {"kind": kinds.get(bid, "UB"), "fault": None}
    return out


# --- running ----------------------------------------------------------------

def run_loop(target, outdir, seed, budget, learn_once, max_len, call_budget=20):
    cmd = [sys.executable, os.path.join(REPO, "scripts", "fuzz_loop.py"),
           target_src(target), "-o", outdir,
           "--rounds", "100000", "--patience", "100000", "--time-limit", str(budget),
           "--batch-size", "1000", "--seed", str(seed), "--max-len", str(max_len),
           "--call-budget", str(call_budget)]
    if learn_once:
        cmd.append("--learn-once")
    with open(outdir + ".log", "w") as log:
        subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=REPO,
                       timeout=budget * 3 + 900)


def build_afl(target, workdir):
    os.makedirs(workdir, exist_ok=True)
    src = [target_src(target), os.path.join(REPO, "fuzz", "runtime", "afl_harness.c")]
    main = os.path.join(workdir, target + ".afl")
    cmplog = os.path.join(workdir, target + ".cmplog")
    env = dict(os.environ, AFL_USE_ASAN="1", AFL_USE_UBSAN="1", AFL_QUIET="1")
    subprocess.run([os.path.join(AFL, "afl-clang-fast"), "-O0", "-g", "-w"] + src
                   + ["-o", main, "-lm"], env=env, check=True, capture_output=True)
    env = dict(os.environ, AFL_LLVM_CMPLOG="1", AFL_QUIET="1")
    subprocess.run([os.path.join(AFL, "afl-clang-fast"), "-O0", "-g", "-w"] + src
                   + ["-o", cmplog, "-lm"], env=env, check=True, capture_output=True)
    return main, cmplog


def run_afl(target, outdir, seed, budget, bins):
    main, cmplog = bins
    seeds_dir = outdir + ".in"
    os.makedirs(seeds_dir, exist_ok=True)
    with open(os.path.splitext(target_src(target))[0] + ".seeds") as f:
        for i, s in enumerate(parse_seed_file(f.read())):
            with open(os.path.join(seeds_dir, "seed%02d" % i), "wb") as g:
                g.write(s)
    env = dict(os.environ, AFL_SKIP_CPUFREQ="1", AFL_NO_UI="1", AFL_NO_AFFINITY="1",
               AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1")
    env.pop("AFL_SKIP_BIN_CHECK", None)   # AFL++ treats it as set at ANY value
    with open(outdir + ".log", "w") as log:
        subprocess.run([os.path.join(AFL, "afl-fuzz"), "-i", seeds_dir, "-o", outdir,
                        # 2000+: generous per-input limit (three runs share
                        # four cores), not applied to the seeds' dry run.
                        "-t", "2000+",
                        "-V", str(budget), "-s", str(seed), "-c", cmplog, "--", main],
                       env=env, stdout=log, stderr=subprocess.STDOUT,
                       timeout=budget * 3 + 600)


# --- scoring ----------------------------------------------------------------

def build_oracles(target, workdir, faults):
    """{0: all-faults oracle, k: oracle with fault k reverted}, plus the
    sanitizer build used to locate unplanted findings."""
    os.makedirs(workdir, exist_ok=True)
    out = {}
    for k in [0] + sorted(faults):
        exe = os.path.join(workdir, "%s.oracle%s" % (target, "" if k == 0 else "-r%d" % k))
        subprocess.run(["gcc", "-O0", "-w", "-fwrapv", "-fno-stack-protector",
                        "-DFUZZ_ORACLE", "-DFUZZ_SAN", "-DFUZZ_REVERT=%d" % k,
                        target_src(target), os.path.join(REPO, "fuzz", "runtime", "harness.c"),
                        "-o", exe, "-lm"], check=True, capture_output=True)
        out[k] = exe
    san = runner.build_san(target_src(target), workdir)
    return out, san


def replay(exe, inputs, workdir, timeout=120):
    """[(planted ids -> function, output hash)] per input, from an oracle build."""
    res = [({}, None) for _ in inputs]
    pending = list(range(len(inputs)))
    path = os.path.join(workdir, "replay.batch")
    while pending:
        with open(path, "wb") as f:
            f.write(pack_batch([inputs[i] for i in pending]))
        try:
            p = subprocess.run([exe, path], stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, timeout=timeout)
            err, rc = p.stderr.decode(errors="replace"), p.returncode
        except subprocess.TimeoutExpired as e:
            err, rc = (e.stderr or b"").decode(errors="replace"), "timeout"
        cur = None
        for line in err.split("\n"):
            if line.startswith("@@FUZZ-INPUT "):
                cur = int(line.split()[1])
            elif cur is not None and line.startswith("@@BUG "):
                parts = line.split()
                res[pending[cur]][0][parts[1]] = parts[2] if len(parts) > 2 else None
            elif cur is not None and line.startswith("@@OUT "):
                res[pending[cur]] = (res[pending[cur]][0], line.split()[1])
        if rc == 0 or cur is None:
            break
        pending = pending[cur + 1:]       # the culprit hung or died; skip it
    return res


def triggers(oracles, planted, inputs, workdir):
    """[(set of triggered ids, {id: function})] per input."""
    if not inputs:
        return []
    base = replay(oracles[0], inputs, workdir)
    reverted = {k: replay(exe, inputs, workdir) for k, exe in oracles.items() if k}
    out = []
    for i, (marks, outhash) in enumerate(base):
        hit = set()
        for bid, fn in marks.items():
            if bid not in planted:
                continue
            k = planted[bid]["fault"]
            if k is None:
                hit.add(bid)
            elif reverted[k][i][1] != outhash:
                hit.add(bid)          # infected AND the output changed
        out.append((hit, marks))
    return out


def san_locations(san, inputs, workdir, own):
    """{(kind, location)} the sanitizer build reports for these inputs."""
    if not inputs:
        return set()
    found = runner.run_san(san, inputs, workdir, own_sources=own)
    return {(b.kind, b.location) for bs in found.values() for b in bs
            if b.sanitizer in ("asan", "ubsan")}


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


def score_run(tool, target, outdir, oracles, san, planted, workdir, budget=None):
    trig, rep, funcs = {}, {}, {}
    own = runner.own_sources(target_src(target))

    def note(table, ids, t):
        if budget is not None and t > budget:
            return            # found after the budget ran out: does not count
        for b in ids:
            if b in planted and (b not in table or t < table[b]):
                table[b] = t

    stats = {}
    if tool == "afl":
        kept = afl_inputs(outdir, "queue") + afl_inputs(outdir, "crashes")
        crashes = afl_inputs(outdir, "crashes")
        for (data, t), (ids, fn) in zip(kept, triggers(oracles, planted, [d for d, _ in kept], workdir)):
            note(trig, ids, t)
            funcs.update(fn)
        for (data, t), (ids, _) in zip(crashes, triggers(oracles, planted, [d for d, _ in crashes], workdir)):
            note(rep, ids, t)
        found = san_locations(san, [d for d, _ in crashes], workdir, own)
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
        kept_t = triggers(oracles, planted, [d for d, _ in kept], workdir)
        for (data, t), (ids, fn) in zip(kept, kept_t):
            note(trig, ids, t)
            funcs.update(fn)
        sb = [(bytes.fromhex(b["input"]), b["time"]) for b in h["bugs"]]
        for (data, t), (ids, _) in zip(sb, triggers(oracles, planted, [d for d, _ in sb], workdir)):
            note(rep, ids, t)
        # Logic bugs, flagged live: when the loop kept a triggering input, that
        # input broke a rule that was current at the time, in the bug's own
        # function. (The rule may also be broken by correct inputs, so this
        # flags a suspect, not a proof; see the precision count.)
        alarms = true_alarms = 0
        for e, (ids, fn) in zip(h["corpus"], kept_t):
            if e["round"] == 0:
                continue
            vf = {k[0].split("(")[0].lstrip(".") for k in e.get("violates", [])}
            if not vf:
                continue
            alarms += 1
            hit = [b for b in ids if fn.get(b) in vf]
            true_alarms += bool(hit)
            note(rep, hit, e["time"])
        found = {(b["kind"], b["location"]) for b in h["bugs"]
                 if b.get("sanitizer") in ("asan", "ubsan")}
        stats = {"execs_done": h["stats"]["execs"], "corpus_count": h["corpus_size"],
                 "alarms": alarms, "true_alarms": true_alarms,
                 "rules_round0": h["rounds"][0]["invariants"] if h["rounds"] else 0}
    return {"triggered": trig, "reported": rep, "stats": stats, "functions": funcs,
            "sanitizer_findings": sorted("%s @ %s" % f for f in found)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=180, help="seconds per run")
    ap.add_argument("--seeds", type=int, default=3, help="random seeds per cell")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--targets", default=",".join(TARGETS))
    ap.add_argument("--tools", default=",".join(TOOLS))
    ap.add_argument("--call-budget", type=int, default=20,
                    help="Daikon modes: skip tracing functions averaging more "
                         "calls per seed input than this (see apply_call_budget)")
    ap.add_argument("--max-len", type=int, default=1024,
                    help="max input length for the Daikon modes (AFL++ has none)")
    ap.add_argument("--out", default=os.path.join(REPO, "bench-out"))
    ap.add_argument("--score-only", action="store_true")
    ap.add_argument("--resume", action="store_true",
                    help="skip runs that already finished (they leave a .done file)")
    args = ap.parse_args(argv)
    targets, tools = args.targets.split(","), args.tools.split(",")
    os.environ.setdefault("DAIKONDIR", os.path.join(REPO, "daikon"))

    afl_bins = {}
    if "afl" in tools and not args.score_only:
        for t in targets:
            afl_bins[t] = build_afl(t, os.path.join(args.out, "_build", t))
    os.makedirs(args.out, exist_ok=True)
    jobs = [(t, tool, s) for t in targets for tool in tools for s in range(args.seeds)]
    if not args.score_only:
        def go(job):
            t, tool, s = job
            od = os.path.join(args.out, t, tool, "seed%d" % s)
            if args.resume and os.path.exists(od + ".done"):
                return "%-14s %-10s seed %d  already done" % (t, tool, s)
            shutil.rmtree(od, ignore_errors=True)
            os.makedirs(os.path.dirname(od), exist_ok=True)
            t0 = time.time()
            note = ""
            try:
                if tool == "afl":
                    run_afl(t, od, s, args.budget, afl_bins[t])
                else:
                    run_loop(t, od, s, args.budget, tool == "learn-once", args.max_len,
                             args.call_budget)
            except subprocess.TimeoutExpired:
                note = "  KILLED (ran past 3x budget)"     # scored on what it kept
            open(od + ".done", "w").close()
            return "%-14s %-10s seed %d  %.0fs%s" % (t, tool, s, time.time() - t0, note)
        with cf.ThreadPoolExecutor(args.jobs) as ex:
            for line in ex.map(go, jobs):
                print(line, flush=True)

    results = {}
    for t in targets:
        planted = planted_bugs(t)
        work = os.path.join(args.out, "_score", t)
        faults = {v["fault"] for v in planted.values() if v["fault"]}
        oracles, san = build_oracles(t, work, faults)
        for tool in tools:
            for s in range(args.seeds):
                od = os.path.join(args.out, t, tool, "seed%d" % s)
                try:
                    r = score_run(tool, t, od, oracles, san, planted, work, args.budget)
                except (OSError, ValueError, KeyError) as e:
                    r = {"error": str(e)}
                results.setdefault(t, {}).setdefault(tool, []).append(r)
        results[t]["_bugs"] = planted
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
        for bid, info in per["_bugs"].items():
            cells = []
            for tool in tools:
                runs = per.get(tool, [])
                for key in ("triggered", "reported"):
                    cells.append(fmt_times([r.get(key, {}).get(bid) for r in runs], n))
            print("| %s | %s | %s | %s |" % (target, bid, info["kind"], " | ".join(cells)))
    print("\ntotals (bug-runs found, out of bugs x seeds):\n")
    print("| tool | triggered | reported | reported: memory/UB | reported: logic "
          "| alarm precision | median executions |")
    print("|---|---|---|---|---|---|---|")
    for tool in tools:
        tr = rp = rpm = rpl = tot = al = ta = 0
        execs = []
        for target, per in results.items():
            for r in per.get(tool, []):
                execs.append(r.get("stats", {}).get("execs_done", 0))
                al += r.get("stats", {}).get("alarms", 0)
                ta += r.get("stats", {}).get("true_alarms", 0)
                for bid, info in per["_bugs"].items():
                    tot += 1
                    tr += bid in r.get("triggered", {})
                    if bid in r.get("reported", {}):
                        rp += 1
                        if info["kind"] == "logic":
                            rpl += 1
                        else:
                            rpm += 1
        print("| %s | %d/%d | %d/%d | %d | %d | %s | %s |" % (
            tool, tr, tot, rp, tot, rpm, rpl,
            "%d/%d" % (ta, al) if al else "-",
            "%d" % statistics.median(execs) if execs else "-"))
    print("\nsanitizer findings (distinct kind@location, union over seeds):\n")
    for target, per in results.items():
        for tool in tools:
            f = sorted({x for r in per.get(tool, []) for x in r.get("sanitizer_findings", [])})
            print("  %-14s %-10s %d  %s" % (target, tool, len(f), "; ".join(f)[:300]))


if __name__ == "__main__":
    sys.exit(main())
