#!/usr/bin/env python3
"""Build, trace and grade a corpus of real C programs at -O0, -O1 and -O2.

Feeds scripts/audit_heuristics.py, which grades every inference rule in
docs/HEURISTICS.md against debug info. Everything lands under audit/, which is
gitignored because it holds third-party sources and large outputs:

  audit/src/llvm/          LLVM test-suite single-file benchmarks, pinned commit
  audit/src/kvasir/O<n>/   per-level copies of Daikon's Kvasir test programs
  audit/build/O<n>/        the -g binaries, one per program and level
  audit/out/O<n>/          tracer outputs: <name>.json, .dtrace.gz, .log
  audit/results.jsonl      one graded record per program and level

Every step is resumable and skips work already done:

  audit_corpus.py fetch      download the LLVM sources
  audit_corpus.py build      compile everything at each level
  audit_corpus.py run        trace every binary (--jobs N in parallel)
  audit_corpus.py grade      grade every trace into results.jsonl
  audit_corpus.py summary    print the per-rule tables
  audit_corpus.py all        all of the above, in order

The programs are run without input files: the tracer cannot supply file or
stdin input yet (docs/HEURISTICS.md, H37), so programs that need it mostly run
their error paths. Only what executed is graded.
"""
from __future__ import print_function

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT = os.path.join(ROOT, "audit")
KVASIR_TESTS = os.path.join(ROOT, "daikon", "tests", "kvasir-tests")
SHIM = os.path.join(ROOT, "scripts", "unicorn_dwarf.py")
LEVELS = ("0", "1", "2")

# llvm/llvm-test-suite, SingleSource/Benchmarks: every single-file C program
# that needs no input. Pinned so the corpus is reproducible.
LLVM_SHA = "57fbfe58ed5b1363083ad8d3515a2aae4108ae84"
LLVM_FILES = {
    "BenchmarkGame": ["fannkuch.c", "n-body.c", "nsieve-bits.c",
                      "partialsums.c", "puzzle.c", "recursive.c",
                      "spectral-norm.c"],
    "CoyoteBench": ["almabench.c", "huffbench.c", "lpbench.c"],
    "Dhrystone": ["dry.c", "fldry.c"],
    "Linpack": ["linpack-pc.c"],
    "McGill": ["chomp.c", "exptree.c", "misr.c", "queens.c"],
    "Misc": ["ReedSolomon.c", "dt.c", "evalloop.c", "fbench.c", "ffbench.c",
             "flops-1.c", "flops-2.c", "flops-3.c", "flops-4.c", "flops-5.c",
             "flops-6.c", "flops-7.c", "flops-8.c", "flops.c", "fp-convert.c",
             "himenobmtxpa.c", "lowercase.c", "mandel-2.c", "mandel.c",
             "matmul_f64_4x4.c", "oourafft.c", "perlin.c", "pi.c",
             "revertBits.c", "richards_benchmark.c", "salsa20.c",
             "whetstone.c"],
    "Shootout": ["ackermann.c", "ary3.c", "fib2.c", "hash.c", "heapsort.c",
                 "hello.c", "lists.c", "matrix.c", "methcall.c",
                 "nestedloop.c", "objinst.c", "random.c", "sieve.c",
                 "strcat.c"],
    "Stanford": ["Bubblesort.c", "FloatMM.c", "IntMM.c", "Oscar.c", "Perm.c",
                 "Puzzle.c", "Queens.c", "Quicksort.c", "RealMM.c",
                 "Towers.c", "Treesort.c"],
}

# The Kvasir suite's own flags (Makefile.common), with the level varied and
# warnings off. Passing CFLAGS on make's command line replaces every `+=`.
def _cflags(level):
    return (f"-gdwarf-3 -O{level} -fno-stack-protector -fcommon -std=gnu89 "
            f"-no-pie -w")


def _llvm_flags(level):
    return ["-gdwarf-3", f"-O{level}", "-fno-stack-protector", "-fcommon",
            "-no-pie", "-w"]


def _log(msg):
    print(msg, flush=True)


# --- fetch ------------------------------------------------------------------------

def fetch():
    base = (f"https://raw.githubusercontent.com/llvm/llvm-test-suite/"
            f"{LLVM_SHA}/SingleSource/Benchmarks")
    got = 0
    for d, files in sorted(LLVM_FILES.items()):
        dest_dir = os.path.join(AUDIT, "src", "llvm", d)
        os.makedirs(dest_dir, exist_ok=True)
        for f in files:
            dest = os.path.join(dest_dir, f)
            if os.path.exists(dest):
                continue
            try:
                with urllib.request.urlopen(f"{base}/{d}/{f}", timeout=60) as r:
                    data = r.read()
            except Exception as e:
                _log(f"[!] fetch {d}/{f}: {e}")
                continue
            with open(dest, "wb") as out:
                out.write(data)
            got += 1
    _log(f"[+] fetched {got} new file(s); pinned at {LLVM_SHA[:12]}")


# --- build ------------------------------------------------------------------------

def _kvasir_programs():
    """[(dir, NAME, args)] for every C program in the Kvasir suite."""
    out = []
    for d in sorted(os.listdir(KVASIR_TESTS)):
        mk = os.path.join(KVASIR_TESTS, d, "Makefile")
        if not os.path.isfile(mk):
            continue
        text = open(mk, errors="replace").read()
        if re.search(r"^\s*CPLUSPLUS\b", text, re.M):
            continue
        m = re.search(r"^\s*NAME\s*:?=\s*(\S+)", text, re.M)
        name = m.group(1) if m else d
        m = re.search(r"^\s*PROGRAM_ARGS\s*:?=\s*(.*)$", text, re.M)
        args = m.group(1).strip() if m else ""
        args = args.split("<")[0].strip()          # no stdin redirection yet
        out.append((d, name, args))
    return out


def build(levels):
    manifest = {}
    built = failed = 0
    for level in levels:
        bdir = os.path.join(AUDIT, "build", f"O{level}")
        os.makedirs(bdir, exist_ok=True)

        for src in sorted(_llvm_sources()):
            d = os.path.basename(os.path.dirname(src))
            name = f"llvm-{d}-{os.path.splitext(os.path.basename(src))[0]}"
            exe = os.path.join(bdir, name + ".exe")
            manifest[name] = {"source": "llvm", "args": ""}
            if os.path.exists(exe):
                continue
            ok = _gcc(src, exe, _llvm_flags(level))
            if not ok:
                ok = _gcc(src, exe, _llvm_flags(level) + ["-std=gnu89"])
            built += ok
            failed += not ok

        kroot = os.path.join(AUDIT, "src", "kvasir", f"O{level}")
        os.makedirs(kroot, exist_ok=True)
        common = os.path.join(kroot, "Makefile.common")
        if not os.path.exists(common):
            shutil.copy(os.path.join(KVASIR_TESTS, "Makefile.common"), common)
        for d, name, args in _kvasir_programs():
            prog = f"kvasir-{d}"
            exe = os.path.join(bdir, prog + ".exe")
            manifest[prog] = {"source": "kvasir", "args": args}
            if os.path.exists(exe):
                continue
            work = os.path.join(kroot, d)
            if not os.path.exists(work):
                shutil.copytree(os.path.join(KVASIR_TESTS, d), work,
                                symlinks=True)
            try:
                proc = subprocess.run(
                    ["make", "-s", "-C", work, name, "CC=gcc",
                     f"CFLAGS={_cflags(level)}"],
                    capture_output=True, text=True, timeout=900)
                ok = proc.returncode == 0 and os.path.exists(
                    os.path.join(work, name))
            except subprocess.TimeoutExpired:
                ok = False
            if ok:
                shutil.copy(os.path.join(work, name), exe)
                built += 1
            else:
                failed += 1
                _log(f"[!] build O{level} {prog}: make failed")
    with open(os.path.join(AUDIT, "build", "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1, sort_keys=True)
    _log(f"[+] built {built} new binaries, {failed} failed")


def _llvm_sources():
    root = os.path.join(AUDIT, "src", "llvm")
    for d in sorted(os.listdir(root)) if os.path.isdir(root) else []:
        for f in sorted(os.listdir(os.path.join(root, d))):
            if f.endswith(".c"):
                yield os.path.join(root, d, f)


def _gcc(src, exe, flags):
    try:
        proc = subprocess.run(["gcc", *flags, "-o", exe, src, "-lm"],
                              capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return False
    if proc.returncode != 0:
        if os.path.exists(exe):
            os.remove(exe)
        return False
    return True


# --- run ----------------------------------------------------------------------------

def _binaries(levels):
    for level in levels:
        bdir = os.path.join(AUDIT, "build", f"O{level}")
        if not os.path.isdir(bdir):
            continue
        for f in sorted(os.listdir(bdir)):
            if f.endswith(".exe"):
                yield level, f[:-4], os.path.join(bdir, f)


# Two passes per binary. Functions are traced without globals, because each
# sample snapshots the data sections and that cost grows with samples times data
# size (2.5 GB for Stanford's Towers at 150,000 instructions). Globals get a
# second, shorter run of their own.
PASSES = {"functions": ["--ignore-globals"], "globals": []}


def _trace_one(pass_name, level, name, exe, args, max_insns, timeout):
    odir = os.path.join(AUDIT, "out", pass_name, f"O{level}")
    os.makedirs(odir, exist_ok=True)
    dump = os.path.join(odir, name + ".json")
    if os.path.exists(dump):
        return name, level, "cached"
    cmd = [sys.executable, SHIM, exe, "-o", os.path.join(odir, name + ".dtrace"),
           "--gzip", "--start-func", "main", "--tier", "9", "--detect-void",
           "--max-insns", str(max_insns), "--timeout", str(timeout),
           "--dump-inferences", dump, "-q", *PASSES[pass_name]]
    if args:
        cmd += ["--argv", args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout + 300, stdin=subprocess.DEVNULL,
                              cwd=ROOT)
        status = "ok" if proc.returncode == 0 else f"exit {proc.returncode}"
        log = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        status, log = "timeout", ""
    with open(os.path.join(odir, name + ".log"), "w") as f:
        f.write(log)
    return name, level, status


def run(pass_name, levels, jobs, max_insns, timeout):
    manifest = {}
    mpath = os.path.join(AUDIT, "build", "manifest.json")
    if os.path.exists(mpath):
        manifest = json.load(open(mpath))
    work = [(lv, nm, exe, manifest.get(nm, {}).get("args", ""))
            for lv, nm, exe in _binaries(levels)]
    _log(f"[+] {pass_name} pass: tracing {len(work)} binaries, "
         f"{max_insns} instructions each, {jobs} worker(s)")
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = [pool.submit(_trace_one, pass_name, lv, nm, exe, args,
                            max_insns, timeout)
                for lv, nm, exe, args in work]
        for fut in concurrent.futures.as_completed(futs):
            name, level, status = fut.result()
            done += 1
            if status not in ("ok", "cached"):
                _log(f"[!] O{level} {name}: {status}")
            if done % 25 == 0:
                _log(f"    {done}/{len(work)}")
    _log("[+] tracing finished")


# --- grade and summary ---------------------------------------------------------------

def grade(levels):
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import audit_heuristics as A
    results = os.path.join(AUDIT, "results.jsonl")
    n = errors = 0
    with open(results, "w") as out:
        for level, name, exe in _binaries(levels):
            odir = os.path.join(AUDIT, "out", "functions", f"O{level}")
            gpath = os.path.join(AUDIT, "out", "globals", f"O{level}",
                                 name + ".json")
            dump_path = os.path.join(odir, name + ".json")
            if not os.path.exists(dump_path):
                continue
            try:
                dump = json.load(open(dump_path))
                gdump = (json.load(open(gpath)) if os.path.exists(gpath)
                         else None)
                record = A.grade(exe, dump,
                                 os.path.join(odir, name + ".dtrace.gz"),
                                 f"O{level}", globals_dump=gdump)
            except Exception as e:
                errors += 1
                record = {"program": name, "label": f"O{level}",
                          "error": f"{type(e).__name__}: {e}"[:200],
                          "rules": {}}
            out.write(json.dumps(record, sort_keys=True) + "\n")
            n += 1
    _log(f"[+] graded {n} runs ({errors} grading errors) -> {results}")


def summary():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import audit_heuristics as A
    A.summarize([os.path.join(AUDIT, "results.jsonl")])


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("step", choices=["fetch", "build", "run", "grade",
                                     "summary", "all"])
    p.add_argument("--levels", default="0,1,2")
    p.add_argument("--jobs", type=int, default=3)
    p.add_argument("--pass", dest="pass_name", choices=sorted(PASSES),
                   help="run only one tracing pass (default: both)")
    p.add_argument("--max-insns", type=int, default=300_000,
                   help="instruction budget for the functions pass")
    p.add_argument("--globals-insns", type=int, default=40_000,
                   help="instruction budget for the globals pass")
    p.add_argument("--timeout", type=int, default=600,
                   help="emulation time limit per binary, seconds")
    a = p.parse_args(argv)
    levels = tuple(a.levels.split(","))
    if a.step in ("fetch", "all"):
        fetch()
    if a.step in ("build", "all"):
        build(levels)
    if a.step in ("run", "all"):
        if a.pass_name in (None, "functions"):
            run("functions", levels, a.jobs, a.max_insns, a.timeout)
        if a.pass_name in (None, "globals"):
            run("globals", levels, a.jobs, a.globals_insns, a.timeout)
    if a.step in ("grade", "all"):
        grade(levels)
    if a.step in ("summary", "all"):
        summary()
    return 0


if __name__ == "__main__":
    sys.exit(main())
