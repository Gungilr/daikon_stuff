"""Run the tracer + Daikon over a suite with one --type-hints file per binary.

For every <name>.exe in BINS (skipping *_stripped.exe): tracer at --tier 10
with the given extra flags and, if HINTS/<name>.hints.json exists,
--type-hints; then Daikon. Writes OUT/traces/<name>.tracer.t10<tag>.dtrace and
OUT/inv/<name>.tracer.t10<tag>.txt, and links the Kvasir reports from KV_INV so
scripts/score_suite.py can score OUT/inv directly:

    python3 scripts/rea_eval/suite_hints.py --bins bench/ksuite --kv-inv bench/ksuite_inv \\
        --hints HINT_DIR --out OUT --tag .oracle -- --infer-unobserved-fields --poison-uninitialized
    python3 scripts/score_suite.py --bins bench/ksuite --inv OUT/inv --tier 10 --suffix .oracle
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--bins", required=True)
    p.add_argument("--kv-inv", required=True)
    p.add_argument("--hints", default=None)
    p.add_argument("--out", required=True)
    p.add_argument("--tag", default="")
    p.add_argument("--daikon", default=os.path.join(ROOT, "daikon"))
    p.add_argument("--only", default=None, help="comma-separated binary names")
    p.add_argument("extra", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    extra = [x for x in a.extra if x != "--"]
    tdir, idir = os.path.abspath(os.path.join(a.out, "traces")), os.path.abspath(os.path.join(a.out, "inv"))
    os.makedirs(tdir, exist_ok=True)
    os.makedirs(idir, exist_ok=True)
    cp = f"{a.daikon}/java:{a.daikon}/java/lib/*"
    only = set(a.only.split(",")) if a.only else None
    total = 0.0
    for f in sorted(os.listdir(a.bins)):
        if not f.endswith(".exe") or f.endswith("_stripped.exe"):
            continue
        name = f[:-4]
        if only and name not in only:
            continue
        kv = os.path.join(a.kv_inv, f"{name}.kvasir.txt")
        link = os.path.join(idir, f"{name}.kvasir.txt")
        if os.path.exists(kv) and not os.path.exists(link):
            os.symlink(os.path.abspath(kv), link)
        dtrace = os.path.join(tdir, f"{name}.tracer.t10{a.tag}.dtrace")
        log = os.path.join(tdir, f"{name}.tracer.t10{a.tag}.log")
        inv = os.path.join(idir, f"{name}.tracer.t10{a.tag}.txt")
        cmd = [sys.executable, os.path.join(ROOT, "scripts/unicorn_dwarf.py"),
               os.path.join(a.bins, f), "-o", dtrace, "--start-func", "main",
               "--tier", "10"] + extra
        h = os.path.join(a.hints, f"{name}.hints.json") if a.hints else None
        if h and os.path.exists(h):
            cmd += ["--type-hints", h]
        t0 = time.time()
        with open(log, "w") as lf:
            rc = subprocess.run(cmd, stdout=lf, stderr=subprocess.STDOUT).returncode
        dt = time.time() - t0
        total += dt
        status = "ok" if rc == 0 and os.path.getsize(dtrace) else "TRACER FAIL"
        if status == "ok":
            with open(inv, "w") as fh:
                subprocess.run(["java", "-cp", cp, "daikon.Daikon",
                                "-o", os.path.join(tdir, f"{name}.inv.gz"), dtrace],
                               stdout=fh, stderr=subprocess.STDOUT, cwd=tdir)
        hint_line = ""
        for line in open(log, errors="replace"):
            if "Type hints:" in line:
                hint_line = line.split("Type hints:", 1)[1].strip()
        print(f"{name:30s} {status:12s} tracer {dt:5.1f}s  hints: {hint_line}", flush=True)
    print(f"tracer total {total:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
