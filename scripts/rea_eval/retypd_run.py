"""Run retypd (GrammaTech) over a suite through its Ghidra plugin, headless.

For each <name>.exe in BINS: `strip --strip-debug` a copy, run Retypd.java
(the GhidraRetypd extension, built against stock Ghidra 11.0.3) and keep the
constraints it generated (bin.json) and the types the solver inferred
(bin.json.types.json) in OUT/<name>/.  `retypd-ghidra` must be on PATH.

Usage:
    GHIDRA_11=... PATH=<retypd venv>/bin:$PATH python3 scripts/rea_eval/retypd_run.py BINS OUT
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time


def main(argv):
    bins, out = argv[1:3]
    ghidra = os.environ["GHIDRA_11"]
    for f in sorted(os.listdir(bins)):
        if not f.endswith(".exe") or f.endswith("_stripped.exe"):
            continue
        name = f[:-4]
        odir = os.path.join(out, name)
        os.makedirs(odir, exist_ok=True)
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, name)
            shutil.copy(os.path.join(bins, f), b)
            subprocess.run(["strip", "--strip-debug", b], check=True)
            os.makedirs(os.path.join(d, "proj"))
            t0 = time.time()
            p = subprocess.run([os.path.join(ghidra, "support/analyzeHeadless"),
                                os.path.join(d, "proj"), "rt", "-deleteProject", "-import", b,
                                "-postScript", "Retypd.java"], capture_output=True, text=True)
        log = p.stdout + p.stderr
        open(os.path.join(odir, "retypd.log"), "w").write(log)
        m = re.search(r"Writing JSON output to (\S+)/bin\.json", log)
        ok = False
        if m:
            for fn in ("bin.json", "bin.json.types.json"):
                src = os.path.join(m.group(1), fn)
                if os.path.exists(src):
                    shutil.copy(src, odir)
                    ok = fn.endswith("types.json") or ok
            shutil.rmtree(m.group(1), ignore_errors=True)
        print(f"{name:28s} {time.time() - t0:5.1f}s  {'types' if ok else 'NO TYPES'}"
              f"{'  ERROR' if 'ERROR' in log else ''}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
