"""Run TypeForge (S&P 2025, github.com/noobone123/TypeForge) over a suite, headless.

For each <name>.exe in BINS: copy it, `strip --strip-debug` the copy (DWARF goes,
the symbol table stays - TypeForge needs `main` by name, and the tracer reads
the same symbols), and run TypeForge's phase 1 (program analysis, no LLM):

    analyzeHeadless PROJ tf -deleteProject -import BIN -postScript TypeForge.java \\
        output=OUT/<name> main_name=main

Needs Ghidra 11.0.3 with the TypeForge extension installed (GHIDRA_11), and the
local fix to TypeForge.java that sets Global.outputDirectory (without it the
script crashes with a NullPointerException in ReTyper.prepare).

Usage:
    GHIDRA_11=... python3 scripts/rea_eval/typeforge_run.py BINS OUT
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time


def main(argv):
    bins, out = argv[1:3]
    ghidra = os.environ["GHIDRA_11"]
    os.makedirs(out, exist_ok=True)
    for f in sorted(os.listdir(bins)):
        if not f.endswith(".exe") or f.endswith("_stripped.exe"):
            continue
        name = f[:-4]
        odir = os.path.join(out, name)
        with tempfile.TemporaryDirectory() as d:
            b = os.path.join(d, name)
            shutil.copy(os.path.join(bins, f), b)
            subprocess.run(["strip", "--strip-debug", b], check=True)
            os.makedirs(os.path.join(d, "proj"))
            t0 = time.time()
            p = subprocess.run([os.path.join(ghidra, "support/analyzeHeadless"),
                                os.path.join(d, "proj"), "tf", "-deleteProject", "-import", b,
                                "-postScript", "TypeForge.java", f"output={os.path.abspath(odir)}",
                                "main_name=main"], capture_output=True, text=True)
            log = p.stdout + p.stderr
        os.makedirs(odir, exist_ok=True)
        with open(os.path.join(odir, "typeforge.log"), "w") as fh:
            fh.write(log)
        files = os.listdir(odir)
        kinds = {k: sum(1 for x in files if x.endswith(k + ".json"))
                 for k in ("_final", "_final_DI", "_global_morph", "_range_morph")}
        err = "SCRIPT ERROR" if "SCRIPT ERROR" in log else ""
        print(f"{name:28s} {time.time() - t0:5.1f}s  structs final {kinds['_final']}  "
              f"lib {kinds['_final_DI']}  ambiguous {kinds['_global_morph'] + kinds['_range_morph']}  "
              f"{err}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
