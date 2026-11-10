"""Decompile the functions a tracer run reached, with Ghidra through REA.

For each <name>.exe in BINS: copy it, `strip --strip-all` the copy (so Ghidra
sees what ReSym was trained on: no symbols, internal functions as FUN_xxx),
open it in one REA session and keep, for every function the tracer reached
(ENTER program points in TRACES/<name>.tracer.t10.dtrace, located by the
unstripped binary's symbol table - the same table the tracer reads), Ghidra's
pseudocode, parameter list and p-code (the static evidence check.py uses).

Output: OUT/<name>.json  {"functions": {"0x401136": {"name", "pseudocode",
"parameters", ...p-code...}}, "procedures": {...}}

Usage:
    GHIDRA_INSTALL_DIR=... python3 scripts/rea_eval/ghidra_decompile.py BINS TRACES OUT
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import ReaMcp  # noqa: E402
from collect_pcode import _slim  # noqa: E402


def reached(dtrace):
    out = set()
    for line in open(dtrace, errors="replace"):
        m = re.match(r"ppt \.\.(.+)\(\):::ENTER$", line.strip())
        if m:
            out.add(m.group(1))
    return out


def symbols(exe):
    out = {}
    for line in subprocess.run(["nm", exe], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[1] in "Tt":
            out[p[2]] = "0x" + p[0].lstrip("0")
    return out


def main(argv):
    bins, traces, out_dir = argv[1:4]
    os.makedirs(out_dir, exist_ok=True)
    for f in sorted(os.listdir(bins)):
        if not f.endswith(".exe") or f.endswith("_stripped.exe"):
            continue
        name = f[:-4]
        out = os.path.join(out_dir, name + ".json")
        dt = os.path.join(traces, f"{name}.tracer.t10.dtrace")
        if os.path.exists(out) or not os.path.exists(dt):
            continue
        syms = symbols(os.path.join(bins, f))
        want = {syms[n]: n for n in reached(dt) if n in syms}
        rec = {"binary": f, "procedures": {}, "functions": {}, "errors": []}
        with tempfile.TemporaryDirectory() as d:
            stripped = os.path.join(d, f)
            shutil.copy(os.path.join(bins, f), stripped)
            subprocess.run(["strip", "--strip-all", stripped], check=True)
            c = ReaMcp(env={"REA_ANALYSIS_PROVIDER": "ghidra"})
            try:
                c.call("open_binary", {"path": stripped})
                for p in c.call("list_procedures", {})["normalized_result"]:
                    rec["procedures"][p["address"]] = {
                        "name": p.get("value"),
                        "external": p.get("procedure", {}).get("external"),
                        "thunk_target": p.get("procedure", {}).get("thunk_target")}
                for a, sym in sorted(want.items()):
                    try:
                        r = _slim(c.call("analyze_function", {"procedure": a}))
                        r["symbol"] = sym     # for the report only; never put in a prompt
                        rec["functions"][a] = r
                    except Exception as e:
                        rec["errors"].append(f"{a}: {e}")
            finally:
                c.close()
        with open(out, "w") as fh:
            json.dump(rec, fh)
        print(f"{name:28s} reached {len(want):3d}  decompiled {len(rec['functions']):3d}  "
              f"errors {len(rec['errors'])}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
