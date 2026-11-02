"""Static field evidence for the tracer's --static-layouts (phase 11, step 6).

For each binary: strip it (Ghidra must not see DWARF), import it once through
REA's MCP server, analyze every internal function, and keep each integer
parameter's constant-offset dereferences from high p-code (observe.py) - every
path, including the ones the emulated run did not take.

Only facts that do not depend on Ghidra's own type guess are kept: the
dereference itself, its constant offset and its LOAD/STORE size. A deref with
an unknown (variable) offset is dropped.

Output, one file per binary, OUT_DIR/<basename>.json:
    {"functions": {"0x401136": {"1": [[off, size], ...], ...}}}
keyed by the tracer's raw argument index (1 = first INTEGER-class register
argument). Ghidra's parameter list is mapped to it by skipping parameters it
typed float/double, which pass in xmm registers.

Usage:
    GHIDRA_INSTALL_DIR=... python3 scripts/rea_eval/static_layouts.py OUT_DIR BIN [BIN ...]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import ReaMcp  # noqa: E402
from collect_pcode import _slim  # noqa: E402
from observe import Function  # noqa: E402

FLOAT_TYPES = ("/float", "/double", "/longdouble", "/float10")


def raw_indices(params):
    """{ghidra ordinal: tracer raw index} for integer-class parameters."""
    out, k = {}, 0
    for p in sorted(params, key=lambda p: p["ordinal"]):
        if (p.get("data_type") or "").lower() in FLOAT_TYPES:
            continue
        k += 1
        if k <= 6:
            out[p["ordinal"]] = k
    return out


def static_fields(rec):
    """{raw index: sorted [[off, size]]} for one analyzed function record."""
    if not rec.get("available"):
        return {}
    fn = Function(rec)
    res = {}
    for ordinal, raw in raw_indices(rec.get("parameters", [])).items():
        obs = fn.param(ordinal)
        fields = {(off, size) for off, size, _ in obs["derefs"]
                  if isinstance(off, int) and off >= 0 and size}
        if fields:
            res[str(raw)] = sorted([o, s] for o, s in fields)
    return res


def run(binary, out_dir):
    out = os.path.join(out_dir, os.path.basename(binary).rsplit(".exe", 1)[0] + ".json")
    if os.path.exists(out):
        return out, "cached"
    with tempfile.TemporaryDirectory() as d:
        stripped = os.path.join(d, os.path.basename(binary))
        shutil.copy(binary, stripped)
        subprocess.run(["strip", "--strip-debug", stripped], check=True)
        c = ReaMcp(env={"REA_ANALYSIS_PROVIDER": "ghidra"})
        funcs, errors = {}, 0
        try:
            c.call("open_binary", {"path": stripped})
            procs = c.call("list_procedures", {})["normalized_result"]
            for p in procs:
                pr = p.get("procedure", {})
                if pr.get("external") or pr.get("thunk_target"):
                    continue
                a = p["address"]
                if not a.startswith("0x"):
                    continue
                try:
                    sf = static_fields(_slim(c.call("analyze_function", {"procedure": a})))
                except Exception:
                    errors += 1
                    continue
                if sf:
                    funcs[a] = sf
        finally:
            c.close()
    with open(out, "w") as fh:
        json.dump({"functions": funcs}, fh, indent=1, sort_keys=True)
    return out, f"{len(funcs)} functions with fields, {errors} errors"


def main(argv):
    out_dir = argv[1]
    os.makedirs(out_dir, exist_ok=True)
    for b in argv[2:]:
        out, msg = run(b, out_dir)
        print(f"{os.path.basename(b):32s} {msg}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
