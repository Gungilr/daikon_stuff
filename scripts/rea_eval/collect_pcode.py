"""Collect Ghidra high p-code (via REA analyze_function) for type checking.

For each stripped binary, one `rea mcp` import, then analyze_function for every
function ADDRESS in the ground truth (addresses only - no names, no types).
Kept per function: p-code operations (opcode, inputs, output), parameter uses,
Ghidra's prototype, callees, and pseudocode (for a later AI stage).  Also the
procedure name map, so calls to library functions can be recognised.

Output: OUT_DIR/<sha256>.json.gz, skipped if present (resumable).

Usage:
    GHIDRA_INSTALL_DIR=... python3 scripts/rea_eval/collect_pcode.py TRUTH.jsonl STRIPPED_DIR OUT_DIR [WORKERS]
"""
import gzip
import json
import os
import sys
import time
import traceback
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import ReaMcp  # noqa: E402


def _vn(v):
    if not v:
        return None
    return [v.get("kind"), v.get("size_bytes"), v.get("location"), v.get("constant_hex")]


def _slim(res):
    n = res.get("normalized_result", {})
    vf = n.get("native_value_flow") or {}
    out = {"available": vf.get("available", False), "truncated": vf.get("truncated"),
           "parameters": vf.get("parameters", []), "parameter_uses": vf.get("parameter_uses", []),
           "def_use": [[e["definition"], e["use"], e["input_index"]] for e in vf.get("def_use", [])],
           "ops": [[op["id"], op["opcode"], [_vn(i) for i in op.get("inputs", [])], _vn(op.get("output"))]
                   for op in vf.get("operations", []) if op.get("block_membership") != "detached"]}
    ps = n.get("pseudocode")
    out["pseudocode"] = ps.get("text") if isinstance(ps, dict) else ps
    callees = n.get("callees")
    if isinstance(callees, dict):
        callees = callees.get("items") or callees.get("callees")
    out["callees"] = [{"address": c.get("address"), "name": c.get("value") or c.get("name")}
                      for c in (callees or []) if isinstance(c, dict)]
    return out


def run_binary(args):
    truth, stripped_path, out = args
    t0 = time.time()
    rec = {"binary": os.path.basename(stripped_path), "procedures": {}, "functions": {}, "errors": []}
    c = ReaMcp(env={"REA_ANALYSIS_PROVIDER": "ghidra"})
    try:
        c.call("open_binary", {"path": os.path.abspath(stripped_path)})
        for p in c.call("list_procedures", {})["normalized_result"]:
            rec["procedures"][p["address"]] = {"name": p.get("value"),
                                               "external": p.get("procedure", {}).get("external"),
                                               "thunk_target": p.get("procedure", {}).get("thunk_target")}
        for f in truth["functions"]:
            a = f["addr"]
            if a not in rec["procedures"]:
                continue
            try:
                rec["functions"][a] = _slim(c.call("analyze_function", {"procedure": a}))
            except Exception as e:
                rec["functions"][a] = {"error": str(e)[:300]}
    except Exception:
        rec["errors"].append(traceback.format_exc()[-1500:])
    finally:
        c.close()
    rec["seconds"] = round(time.time() - t0, 1)
    with gzip.open(out + ".tmp", "wt") as fh:
        json.dump(rec, fh)
    os.replace(out + ".tmp", out)
    return f"{rec['binary'][:12]} funcs={len(rec['functions'])} {rec['seconds']}s errors={len(rec['errors'])}"


def main(truth_path, stripped_dir, out_dir, workers=2):
    os.makedirs(out_dir, exist_ok=True)
    jobs = []
    for line in open(truth_path):
        t = json.loads(line)
        h = os.path.basename(t["binary"])
        out = os.path.join(out_dir, h + ".json.gz")
        if not os.path.exists(out):
            jobs.append((t, os.path.join(stripped_dir, h), out))
    with ProcessPoolExecutor(int(workers)) as pool:
        for i, msg in enumerate(pool.map(run_binary, jobs), 1):
            print(f"[{i}/{len(jobs)}] {msg}", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:5])
