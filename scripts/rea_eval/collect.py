"""Run REA (Ghidra provider) over stripped binaries and cache what it says about types.

For each binary, ONE `rea mcp` process imports the stripped file once, then:
  - list_procedures          -> which truth addresses Ghidra recognised as functions
  - inspect_native_api       -> param / return types for each truth function address
  - inspect_native_data_type -> the type Ghidra assigned at each truth global address

Only ADDRESSES come from the ground truth file - never names or types - so REA
sees nothing but the stripped binary.  Results go to OUT_DIR/<sha256>.json and
an existing file is skipped, so the run can be resumed.

Usage:
    GHIDRA_INSTALL_DIR=... python3 scripts/rea_eval/collect.py TRUTH.jsonl STRIPPED_DIR OUT_DIR
"""
import json
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import ReaMcp  # noqa: E402


def _boundary(res):
    b = res.get("normalized_result", {}).get("boundary", {})
    if not b.get("available", True) and "parameters" not in b:
        return {"available": False, "reason": b.get("reason")}

    def slim(t):
        if not t:
            return None
        return {k: t.get(k) for k in ("ordinal", "name", "data_type", "size_bytes",
                                       "storage", "confidence")}
    return {"available": True,
            "signature_source": b.get("signature_source"),
            "calling_convention": b.get("calling_convention"),
            "return": slim(b.get("return_type")),
            "params": [slim(p) for p in b.get("parameters", [])]}


def _dtype(res):
    r = res.get("normalized_result", {})
    keep = ("status", "reason", "name", "kind", "size_bytes", "referenced_type",
            "array_count", "array_stride_bytes", "total_fields")
    out = {k: r.get(k) for k in keep}
    out["fields"] = [{k: f.get(k) for k in ("offset_bytes", "size_bytes", "type_id", "name")}
                     for f in (r.get("fields") or [])[:64]]
    return out


def run_binary(truth, stripped_path):
    rec = {"binary": os.path.basename(stripped_path), "procedures": [], "functions": {},
           "globals": {}, "errors": []}
    t0 = time.time()
    c = ReaMcp(env={"REA_ANALYSIS_PROVIDER": "ghidra"})
    try:
        c.call("open_binary", {"path": os.path.abspath(stripped_path)})
        procs = c.call("list_procedures", {})["normalized_result"]
        rec["procedures"] = [p["address"] for p in procs
                             if not p.get("procedure", {}).get("external")]
        rec["import_seconds"] = round(time.time() - t0, 1)
        known = set(rec["procedures"])
        for f in truth["functions"]:
            a = f["addr"]
            if a not in known:
                rec["functions"][a] = {"recognised": False}
                continue
            try:
                rec["functions"][a] = {"recognised": True,
                                       **_boundary(c.call("inspect_native_api", {"procedure": a}))}
            except Exception as e:  # one bad function must not lose the binary
                rec["functions"][a] = {"recognised": True, "error": str(e)[:300]}
        for g in truth["globals"]:
            a = g["addr"]
            try:
                rec["globals"][a] = _dtype(c.call("inspect_native_data_type", {"address": a}))
            except Exception as e:
                rec["globals"][a] = {"status": "error", "reason": str(e)[:300]}
    except Exception:
        rec["errors"].append(traceback.format_exc()[-1500:])
    finally:
        c.close()
    rec["seconds"] = round(time.time() - t0, 1)
    return rec


def main(truth_path, stripped_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    truths = [json.loads(line) for line in open(truth_path)]
    for i, t in enumerate(truths, 1):
        h = os.path.basename(t["binary"])
        out = os.path.join(out_dir, h + ".json")
        if os.path.exists(out):
            continue
        rec = run_binary(t, os.path.join(stripped_dir, h))
        with open(out + ".tmp", "w") as fh:
            json.dump(rec, fh)
        os.replace(out + ".tmp", out)
        print(f"[{i}/{len(truths)}] {h[:12]} funcs={len(t['functions'])} "
              f"globals={len(t['globals'])} {rec['seconds']}s errors={len(rec['errors'])}",
              flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:4])
