"""retypd output (retypd_run.py) -> tracer --type-hints files.

Function parameters come from retypd's prototypes (bin.json.types.json) in
Ghidra's parameter order; the tracer counts integer-class arguments, so float
parameters (retypd `float4_t`/`float8_t`) are skipped when numbering.

Types used:
    struct struct_N*      -> pointer to that struct's layout (one level of nested
                             struct pointers expanded)
    intN_t* / uintN_t*    -> pointer to scalar (T[] elements in the tracer)
    char1_t[k] (fields)   -> "unknown": a field of k bytes whose kind the run decides
    intN_t / uintN_t / floatN_t fields -> typed fields
Not used: char1_t* (retypd's "pointer to one unknown byte" - not a claim that it
is a C string), void and function pointers, pointers to pointers.

Usage:
    python3 scripts/rea_eval/retypd_to_hints.py RETYPD_OUT BINS OUT_DIR
"""
import json
import os
import re
import subprocess
import sys

SCAL = re.compile(r"^(u?)int(8|16|32|64)_t$")
FLT = re.compile(r"^float(4|8)_t$")


def scalar(t):
    m = SCAL.match(t)
    if m:
        return {"kind": "int", "size": int(m.group(2)) // 8, "signed": not m.group(1)}
    m = FLT.match(t)
    if m:
        return {"kind": "float", "size": int(m.group(1))}
    return None


def layout(name, structs, depth=0):
    fields = []
    for f in structs[name].get("fields", []):
        off, t = f["offset"], f["type"].strip()
        m = re.match(r"^char1_t\[(\d+)\]$", t)
        if m:
            fields.append({"off": off, "size": int(m.group(1)), "kind": "unknown"})
            continue
        s = scalar(t)
        if s:
            fields.append({"off": off, **s})
            continue
        m = re.match(r"^struct (struct_\d+)\*$", t)
        if m:
            f2 = {"off": off, "size": 8, "kind": "pointer"}
            if m.group(1) in structs and depth < 2:
                f2["pointee"] = layout(m.group(1), structs, depth + 1)
            fields.append(f2)
            continue
        if t.endswith("*"):
            fields.append({"off": off, "size": 8, "kind": "pointer"})
    return {"kind": "struct", "fields": fields}


def symbols(exe):
    out = {}
    for line in subprocess.run(["nm", exe], capture_output=True, text=True).stdout.splitlines():
        p = line.split()
        if len(p) == 3 and p[1] in "Tt":
            out[p[2]] = "0x" + p[0].lstrip("0")
    return out


def main(argv):
    src, bins, out = argv[1:4]
    os.makedirs(out, exist_ok=True)
    stats = {}
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name, "bin.json.types.json")
        exe = os.path.join(bins, name + ".exe")
        if not os.path.exists(p) or not os.path.exists(exe):
            continue
        entries = json.load(open(p))
        structs = {e["name"]: e for e in entries if e.get("type") == "struct"}
        syms = symbols(exe)
        funcs = {}
        for e in entries:
            if e.get("type") != "function" or e["name"] not in syms:
                continue
            args, k = {}, 0
            for prm in sorted(e.get("params", []), key=lambda x: x["index"]):
                t = prm["type"].strip()
                if FLT.match(t):
                    continue
                h = None
                m = re.match(r"^struct (struct_\d+)\*$", t)
                if m and m.group(1) in structs:
                    h = {"kind": "pointer", "pointee": layout(m.group(1), structs)}
                    stats["struct layout"] = stats.get("struct layout", 0) + 1
                elif t.endswith("*") and scalar(t[:-1].strip()):
                    h = {"kind": "pointer", "pointee": scalar(t[:-1].strip())}
                    stats["scalar pointer"] = stats.get("scalar pointer", 0) + 1
                if h and k < 6:
                    args[str(k)] = [h]
                k += 1
            if args:
                funcs[syms[e["name"]]] = {"args": args}
        if funcs:
            json.dump({"source": "retypd (GrammaTech) via its Ghidra plugin", "functions": funcs},
                      open(os.path.join(out, name + ".hints.json"), "w"), indent=1, sort_keys=True)
    print("hinted parameters:", stats)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
