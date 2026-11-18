"""TypeForge output (typeforge_run.py) -> tracer --type-hints files.

Per binary: every function parameter TypeForge tied to a TypeConstraint with a
FINAL struct layout (`*_final.json`; library types `*_final_DI.json` carry no
layout, and ambiguous `*_morph.json` ones are left out - the hint abstains where
TypeForge itself is unsure) gets that layout as its pointee.

Field kinds: TypeForge's typed primitives (`int`, `long`, `char`, `float`, ...)
and pointers (`char *` as a string; a pointer whose ptrRef names another final
layout, nested one level) become typed hint fields. Its untyped `byte` / `word`
/ `dword` / `qword` become "unknown" fields: a field of that width whose kind
the run decides (hints.py).

Parameter numbering: TypeForge's `param_N` is Ghidra's ordinal N-1; the tracer
counts integer-class arguments, so float/double parameters (from the Ghidra
parameter types saved by ghidra_decompile.py) are skipped.

Usage:
    python3 scripts/rea_eval/typeforge_to_hints.py TF_OUT DECOMP_DIR OUT_DIR
"""
import glob
import json
import os
import re
import sys

TYPED = {"char": ("int", 1, True), "uchar": ("int", 1, False), "short": ("int", 2, True),
         "ushort": ("int", 2, False), "int": ("int", 4, True), "uint": ("int", 4, False),
         "long": ("int", 8, True), "ulong": ("int", 8, False), "longlong": ("int", 8, True),
         "ulonglong": ("int", 8, False), "bool": ("int", 1, False),
         "float": ("float", 4, None), "double": ("float", 8, None)}
UNTYPED = {"byte", "word", "dword", "qword", "undefined", "undefined1", "undefined2",
           "undefined4", "undefined8"}
FLOAT_TYPES = ("/float", "/double", "/longdouble", "/float10")


def layouts(d):
    out = {}
    for p in glob.glob(os.path.join(d, "*_final.json")):
        tc = re.match(r"(TypeConstraint_[0-9a-f]+)_final\.json$", os.path.basename(p))
        if not tc:
            continue
        for s in json.load(open(p)).values():
            if isinstance(s, dict) and s.get("desc") == "Structure" and s.get("layout"):
                out[tc.group(1)] = s
    return out


def to_layout(s, lays, depth=0):
    fields = []
    refs = s.get("ptrRef") or {}
    for o, m in sorted(s["layout"].items(), key=lambda kv: int(kv[0], 16)):
        off, size, t = int(o, 16), m.get("size"), (m.get("type") or "").strip()
        if not size:
            continue
        if m.get("desc") == "Pointer" or t.endswith("*"):
            if size != 8:
                continue
            f = {"off": off, "size": 8, "kind": "pointer"}
            if re.fullmatch(r"(const )?char \*", t):
                f["pointee"] = {"kind": "char", "size": 1}
            elif o in refs and refs[o].get("ptrLevel") == 1 and refs[o].get("refSkt") in lays \
                    and depth < 2:
                f["pointee"] = to_layout(lays[refs[o]["refSkt"]], lays, depth + 1)
            fields.append(f)
        elif t in TYPED and TYPED[t][1] == size:
            k, w, sg = TYPED[t]
            fields.append({"off": off, "size": w, "kind": k, **({"signed": sg} if k == "int" else {})})
        elif t in UNTYPED or t in TYPED:
            fields.append({"off": off, "size": size, "kind": "unknown"})
    return {"kind": "struct", "fields": fields}


def main(argv):
    tf, decomp, out = argv[1:4]
    os.makedirs(out, exist_ok=True)
    total = 0
    for name in sorted(os.listdir(tf)):
        d = os.path.join(tf, name)
        vt = os.path.join(d, "varType.json")
        if not os.path.exists(vt):
            continue
        lays = layouts(d)
        dec = os.path.join(decomp, name + ".json")
        gparams = {}
        if os.path.exists(dec):
            for a, r in json.load(open(dec))["functions"].items():
                gparams[int(a, 16)] = {p["ordinal"]: p.get("data_type") for p in r.get("parameters", [])}
        funcs = {}
        for a, f in json.load(open(vt)).items():
            addr = int(a, 16)
            for k, p in (f.get("Parameters") or {}).items():
                m = re.search(r"param_(\d+)$", p.get("Name", ""))
                tc = p.get("TypeConstraint")
                if not m or tc not in lays:
                    continue
                ordinal = int(m.group(1)) - 1
                gp = gparams.get(addr, {})
                if (gp.get(ordinal) or "").lower() in FLOAT_TYPES:
                    continue
                idx = sum(1 for o in range(ordinal) if (gp.get(o) or "").lower() not in FLOAT_TYPES)
                if idx >= 6:
                    continue
                funcs.setdefault(hex(addr), {"args": {}})["args"][str(idx)] = [
                    {"kind": "pointer", "pointee": to_layout(lays[tc], lays)}]
                total += 1
        if funcs:
            json.dump({"source": "TypeForge phase 1 (program analysis)", "functions": funcs},
                      open(os.path.join(out, name + ".hints.json"), "w"), indent=1, sort_keys=True)
    print(f"parameters given a TypeForge layout: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
