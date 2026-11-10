"""ReSym predictions (VarDecoder + FieldDecoder) -> tracer --type-hints files.

Inputs are resym_infer.py outputs on the prompts of ghidra_to_resym.py:
    VAR.jsonl     "a1: name, type" lines per function
    FIELD.jsonl   "expr: var, vartype -> field, fieldtype" lines per function
and the prompt files (for each access's byte offset and width, and the
Ghidra parameter list). No DWARF is read.

Struct layouts are pooled ACROSS functions by the struct name ReSym predicts
for the accessed variable (the paper's cross-function idea, simplified): every
access any function makes into `struct map` contributes a field at its offset
and width; the field's kind comes from the predicted field type when it agrees
with the access width, else from the access width alone. A parameter whose
predicted type points at a struct with a pooled layout gets that layout.

    --no-fields   VarDecoder only (parameter types, no layouts)
    --filter MODE evidence from the binary (Ghidra p-code, resym_check.judge, saved
                  by ghidra_decompile.py in DECOMP_DIR): "contradicted" drops a
                  predicted parameter type the code contradicts; "supported" keeps
                  only types the code supports. Default: no filter.
    --decomp DIR  ghidra_decompile.py output (needed with --filter)

Usage:
    python3 scripts/rea_eval/resym_to_hints.py PROMPT_DIR VAR.jsonl FIELD.jsonl OUT_DIR [--no-fields]
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from resym_score import norm, parse  # noqa: E402

FLOAT_TYPES = ("/float", "/double", "/longdouble", "/float10")
INTS = {"char": (1, True), "signed char": (1, True), "unsigned char": (1, False),
        "_BYTE": (1, False), "__int8": (1, True), "unsigned __int8": (1, False),
        "int8_t": (1, True), "uint8_t": (1, False), "bool": (1, False), "_Bool": (1, False),
        "short": (2, True), "short int": (2, True), "unsigned short": (2, False),
        "short unsigned int": (2, False), "unsigned short int": (2, False), "_WORD": (2, False),
        "__int16": (2, True), "unsigned __int16": (2, False), "int16_t": (2, True),
        "uint16_t": (2, False), "int": (4, True), "signed int": (4, True),
        "unsigned int": (4, False), "unsigned": (4, False), "_DWORD": (4, False),
        "__int32": (4, True), "int32_t": (4, True), "uint32_t": (4, False),
        "long": (8, True), "long int": (8, True), "unsigned long": (8, False),
        "long unsigned int": (8, False), "long long": (8, True), "long long int": (8, True),
        "unsigned long long": (8, False), "long long unsigned int": (8, False),
        "__int64": (8, True), "unsigned __int64": (8, False), "_QWORD": (8, False),
        "int64_t": (8, True), "uint64_t": (8, False), "size_t": (8, False),
        "ssize_t": (8, True), "off_t": (8, True)}
FLOATS = {"float": 4, "double": 8}


def base_name(t):
    t = norm(t)
    t = re.sub(r"^(struct|union|enum) ", "", t)
    return t.replace("*", "").strip()


def ctype(t):
    """Parse a predicted C type: ('ptr', pointee) | ('int', size, signed) |
    ('float', size) | ('chararray', n) | ('array', n, elem) | ('named', name) | None."""
    if t is None:
        return None
    t = norm(t)
    if not t or t in ("-", "void"):
        return None
    m = re.match(r"^(.*?)\s*\[(\d+)\]$", t)
    if m:
        e = ctype(m.group(1))
        n = int(m.group(2))
        if e and e[0] == "int" and e[1] == 1 and m.group(1).strip() in ("char", "signed char"):
            return ("chararray", n)
        return ("array", n, e) if e else None
    if "(" in t:
        return ("ptr", ("func",))
    if t.endswith("*"):
        return ("ptr", ctype(t[:-1].strip()) or ("named", base_name(t[:-1])))
    t = re.sub(r"^(struct|union|enum) ", "", t)
    if t in INTS:
        return ("int",) + INTS[t]
    if t in FLOATS:
        return ("float", FLOATS[t])
    return ("named", t)


def pointee_hint(p, layouts, depth=0):
    if p is None:
        return {"kind": "void"}
    if p[0] == "int":
        if p[1] == 1 and p[2]:
            return {"kind": "char", "size": 1}
        return {"kind": "int", "size": p[1], "signed": p[2]}
    if p[0] == "float":
        return {"kind": "float", "size": p[1]}
    if p[0] == "ptr":
        return {"kind": "pointer", "size": 8}
    if p[0] == "named":
        lay = layouts.get(p[1])
        h = {"kind": "struct", "name": p[1]}
        if lay and depth < 2:
            h["fields"] = [dict(f, pointee=pointee_hint(f["_pointee"], layouts, depth + 1))
                           if "_pointee" in f else f for f in lay]
            h["fields"] = [{k: v for k, v in f.items() if k != "_pointee"} for f in h["fields"]]
        return h
    return {"kind": "void"}


def field_leaf(off, width, ft):
    """A layout field for an access of `width` bytes at `off` typed `ft`."""
    if ft and ft[0] == "chararray":
        return {"off": off, "size": ft[1], "kind": "chararray"}
    if ft and ft[0] == "array" and ft[2] and ft[2][0] in ("int", "float"):
        e = ft[2]
        w = e[1]
        elem = {"kind": e[0], "size": w}
        if e[0] == "int":
            elem["signed"] = e[2]
        return {"off": off, "size": w * ft[1], "kind": "array", "count": ft[1], "elem": elem}
    if ft and ft[0] == "ptr" and width == 8:
        return {"off": off, "size": 8, "kind": "pointer", "_pointee": ft[1]}
    if ft and ft[0] == "float" and ft[1] == width:
        return {"off": off, "size": width, "kind": "float"}
    if ft and ft[0] == "int" and ft[1] == width:
        return {"off": off, "size": width, "kind": "int", "signed": ft[2]}
    # Unknown or disagreeing type: the access width alone, as a signed int -
    # the run's own default reading of an untyped field.
    return {"off": off, "size": width, "kind": "int", "signed": True}


def build_layouts(field_prompts, field_preds):
    votes = collections.defaultdict(lambda: collections.Counter())
    var_struct = collections.defaultdict(collections.Counter)   # (bin, addr, ordinal) -> name
    for fp in field_prompts:
        pred = field_preds.get(fp["funname"])
        if pred is None:
            continue
        ans = {}
        for line in pred.splitlines():
            m = re.match(r"\s*(.+?):\s*([^,]*?),\s*(.+?)\s*->\s*([^,]*?),\s*(.+?)\s*$", line)
            if m:
                ans.setdefault(m.group(1).strip(), (m.group(3), m.group(4).strip(), m.group(5)))
        for expr, ordinal, off, width in fp["accesses"]:
            if expr not in ans:
                continue
            vtype, fname, ftype = ans[expr]
            if fname == "-":
                continue      # ReSym: not a struct field (a pointer to scalars)
            ct = ctype(vtype)
            if not ct or ct[0] != "ptr" or not ct[1] or ct[1][0] != "named":
                continue
            name = ct[1][1]
            leaf = field_leaf(off, width, ctype(ftype))
            key = json.dumps({k: v for k, v in leaf.items()}, sort_keys=True, default=str)
            votes[name][key] += 1
            var_struct[(fp["bin"], fp["addr"], ordinal)][name] += 1
    layouts = {}
    for name, c in votes.items():
        chosen = []
        cands = sorted(c.items(), key=lambda kv: (-kv[1], json.loads(kv[0])["size"]))
        for key, _ in cands:
            f = json.loads(key)
            if f.get("_pointee") is not None:
                f["_pointee"] = tuple(_tup(f["_pointee"]))
            if any(f["off"] < g["off"] + g["size"] and g["off"] < f["off"] + f["size"]
                   for g in chosen):
                continue
            chosen.append(f)
        layouts[name] = sorted(chosen, key=lambda f: f["off"])
    return layouts, var_struct


def _tup(x):
    return tuple(_tup(v) if isinstance(v, list) else v for v in x)


def arg_index(params, ordinal):
    """Tracer integer-class index of a Ghidra parameter, or None."""
    k = 0
    for o, _n, _t, gt in sorted(params):
        if (gt or "").lower() in FLOAT_TYPES:
            if o == ordinal:
                return None
            continue
        if o == ordinal:
            return k if k < 6 else None
        k += 1
    return None


def _opt(argv, name):
    return argv[argv.index(name) + 1] if name in argv else None


def main(argv):
    no_fields = "--no-fields" in argv
    filt = _opt(argv, "--filter")
    decomp = _opt(argv, "--decomp")
    skip = {filt, decomp}
    args = [a for a in argv[1:] if not a.startswith("--") and a not in skip]
    binaries = {}
    if filt:
        from check import Binary
        from resym_check import judge

        def verdict(b, addr, ordinal, tstr):
            if b not in binaries:
                binaries[b] = Binary(json.load(open(os.path.join(decomp, b + ".json"))))
            return judge(binaries[b], None, addr, ordinal, tstr)
    pdir, var_path, field_path, out_dir = args[:4]
    os.makedirs(out_dir, exist_ok=True)
    vprompts = [json.loads(l) for l in open(os.path.join(pdir, "var_prompts.jsonl"))]
    fprompts = [json.loads(l) for l in open(os.path.join(pdir, "field_prompts.jsonl"))]
    vpred = {}
    for l in open(var_path):
        r = json.loads(l)
        vpred[r["funname"]] = r["predict"]
    fpred = {}
    if not no_fields and os.path.exists(field_path):
        for l in open(field_path):
            r = json.loads(l)
            fpred[r["funname"]] = r["predict"]
    layouts, var_struct = build_layouts(fprompts, fpred) if not no_fields else ({}, {})
    out = collections.defaultdict(dict)
    stats = collections.Counter()
    for vp in vprompts:
        pred = parse(vpred.get(vp["funname"], ""))
        spec = {"args": {}}
        for o, n, _t, _gt in vp["params"]:
            k = arg_index(vp["params"], o)
            if k is None or n not in pred:
                continue
            ct = ctype(pred[n][1])
            if filt:
                v = verdict(vp["bin"], vp["addr"], o, pred[n][1])
                stats[f"evidence {v}"] += 1
                if v == "FAIL" or (filt == "supported" and v != "PASS"):
                    continue
            vs = var_struct.get((vp["bin"], vp["addr"], o)) if var_struct else None
            if vs:
                # The FieldDecoder named the struct this parameter's accesses go into.
                ct = ("ptr", ("named", vs.most_common(1)[0][0]))
            if not ct:
                continue
            if ct[0] == "ptr":
                h = {"kind": "pointer", "pointee": pointee_hint(ct[1], layouts)}
                stats["struct layout" if h["pointee"].get("fields") else "pointer"] += 1
            elif ct[0] == "int":
                h = {"kind": "int", "size": ct[1], "signed": ct[2]}
                stats["scalar"] += 1
            else:
                continue
            spec["args"][str(k)] = [h]
        if spec["args"]:
            out[vp["bin"]][vp["addr"]] = spec
    for b, funcs in out.items():
        with open(os.path.join(out_dir, f"{b}.hints.json"), "w") as fh:
            json.dump({"source": "ReSym on Ghidra pseudocode" + (" (VarDecoder only)" if no_fields
                                                                 else " (VarDecoder + FieldDecoder)"),
                       "functions": funcs}, fh, indent=1, sort_keys=True, default=list)
    print(f"binaries {len(out)}  struct layouts pooled {len(layouts)}  hinted args: "
          + ", ".join(f"{k} {v}" for k, v in sorted(stats.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
