"""ORACLE answers pushed through the ReSym ingestion path (a pipeline self-test).

Question it answers: if the model had answered every prompt CORRECTLY, would
resym_to_hints.py + the tracer have turned those answers into the gain the
direct DWARF hint files give?  If not, the ingestion path loses information
(a bug, or a limit of going through Ghidra's parameter lists and accesses).

It writes prediction files in resym_infer.py's format, one line per prompt of
ghidra_to_resym.py, with the DWARF truth spelled as C types:
    OUT/var_pred.jsonl     "a1: x, int*"                       (VarDecoder format)
    OUT/field_pred.jsonl   "(_DWORD *)(a1 + 8): v, S_ab12* -> f8, int"   (FieldDecoder format)
Feed them to resym_to_hints.py exactly as real predictions are fed.  DWARF is
read here; the output is an ORACLE diagnostic, never a result.

Usage:
    python3 scripts/rea_eval/pipe_oracle.py BINS TRUTH.jsonl PROMPT_DIR OUT_DIR
"""
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hints_from_dwarf import struct_hints  # noqa: E402
from resym_to_hints import arg_index  # noqa: E402

INT_NAMES = {1: "char", 2: "short", 4: "int", 8: "long"}


def int_name(size, signed, plain_char=True):
    if size == 1:
        return "char" if signed else "unsigned char"
    base = INT_NAMES.get(size, "int")
    return base if signed else "unsigned " + base


def sanitize(c):
    return re.sub(r"\W+", "_", re.sub(r"^(struct|union) ", "", c or "anon")).strip("_") or "anon"


def truth_cstr(t):
    """ground_truth.py type dict -> a C spelling resym_to_hints.ctype() parses."""
    k = t.get("kind")
    if k == "int":
        return int_name(t.get("size"), t.get("signed") is not False)
    if k == "bool":
        return "bool"
    if k == "enum":
        return "unsigned int"
    if k == "float":
        return {4: "float", 8: "double"}.get(t.get("size"), "double")
    if k == "pointer":
        p = t.get("pointee")
        if not p or p.get("kind") in ("void", "func", "other"):
            return "void*"
        if p.get("kind") in ("struct", "union"):
            return "struct " + sanitize(p.get("c")) + "*"
        if p.get("kind") == "array":
            return truth_cstr(p.get("elem") or {"kind": "pointer"}) + "*"
        return truth_cstr(p) + "*"
    if k in ("struct", "union"):
        return "struct " + sanitize(t.get("c"))
    return "void*"


def sname(layout):
    return "S_" + hashlib.md5(json.dumps(layout.get("fields"), sort_keys=True).encode()).hexdigest()[:8]


def leaf_cstr(f):
    k = f.get("kind")
    if k == "int":
        return int_name(f.get("size"), f.get("signed") is not False)
    if k == "float":
        return {4: "float", 8: "double"}.get(f.get("size"), "double")
    if k == "chararray":
        return f"char[{f['size']}]"
    if k == "array":
        e = f.get("elem") or {}
        en = ({4: "float", 8: "double"}.get(e.get("size"), "double") if e.get("kind") == "float"
              else "void*" if e.get("kind") == "pointer"
              else int_name(e.get("size"), e.get("signed") is not False))
        return f"{en}[{f.get('count')}]"
    if k == "pointer":
        p = f.get("pointee") or {}
        pk = p.get("kind")
        if pk == "char":
            return "char*"
        if pk == "struct" and p.get("fields"):
            return sname(p) + "*"
        if pk == "int":
            return int_name(p.get("size"), p.get("signed") is not False) + "*"
        if pk == "float":
            return {4: "float", 8: "double"}.get(p.get("size"), "double") + "*"
        return "void*"
    return "void"


def main(argv):
    bins, truth_path, pdir, out = argv[1:5]
    os.makedirs(out, exist_ok=True)
    truth = {}
    for line in open(truth_path):
        t = json.loads(line)
        truth[os.path.basename(t["binary"])[:-4]] = {f["addr"]: f for f in t["functions"]}
    nv = nf = 0
    with open(os.path.join(out, "var_pred.jsonl"), "w") as vp:
        for line in open(os.path.join(pdir, "var_prompts.jsonl")):
            pr = json.loads(line)
            f = truth.get(pr["bin"], {}).get(pr["addr"])
            if not f:
                continue
            ints = [p for p in f["params"] if p["type"].get("kind") != "float"]
            ans = []
            for o, n, _t, _gt in pr["params"]:
                k = arg_index(pr["params"], o)
                if k is not None and k < len(ints):
                    ans.append(f"{n}: {ints[k]['name']}, {truth_cstr(ints[k]['type'])}")
            vp.write(json.dumps({"funname": pr["funname"], "predict": "\n".join(ans)}) + "\n")
            nv += len(ans)
    layouts = {}
    with open(os.path.join(out, "field_pred.jsonl"), "w") as fp:
        for line in open(os.path.join(pdir, "field_prompts.jsonl")):
            pr = json.loads(line)
            b = pr["bin"]
            if b not in layouts:
                layouts[b] = struct_hints(os.path.join(bins, b + ".exe"))[0]
            args = (layouts[b].get(pr["addr"]) or {}).get("args", {})
            ans = []
            for expr, ordinal, off, width in pr["accesses"]:
                k = arg_index(pr["params"], ordinal)
                h = (args.get(str(k)) or [None])[0] if k is not None else None
                p = (h or {}).get("pointee") or {}
                if p.get("kind") == "struct" and p.get("fields"):
                    leaf = next((x for x in p["fields"] if x["off"] == off), None)
                    if leaf is not None:
                        ans.append(f"{expr}: v, {sname(p)}* -> f{off}, {leaf_cstr(leaf)}")
                        continue
                ans.append(f"{expr}: v, void* -> -, void")
            fp.write(json.dumps({"funname": pr["funname"], "predict": "\n".join(ans)}) + "\n")
            nf += sum(1 for a in ans if "-> -," not in a)
    print(f"oracle answers written: {nv} parameter types, {nf} struct-field accesses")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
