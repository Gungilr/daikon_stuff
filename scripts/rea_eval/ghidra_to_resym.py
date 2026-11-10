"""Turn Ghidra pseudocode into ReSym's IDA-style prompts (VarDecoder + FieldDecoder).

ReSym was trained on IDA Hex-Rays output. Ghidra's is close but spelled
differently, so this rewrites it towards IDA's conventions:
    FUN_00401136 -> sub_401136      param_N -> aN      locals -> vK (K after the params)
    undefined8/4/2/1 -> _QWORD/_DWORD/_WORD/_BYTE      long -> __int64   ulong -> unsigned __int64
    uint -> unsigned int            small hex constants -> decimal
The result is still out of ReSym's training style; that is part of what is measured.

FieldDecoder questions are the memory accesses made through a PARAMETER with a
constant offset, written as IDA writes them: `(_DWORD *)(a1 + 24)`, `(_QWORD *)a1`,
`a1[2]`, `a1` (= *a1). Each keeps its byte offset and access width, computed here
from Ghidra's own pointer arithmetic, so a model answer maps back to (offset, width).

Output (one line per function, two files):
    OUT/var_prompts.jsonl    {"input", "output": "a1:", "n_answers", "bin", "funname", "addr", "params"}
    OUT/field_prompts.jsonl  same, plus "accesses": [[expr, param ordinal, offset, width], ...]
"params": [[ordinal, ida name, ida type, ghidra data_type]].

Usage:
    python3 scripts/rea_eval/ghidra_to_resym.py DECOMP_DIR OUT_DIR
"""
import json
import os
import re
import sys

TYPE_MAP = [
    (r"\bundefined8\b", "_QWORD"), (r"\bundefined4\b", "_DWORD"), (r"\bundefined2\b", "_WORD"),
    (r"\bundefined1\b", "_BYTE"), (r"\bundefined\b", "_BYTE"),
    (r"\bulonglong\b", "unsigned __int64"), (r"\blonglong\b", "__int64"),
    (r"\bulong\b", "unsigned __int64"), (r"\blong\b", "__int64"), (r"\buint\b", "unsigned int"),
    (r"\bushort\b", "unsigned __int16"), (r"\buchar\b", "unsigned __int8"),
    (r"\bbyte\b", "unsigned __int8"), (r"\bsbyte\b", "__int8"),
]
SIZES = {"_BYTE": 1, "char": 1, "bool": 1, "unsigned __int8": 1, "__int8": 1,
         "unsigned char": 1, "_WORD": 2, "short": 2, "unsigned __int16": 2, "__int16": 2,
         "_DWORD": 4, "int": 4, "unsigned int": 4, "float": 4, "__int32": 4,
         "_QWORD": 8, "__int64": 8, "unsigned __int64": 8, "double": 8, "void": 1}
LOCAL = re.compile(r"\b((?:local|in|extraout|unaff|auStack|puStack|uStack|iStack|lStack|"
                   r"pcStack)_\w+|[a-z]{1,4}Var\d+)\b")
FLOAT_TYPES = ("/float", "/double", "/longdouble", "/float10")
MAX_ACCESSES = 24


def sizeof(t):
    t = t.strip()
    if t.endswith("*"):
        return 8
    t = re.sub(r"\b(const|volatile|struct|union)\b", "", t).strip()
    return SIZES.get(t)


def to_ida(pseudo):
    """(ida code, [(ordinal, ida name, ida type)]) or (None, None)."""
    code = re.sub(r"/\*.*?\*/", "", pseudo, flags=re.S).strip("\n")
    if "{" in code:
        # Ghidra wraps a long signature over several lines; IDA prints one.
        head, body = code.split("{", 1)
        code = re.sub(r"\s+", " ", head).strip() + "\n{" + body
    m = re.search(r"^(.*?)\bFUN_([0-9a-fA-F]+)\s*\((.*?)\)\s*$", code, re.M)
    if not m:
        return None, None
    plist = [] if m.group(3).strip() in ("", "void") else [p.strip() for p in m.group(3).split(",")]
    params = []
    for p in plist:
        pm = re.match(r"(.*?)\b(param_\d+)$", p)
        if not pm:
            return None, None
        params.append((int(pm.group(2)[6:]) - 1, pm.group(2), pm.group(1).strip()))
    ren = {g: f"a{o + 1}" for o, g, _ in params}
    locs = []
    for name in LOCAL.findall(code):
        if name not in ren and name not in locs:
            locs.append(name)
    for k, name in enumerate(locs):
        ren[name] = f"v{len(params) + 1 + k}"
    for g, i in sorted(ren.items(), key=lambda kv: -len(kv[0])):
        code = re.sub(rf"\b{re.escape(g)}\b", i, code)
    for pat, rep in TYPE_MAP:
        code = re.sub(pat, rep, code)
    code = re.sub(r"\bFUN_0*([0-9a-fA-F]+)\b", lambda x: "sub_" + x.group(1).upper(), code)
    code = re.sub(r"\b0x([0-9a-fA-F]{1,4})\b", lambda x: str(int(x.group(1), 16)), code)
    # IDA marks a function with parameters __fastcall
    code = re.sub(r"^(.*?)\b(sub_[0-9A-F]+)\s*\(", lambda x: x.group(1) + (
        "__fastcall " if params else "") + x.group(2) + "(", code, count=1, flags=re.M)
    ptypes = {}
    sig = re.search(r"\bsub_[0-9A-F]+\s*\((.*?)\)", code)
    for p in ([] if not sig or sig.group(1).strip() in ("", "void") else sig.group(1).split(",")):
        pm = re.match(r"(.*?)\b(a\d+)$", p.strip())
        if pm:
            ptypes[pm.group(2)] = pm.group(1).strip()
    return code, [(o, f"a{o + 1}", ptypes.get(f"a{o + 1}", t)) for o, _, t in params]


def accesses(code, params):
    """[(expr, ordinal, byte offset, width)] for constant-offset accesses via params."""
    ptype = {n: t for _, n, t in params}
    ordn = {n: o for o, n, _ in params}
    out, seen = [], set()

    def add(expr, n, off, w):
        if n in ordn and w and off is not None and off >= 0 and expr not in seen:
            seen.add(expr)
            out.append((expr, ordn[n], off, w))

    def elem(n):
        t = ptype.get(n, "")
        return sizeof(t[:-1].strip()) if t.endswith("*") else None

    T = r"([A-Za-z_][\w ]*?\s*\*+)"
    for m in re.finditer(rf"\*\({T}\)\((a\d+) \+ (\d+)\)", code):
        t, n, k = m.group(1), m.group(2), int(m.group(3))
        e = elem(n) if ptype.get(n, "").endswith("*") else 1
        add(f"({t.strip()})({n} + {k})", n, k * (e or 1), sizeof(t.strip()[:-1]))
    for m in re.finditer(rf"\*\({T}\)\(\(__int64\)(a\d+) \+ (\d+)\)", code):
        t, n, k = m.group(1), m.group(2), int(m.group(3))
        add(f"({t.strip()})((__int64){n} + {k})", n, k, sizeof(t.strip()[:-1]))
    for m in re.finditer(rf"\*\({T}\)(a\d+)\b(?!\s*[\[+])", code):
        t, n = m.group(1), m.group(2)
        add(f"({t.strip()}){n}", n, 0, sizeof(t.strip()[:-1]))
    for m in re.finditer(r"\b(a\d+)\[(\d+)\]", code):
        n, k = m.group(1), int(m.group(2))
        e = elem(n)
        if e:
            add(f"{n}[{k}]", n, k * e, e)
    for m in re.finditer(r"(?<![\w)\]*])\*(a\d+)\b(?!\s*[\[+])", code):
        n = m.group(1)
        add(n, n, 0, elem(n))
    return out[:MAX_ACCESSES]


def main(argv):
    src, out_dir = argv[1:3]
    os.makedirs(out_dir, exist_ok=True)
    vp = open(os.path.join(out_dir, "var_prompts.jsonl"), "w")
    fp = open(os.path.join(out_dir, "field_prompts.jsonl"), "w")
    nv = nf = 0
    for f in sorted(os.listdir(src)):
        if not f.endswith(".json"):
            continue
        d = json.load(open(os.path.join(src, f)))
        for addr, r in sorted(d["functions"].items()):
            if not r.get("pseudocode"):
                continue
            code, params = to_ida(r["pseudocode"])
            if code is None or not params:
                continue
            gtypes = {p["ordinal"]: p.get("data_type") for p in r.get("parameters", [])}
            meta = {"bin": f[:-5], "funname": f"{f[:-5]}:{addr}", "addr": addr,
                    "params": [[o, n, t, gtypes.get(o)] for o, n, t in params]}
            names = ", ".join(f"`{n}`" for _, n, _ in params)
            vp.write(json.dumps({**meta, "input": f"What are the original name and data type of "
                                 f"variables {names}?\n```\n{code}\n```",
                                 "output": f"{params[0][1]}:", "n_answers": len(params)}) + "\n")
            nv += 1
            acc = accesses(code, params)
            if acc:
                q = ", ".join(a[0] for a in acc)
                fp.write(json.dumps({**meta, "input": f"```\n{code}\n```\nWhat are the variable "
                                     f"name and type for the following memory accesses:{q}?\n",
                                     "output": f"{acc[0][0]}:", "n_answers": len(acc),
                                     "accesses": acc}) + "\n")
                nf += 1
    print(f"var prompts {nv}, field prompts {nf}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
