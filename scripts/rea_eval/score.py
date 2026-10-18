"""Score REA's (Ghidra's) recovered types against DWARF ground truth.

Every prediction is reduced to the facts the tracer's invariants need:
  kind      void | int | float | bool | pointer | struct | union | array | enum | func
  size      bytes
  signed    for integers, when stated
  pointee   for pointers: char | int | float | struct | pointer | func | void
An `undefinedN` (Ghidra's "N unknown bytes") is ABSTAIN: it carries a size but
no claim, and is counted separately from a wrong answer.  For a fuzzing
consumer a confident wrong type is worse than no type, so that is reported on
its own line.

Duplicate functions (same name and declared signature in several projects) and
duplicate globals are scored once.

Usage:
    python3 scripts/rea_eval/score.py TRUTH.jsonl REA_OUT_DIR [--examples N]
"""
import collections
import json
import os
import random
import re
import sys

GHIDRA_INTS = {
    "char": (1, True), "schar": (1, True), "uchar": (1, False), "byte": (1, False),
    "sbyte": (1, True), "short": (2, True), "ushort": (2, False), "word": (2, False),
    "int": (4, True), "uint": (4, False), "dword": (4, False),
    "long": (8, True), "ulong": (8, False), "longlong": (8, True), "ulonglong": (8, False),
    "qword": (8, False), "size_t": (8, False), "ssize_t": (8, True),
    "int8_t": (1, True), "uint8_t": (1, False), "int16_t": (2, True), "uint16_t": (2, False),
    "int32_t": (4, True), "uint32_t": (4, False), "int64_t": (8, True), "uint64_t": (8, False),
    "wchar_t": (4, True), "char16_t": (2, False), "char32_t": (4, False),
    "int128": (16, True), "uint128": (16, False),
}
GHIDRA_FLOATS = {"float": 4, "double": 8, "longdouble": 16, "float10": 10, "float16": 16}


def ghidra_type(s, size=None):
    """Parse a Ghidra data-type display/path name into the common fact set."""
    if s is None:
        return {"kind": "abstain", "size": size}
    s = s.strip()
    s = s.rsplit("/", 1)[-1] if s.startswith("/") else s
    if s.endswith("*") or s in ("pointer", "pointer64", "addr"):
        base = s[:-1].strip() if s.endswith("*") else "undefined"
        inner = ghidra_type(base)
        if base.startswith("code") or inner["kind"] == "func":
            pk = "func"
        elif inner["kind"] == "pointer":
            pk = "pointer"
        elif inner["kind"] == "int" and inner.get("char"):
            pk = "char"
        elif inner["kind"] in ("abstain", "void"):
            pk = "void"
        elif inner["kind"] == "named":  # a type Ghidra knows by name (FILE, a libc struct)
            pk = "struct"
        else:
            pk = inner["kind"]
        return {"kind": "pointer", "size": 8, "pointee": pk}
    m = re.fullmatch(r"undefined(\d*)", s)
    if m:
        return {"kind": "abstain", "size": int(m.group(1) or 1)}
    if s == "void":
        return {"kind": "void", "size": 0}
    if s in ("bool", "_Bool"):
        return {"kind": "bool", "size": 1}
    if s in GHIDRA_INTS:
        sz, signed = GHIDRA_INTS[s]
        return {"kind": "int", "size": sz, "signed": signed,
                "char": s in ("char", "uchar", "schar", "byte", "sbyte")}
    if s in GHIDRA_FLOATS:
        return {"kind": "float", "size": GHIDRA_FLOATS[s]}
    if s.startswith("code"):
        return {"kind": "func", "size": None}
    if re.search(r"\[\d*\]$", s) or s == "string":
        return {"kind": "array", "size": size}
    # any other named type is a user/library type Ghidra knows (struct, enum, typedef)
    return {"kind": "named", "size": size, "name": s}


def truth_facts(d):
    k = d["kind"]
    f = {"kind": k, "size": d.get("size")}
    if k == "int":
        f.update(signed=d.get("signed"), char=d.get("char"))
    elif k == "pointer":
        p = d.get("pointee", {"kind": "void"})
        pk = p["kind"]
        if pk == "int" and p.get("char"):
            pk = "char"
        elif pk in ("enum", "bool"):
            pk = "int"
        elif pk == "union":
            pk = "struct"
        elif pk in ("other",):
            pk = "void"
        f["pointee"] = pk
    elif k == "enum":
        f.update(kind="int", signed=None)
    return f


def same_kind(pred, true):
    pk, tk = pred["kind"], true["kind"]
    if pk == "named":  # Ghidra-known named type: right if truth is an aggregate/enum
        return tk in ("struct", "union", "int") if True else False
    if tk == "union":
        tk = "struct"
    return pk == tk


class Tally:
    def __init__(self):
        self.c = collections.Counter()
        self.wrong = collections.Counter()
        self.examples = collections.defaultdict(list)

    def add(self, cat, pred, true, label):
        c = self.c
        c["total"] += 1
        c[f"total:{cat}"] += 1
        if pred is None:
            c["not_recognised"] += 1
            return
        if pred["kind"] == "abstain":
            c["abstain"] += 1
            c[f"abstain:{cat}"] += 1
            if pred.get("size") and true.get("size") and pred["size"] == true["size"]:
                c["abstain_size_ok"] += 1
            return
        c["answered"] += 1
        c[f"answered:{cat}"] += 1
        tptr, pptr = true["kind"] == "pointer", pred["kind"] == "pointer"
        if tptr == pptr:
            c["ptr_vs_scalar_ok"] += 1
        kind_ok = same_kind(pred, true)
        if kind_ok:
            c["kind_ok"] += 1
            c[f"kind_ok:{cat}"] += 1
        else:
            key = f"{true['kind']}->{pred['kind']}"
            self.wrong[key] += 1
            if len(self.examples[key]) < 3:
                self.examples[key].append(label)
        if pred.get("size") and true.get("size"):
            c["size_checked"] += 1
            c["size_ok"] += pred["size"] == true["size"]
        if kind_ok and true["kind"] == "int" and true.get("signed") is not None \
                and pred.get("signed") is not None:
            c["sign_checked"] += 1
            c["sign_ok"] += pred["signed"] == true["signed"]
        if kind_ok and tptr:
            c["pointee_checked"] += 1
            ok = pred.get("pointee") == true.get("pointee")
            c["pointee_ok"] += ok
            if pred.get("pointee") == "void":
                c["pointee_void"] += 1
            if not ok:
                key = f"*{true.get('pointee')}->*{pred.get('pointee')}"
                self.wrong[key] += 1
                if len(self.examples[key]) < 3:
                    self.examples[key].append(label)
        exact = kind_ok and (not pred.get("size") or not true.get("size") or pred["size"] == true["size"]) \
            and (true["kind"] != "int" or pred.get("signed") in (None, true.get("signed"))) \
            and (not tptr or pred.get("pointee") == true.get("pointee"))
        c["exact"] += exact


def category(t):
    k = t["kind"]
    if k == "pointer":
        return "ptr->" + t.get("pointee", "?")
    if k == "int":
        return "char" if t.get("char") else "int"
    return k


def pct(a, b):
    return f"{100.0 * a / b:5.1f}%" if b else "   n/a"


def main(argv):
    truth_path, rea_dir = argv[1], argv[2]
    n_ex = int(argv[argv.index("--examples") + 1]) if "--examples" in argv else 0
    truths = [json.loads(line) for line in open(truth_path)]
    P, R, G = Tally(), Tally(), Tally()
    arity = collections.Counter()
    seen_f, seen_g = set(), set()
    binaries = recognised = funcs_total = 0
    import_secs = []
    for t in truths:
        h = os.path.basename(t["binary"])
        path = os.path.join(rea_dir, h + ".json")
        if not os.path.exists(path):
            continue
        rea = json.load(open(path))
        binaries += 1
        if rea.get("import_seconds"):
            import_secs.append(rea["import_seconds"])
        for f in t["functions"]:
            sig = (f["name"], f["return"]["c"], tuple(p["type"]["c"] for p in f["params"]))
            if sig in seen_f:
                continue
            seen_f.add(sig)
            funcs_total += 1
            r = rea["functions"].get(f["addr"], {})
            ok = r.get("recognised") and r.get("available", True) and "error" not in r
            recognised += bool(ok)
            label = f"{f['name']} @{f['addr']} ({h[:8]})"
            tparams = [p for p in f["params"] if p["type"]["kind"] != "varargs"]
            if ok:
                rp = r.get("params") or []
                arity["checked"] += 1
                arity["ok"] += len(rp) == len(tparams)
                arity["over"] += len(rp) > len(tparams)
                arity["under"] += len(rp) < len(tparams)
            tr = truth_facts(f["return"])
            pr = ghidra_type((r.get("return") or {}).get("data_type"),
                             (r.get("return") or {}).get("size_bytes")) if ok else None
            R.add(category(tr), pr, tr, label + " return")
            for i, p in enumerate(tparams):
                tp = truth_facts(p["type"])
                pp = None
                if ok:
                    rp = r.get("params") or []
                    pp = ghidra_type(rp[i]["data_type"], rp[i].get("size_bytes")) if i < len(rp) \
                        else {"kind": "abstain", "size": None}
                P.add(category(tp), pp, tp, f"{label} param{i} {p['type']['c']}")
        for g in t["globals"]:
            gsig = (g["name"], g["type"]["c"], g["type"].get("size"))
            if gsig in seen_g:
                continue
            seen_g.add(gsig)
            tg = truth_facts(g["type"])
            r = rea["globals"].get(g["addr"], {})
            if r.get("status") != "available":
                pg = {"kind": "abstain", "size": None}
            else:
                k = r.get("kind")
                if k == "scalar":
                    pg = ghidra_type(r.get("name"), r.get("size_bytes"))
                elif k == "pointer":
                    pg = ghidra_type((r.get("referenced_type") or "undefined") + " *")
                elif k in ("struct", "union"):
                    pg = {"kind": k, "size": r.get("size_bytes")}
                elif k == "array":
                    pg = {"kind": "array", "size": r.get("size_bytes")}
                elif k == "enum":
                    pg = {"kind": "int", "size": r.get("size_bytes")}
                elif k == "typedef":
                    pg = {"kind": "named", "size": r.get("size_bytes"), "name": r.get("name")}
                else:
                    pg = {"kind": "abstain", "size": None}
            G.add(category(tg), pg, tg, f"{g['name']} @{g['addr']} {g['type']['c']} ({h[:8]})")

    print(f"binaries scored: {binaries}   unique functions: {funcs_total}   "
          f"Ghidra recognised as functions with a signature: {recognised} ({pct(recognised, funcs_total)})")
    if import_secs:
        print(f"Ghidra import+analysis: median {sorted(import_secs)[len(import_secs)//2]}s per binary")
    print(f"arity (param count) exact: {pct(arity['ok'], arity['checked'])}   "
          f"too many {pct(arity['over'], arity['checked'])}   too few {pct(arity['under'], arity['checked'])}")
    for name, T in (("PARAMETERS", P), ("RETURN VALUES", R), ("GLOBALS", G)):
        c = T.c
        tot = c["total"]
        print(f"\n== {name}: {tot}")
        print(f"  not recognised (no function) {pct(c['not_recognised'], tot)}   "
              f"abstain (undefined/unavailable) {pct(c['abstain'], tot)}   answered {pct(c['answered'], tot)}")
        a = c["answered"]
        print(f"  of answered:  kind right {pct(c['kind_ok'], a)}   pointer-vs-scalar right {pct(c['ptr_vs_scalar_ok'], a)}   "
              f"size right {pct(c['size_ok'], c['size_checked'])}   fully exact {pct(c['exact'], a)}")
        if c["sign_checked"]:
            print(f"  signedness right (ints): {pct(c['sign_ok'], c['sign_checked'])} of {c['sign_checked']}")
        if c["pointee_checked"]:
            print(f"  pointee right (pointers): {pct(c['pointee_ok'], c['pointee_checked'])} of {c['pointee_checked']}"
                  f"   (said 'void*/unknown*' for {pct(c['pointee_void'], c['pointee_checked'])})")
        print(f"  confidently WRONG kind: {pct(c['answered'] - c['kind_ok'], tot)} of all")
        cats = sorted({k.split(':', 1)[1] for k in c if k.startswith('total:')},
                      key=lambda k: -c[f'total:{k}'])
        print("  by true category:   (n | answered | kind right of answered)")
        for k in cats[:12]:
            n = c[f"total:{k}"]
            print(f"    {k:14} {n:6} | {pct(c[f'answered:{k}'], n)} | {pct(c[f'kind_ok:{k}'], c[f'answered:{k}'])}")
        print("  top mistakes: " + ", ".join(f"{k} {v}" for k, v in T.wrong.most_common(8)))
        if n_ex:
            for k, _ in T.wrong.most_common(4):
                for e in T.examples[k][:n_ex]:
                    print(f"      e.g. [{k}] {e}")


if __name__ == "__main__":
    main(sys.argv)
