"""ORACLE hint files from DWARF, for --type-hints ceilings only.

Writes one hint file per binary (scripts/tracer/hints.py format) with a single
candidate per argument: the DECLARED type. A run with these hints measures the
most --type-hints can buy with perfect types. It is a ceiling, never a result:
DWARF must not feed the tracer in any reported measurement.

Arguments are numbered as the tracer numbers them: integer-class parameters in
order (float/double parameters travel in xmm registers and are skipped).

    --structs        also give every struct a full LAYOUT (pointees of
                     arguments/returns, and a "globals" section for struct
                     globals, arrays of structs and pointers to structs)
    --observed-only  mark the file so the tracer keeps only the hinted fields
                     the run itself accessed (the FieldDecoder-like ceiling)
    --no-globals     leave out the "globals" section (layouts reach the tracer
                     only through arguments and returns, as a model that types
                     parameters, like ReSym's, would provide)

Usage:
    python3 scripts/rea_eval/hints_from_dwarf.py TRUTH.jsonl OUT_DIR
    python3 scripts/rea_eval/hints_from_dwarf.py --structs [--observed-only] BIN_DIR OUT_DIR
TRUTH.jsonl: scripts/rea_eval/ground_truth.py output.
"""
import json
import os
import sys

from elftools.elf.elffile import ELFFile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ground_truth import _attr, _array_count, _location_addr, _name, _ref, _strip  # noqa: E402

MAX_DEPTH = 3


def hint_type(t):
    """ground_truth.py type dict -> hints.py TYPE, or None."""
    k = t.get("kind")
    if k == "pointer":
        p = t.get("pointee") or {}
        pk = p.get("kind")
        if pk == "int" and p.get("char") and p.get("signed") is not False:
            pe = {"kind": "char", "size": 1}
        elif pk in ("int", "enum", "bool"):
            pe = {"kind": "int", "size": p.get("size"), "signed": p.get("signed")}
        elif pk == "float":
            pe = {"kind": "float", "size": p.get("size")}
        elif pk == "pointer":
            pe = {"kind": "pointer", "size": 8}
        elif pk in ("struct", "union"):
            pe = {"kind": "struct", "size": p.get("size")}
        else:
            pe = {"kind": "void"}
        return {"kind": "pointer", "pointee": pe}
    if k in ("int", "enum", "bool"):
        return {"kind": "int", "size": t.get("size"), "signed": t.get("signed")}
    return None


# ------------------------------------------------------------ struct layouts
def _base(die):
    """('int', size, signed, is_char) / ('float', size) / None for a base type."""
    enc = _attr(die, "DW_AT_encoding")
    size = _attr(die, "DW_AT_byte_size")
    if enc == 4:
        return ("float", size)
    if enc in (2, 5, 6, 7, 8):
        return ("int", size, enc in (5, 6), enc == 6)   # is_char: plain (signed) char only
    return None


def leaf(die, off, depth):
    """Hint leaves (flattened) for one member type at offset `off`."""
    d = _strip(die)
    if d is None:
        return []
    t = d.tag
    if t == "DW_TAG_base_type":
        b = _base(d)
        if b is None:
            return []
        if b[0] == "float":
            return [{"off": off, "size": b[1], "kind": "float"}]
        return [{"off": off, "size": b[1], "kind": "int", "signed": b[2]}]
    if t == "DW_TAG_enumeration_type":
        return [{"off": off, "size": _attr(d, "DW_AT_byte_size"), "kind": "int", "signed": False}]
    if t == "DW_TAG_pointer_type":
        return [{"off": off, "size": 8, "kind": "pointer", "pointee": pointee(_ref(d), depth)}]
    if t == "DW_TAG_structure_type":
        out = []
        for f in members(d, depth):
            f = dict(f, off=f["off"] + off)
            out.append(f)
        return out
    if t == "DW_TAG_array_type":
        n = _array_count(d)
        e = _strip(_ref(d))
        if not n or e is None:
            return []
        if e.tag == "DW_TAG_base_type":
            b = _base(e)
            if b is None:
                return []
            if b[0] == "int" and b[1] == 1 and b[3]:
                return [{"off": off, "size": n, "kind": "chararray"}]
            elem = ({"kind": "float", "size": b[1]} if b[0] == "float"
                    else {"kind": "int", "size": b[1], "signed": b[2]})
            return [{"off": off, "size": n * b[1], "kind": "array", "count": n, "elem": elem}]
        if e.tag == "DW_TAG_pointer_type":
            return [{"off": off, "size": n * 8, "kind": "array", "count": n,
                     "elem": {"kind": "pointer", "size": 8}}]
        return []          # array of structs/unions inside a struct: abstain
    return []              # union, function, other: abstain


def members(sdie, depth):
    out = []
    if _attr(sdie, "DW_AT_declaration"):
        return out
    for m in sdie.iter_children():
        if m.tag != "DW_TAG_member" or "DW_AT_type" not in m.attributes:
            continue
        if "DW_AT_bit_size" in m.attributes:
            continue                         # bit-fields: abstain
        off = _attr(m, "DW_AT_data_member_location", 0)
        if not isinstance(off, int):
            continue
        out += leaf(_ref(m), off, depth)
    return out


def pointee(die, depth):
    """hints.py pointee for a pointer's target; structs get a layout."""
    d = _strip(die)
    if d is None:
        return {"kind": "void"}
    t = d.tag
    if t == "DW_TAG_base_type":
        b = _base(d)
        if b is None:
            return {"kind": "void"}
        if b[0] == "float":
            return {"kind": "float", "size": b[1]}
        if b[1] == 1 and b[3]:
            return {"kind": "char", "size": 1}
        return {"kind": "int", "size": b[1], "signed": b[2]}
    if t == "DW_TAG_enumeration_type":
        return {"kind": "int", "size": _attr(d, "DW_AT_byte_size"), "signed": False}
    if t == "DW_TAG_pointer_type":
        return {"kind": "pointer", "size": 8}
    if t == "DW_TAG_structure_type":
        p = {"kind": "struct", "size": _attr(d, "DW_AT_byte_size")}
        if depth < MAX_DEPTH and not _attr(d, "DW_AT_declaration"):
            p["fields"] = members(d, depth + 1)
        return p
    return {"kind": "void"}


def global_type(die):
    """hints.py TYPE for a global's own storage, or None."""
    d = _strip(die)
    if d is None:
        return None
    if d.tag == "DW_TAG_structure_type":
        return {"kind": "struct", "size": _attr(d, "DW_AT_byte_size"),
                "fields": members(d, 1)}
    if d.tag == "DW_TAG_array_type":
        e = _strip(_ref(d))
        n = _array_count(d)
        if e is not None and e.tag == "DW_TAG_structure_type" and n:
            return {"kind": "array", "count": n,
                    "elem": {"kind": "struct", "size": _attr(e, "DW_AT_byte_size"),
                             "fields": members(e, 1)}}
        return None
    if d.tag == "DW_TAG_pointer_type":
        p = pointee(_ref(d), 0)
        if p.get("kind") == "struct" and p.get("fields"):
            return {"kind": "pointer", "pointee": p}
    return None


def param_type(die):
    """hints.py TYPE for an integer-class parameter or return, with layouts."""
    d = _strip(die)
    if d is None:
        return None
    if d.tag == "DW_TAG_pointer_type":
        return {"kind": "pointer", "pointee": pointee(_ref(d), 0)}
    if d.tag == "DW_TAG_base_type":
        b = _base(d)
        if b and b[0] == "int":
            return {"kind": "int", "size": b[1], "signed": b[2]}
    if d.tag == "DW_TAG_enumeration_type":
        return {"kind": "int", "size": _attr(d, "DW_AT_byte_size"), "signed": False}
    return None


def _is_float(die):
    d = _strip(die)
    return d is not None and d.tag == "DW_TAG_base_type" and _attr(d, "DW_AT_encoding") == 4


def struct_hints(path):
    funcs, globs = {}, {}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    low = _attr(die, "DW_AT_low_pc")
                    if not isinstance(low, int) or hex(low) in funcs:
                        continue
                    args, i = {}, 0
                    for ch in die.iter_children():
                        if ch.tag != "DW_TAG_formal_parameter" or "DW_AT_type" not in ch.attributes:
                            continue
                        if _is_float(_ref(ch)):
                            continue
                        h = param_type(_ref(ch))
                        if h:
                            args[str(i)] = [h]
                        i += 1
                    spec = {"args": args}
                    if "DW_AT_type" in die.attributes:
                        r = param_type(_ref(die))
                        if r:
                            spec["return"] = [r]
                    funcs[hex(low)] = spec
                elif die.tag == "DW_TAG_variable":
                    addr = _location_addr(die)
                    if addr is None or hex(addr) in globs:
                        continue
                    named = die
                    if "DW_AT_specification" in die.attributes:
                        named = die.get_DIE_from_attribute("DW_AT_specification")
                    if "DW_AT_type" not in named.attributes:
                        continue
                    g = global_type(_ref(named))
                    if g:
                        globs[hex(addr)] = [g]
    return funcs, globs


def main(argv):
    structs = "--structs" in argv
    observed = "--observed-only" in argv
    no_globals = "--no-globals" in argv
    args = [a for a in argv[1:] if not a.startswith("--")]
    src, out_dir = args[:2]
    os.makedirs(out_dir, exist_ok=True)
    if structs:
        for f in sorted(os.listdir(src)):
            if not f.endswith(".exe") or f.endswith("_stripped.exe"):
                continue
            funcs, globs = struct_hints(os.path.join(src, f))
            if no_globals:
                globs = {}
            doc = {"source": "DWARF layouts (ORACLE ceiling only)", "functions": funcs,
                   "globals": globs}
            if observed:
                doc["observed_fields_only"] = True
            with open(os.path.join(out_dir, f[:-4] + ".hints.json"), "w") as fh:
                json.dump(doc, fh, indent=1, sort_keys=True)
        return 0
    for line in open(src):
        t = json.loads(line)
        funcs = {}
        for f in t["functions"]:
            ints = [p for p in f["params"] if p["type"].get("kind") != "float"]
            fargs = {}
            for i, p in enumerate(ints):
                h = hint_type(p["type"])
                if h:
                    fargs[str(i)] = [h]
            spec = {"args": fargs}
            r = f.get("return")
            if r and hint_type(r):
                spec["return"] = [hint_type(r)]
            funcs[f["addr"]] = spec
        name = os.path.basename(t["binary"])
        name = name[:-4] if name.endswith(".exe") else name
        with open(os.path.join(out_dir, name + ".hints.json"), "w") as fh:
            json.dump({"source": "DWARF (ORACLE ceiling only)", "functions": funcs},
                      fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
