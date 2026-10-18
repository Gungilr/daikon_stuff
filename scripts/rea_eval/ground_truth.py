"""Ground-truth types from DWARF, for scoring type recovery on stripped binaries.

For every function with code (DW_AT_low_pc) and every global with a fixed
address, record the declared type of each parameter, the return value and the
global itself.  Records are keyed by ADDRESS, because a stripped copy of the
same binary keeps every address and loses only the names.

This module is the ONLY place debug information is read.  Whatever is being
scored (REA, the tracer, a model) must see the stripped binary alone.

Usage:
    python3 scripts/rea_eval/ground_truth.py OUT.jsonl BIN [BIN ...]
"""
import json
import sys

from elftools.elf.elffile import ELFFile

QUALIFIERS = ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
              "DW_TAG_restrict_type", "DW_TAG_atomic_type")
MAX_DEPTH = 8


def _attr(die, name, default=None):
    a = die.attributes.get(name)
    return a.value if a is not None else default


def _name(die):
    n = _attr(die, "DW_AT_name")
    return n.decode(errors="replace") if isinstance(n, bytes) else n


def _ref(die):
    if "DW_AT_type" not in die.attributes:
        return None
    return die.get_DIE_from_attribute("DW_AT_type")


def _strip(die):
    """Follow typedefs and qualifiers to the underlying type DIE."""
    for _ in range(32):
        if die is None or die.tag not in QUALIFIERS:
            return die
        die = _ref(die)
    return die


def _c_name(die, depth=0):
    """A readable C spelling, for reports only - scoring uses the fields."""
    if die is None:
        return "void"
    if depth > MAX_DEPTH:
        return "..."
    t = die.tag
    if t in QUALIFIERS:
        n = _name(die) if t == "DW_TAG_typedef" else None
        return n or _c_name(_ref(die), depth + 1)
    if t == "DW_TAG_base_type":
        return _name(die)
    if t == "DW_TAG_pointer_type":
        return _c_name(_ref(die), depth + 1) + " *"
    if t == "DW_TAG_array_type":
        return _c_name(_ref(die), depth + 1) + "[]"
    if t in ("DW_TAG_structure_type", "DW_TAG_union_type",
             "DW_TAG_enumeration_type", "DW_TAG_class_type"):
        kw = {"DW_TAG_structure_type": "struct", "DW_TAG_union_type": "union",
              "DW_TAG_enumeration_type": "enum", "DW_TAG_class_type": "class"}[t]
        return f"{kw} {_name(die) or '<anon>'}"
    if t == "DW_TAG_subroutine_type":
        return "func"
    return t.replace("DW_TAG_", "")


def _array_count(die):
    count = 1
    seen = False
    for sub in die.iter_children():
        if sub.tag != "DW_TAG_subrange_type":
            continue
        if "DW_AT_count" in sub.attributes:
            n = _attr(sub, "DW_AT_count")
        elif "DW_AT_upper_bound" in sub.attributes:
            ub = _attr(sub, "DW_AT_upper_bound")
            n = ub + 1 if isinstance(ub, int) else None
        else:
            n = None
        if not isinstance(n, int):
            return None
        count *= n
        seen = True
    return count if seen else None


def describe(die, depth=0):
    """Type descriptor used for scoring.

    kind: void | int | float | bool | pointer | struct | union | array | enum | func | other
    plus size (bytes), signed (int/enum), and for aggregates their shape.
    """
    raw = die
    die = _strip(die)
    d = {"c": _c_name(raw)}
    if die is None:
        d.update(kind="void", size=0)
        return d
    t = die.tag
    size = _attr(die, "DW_AT_byte_size")
    if t == "DW_TAG_base_type":
        enc = _attr(die, "DW_AT_encoding")
        # DW_ATE: 2 boolean, 4 float, 5 signed, 6 signed_char, 7 unsigned, 8 unsigned_char
        kind = {2: "bool", 4: "float"}.get(enc, "int")
        d.update(kind=kind, size=size)
        if kind == "int":
            d["signed"] = enc in (5, 6)
            d["char"] = enc in (6, 8)
    elif t in ("DW_TAG_pointer_type", "DW_TAG_reference_type",
               "DW_TAG_rvalue_reference_type"):
        d.update(kind="pointer", size=size or 8)
        if depth < 2:
            target = _ref(die)
            d["pointee"] = describe(target, depth + 1) if target is not None \
                else {"kind": "void", "size": 0, "c": "void"}
    elif t in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_class_type"):
        kind = "union" if t == "DW_TAG_union_type" else "struct"
        d.update(kind=kind, size=size)
        if _attr(die, "DW_AT_declaration"):
            d["incomplete"] = True
        elif depth < 2:
            fields = []
            for m in die.iter_children():
                if m.tag != "DW_TAG_member" or "DW_AT_type" not in m.attributes:
                    continue
                off = _attr(m, "DW_AT_data_member_location", 0)
                if not isinstance(off, int):
                    off = None
                fd = describe(_ref(m), depth + 1)
                fields.append({"off": off, "size": fd.get("size"), "kind": fd["kind"],
                               "c": fd["c"]})
            d["fields"] = fields
    elif t == "DW_TAG_array_type":
        elem = describe(_ref(die), depth + 1)
        n = _array_count(die)
        d.update(kind="array", count=n, elem=elem,
                 size=(n * elem["size"]) if (n and elem.get("size")) else size)
    elif t == "DW_TAG_enumeration_type":
        d.update(kind="enum", size=size)
    elif t == "DW_TAG_subroutine_type":
        d.update(kind="func", size=None)
    else:
        d.update(kind="other", size=size)
    return d


def _location_addr(die):
    loc = _attr(die, "DW_AT_location")
    if isinstance(loc, list) and len(loc) == 9 and loc[0] == 0x03:  # DW_OP_addr
        return int.from_bytes(bytes(loc[1:9]), "little")
    return None


def extract(path):
    functions, globals_ = {}, {}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        if not elf.has_dwarf_info():
            return {"functions": [], "globals": []}
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            cu_name = _name(cu.get_top_DIE())
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    low = _attr(die, "DW_AT_low_pc")
                    if not isinstance(low, int) or low in functions:
                        continue
                    params = []
                    for ch in die.iter_children():
                        if ch.tag == "DW_TAG_formal_parameter":
                            params.append({"ordinal": len(params), "name": _name(ch),
                                           "type": describe(_ref(ch))})
                        elif ch.tag == "DW_TAG_unspecified_parameters":
                            params.append({"ordinal": len(params), "name": "...",
                                           "type": {"kind": "varargs", "c": "..."}})
                    functions[low] = {
                        "addr": hex(low), "name": _name(die), "cu": cu_name,
                        "external": bool(_attr(die, "DW_AT_external")),
                        "return": describe(_ref(die)), "params": params,
                    }
                elif die.tag == "DW_TAG_variable":
                    addr = _location_addr(die)
                    if addr is None or addr in globals_:
                        continue
                    # a variable with a fixed address but no name of its own refers
                    # back to its declaration via DW_AT_specification
                    named = die
                    if "DW_AT_specification" in die.attributes:
                        named = die.get_DIE_from_attribute("DW_AT_specification")
                    if "DW_AT_type" not in named.attributes:
                        continue
                    parent = die.get_parent()
                    globals_[addr] = {
                        "addr": hex(addr), "name": _name(named), "cu": cu_name,
                        "static_local": parent is not None and parent.tag != "DW_TAG_compile_unit",
                        "type": describe(_ref(named)),
                    }
    return {"functions": sorted(functions.values(), key=lambda f: int(f["addr"], 16)),
            "globals": sorted(globals_.values(), key=lambda g: int(g["addr"], 16))}


def main(argv):
    out, bins = argv[1], argv[2:]
    with open(out, "w") as fh:
        for b in bins:
            rec = {"binary": b, **extract(b)}
            fh.write(json.dumps(rec) + "\n")
            print(f"{b}: {len(rec['functions'])} functions, {len(rec['globals'])} globals",
                  file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv)
