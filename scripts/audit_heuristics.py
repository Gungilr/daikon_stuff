#!/usr/bin/env python3
"""Grade the tracer's inferences against debug info, rule by rule.

docs/HEURISTICS.md lists every rule the tracer uses to decide what to report,
with a verdict for each. This measures those verdicts on real programs. For one
program it reads:

  the -g build       ground truth from DWARF. Read HERE only, as in
                     score_invariants.py; the tracer never sees it.
  --dump-inferences  what the tracer concluded (tracer --dump-inferences).
  the .dtrace(.gz)   the values it emitted, for checks that need values.

and prints one JSON record of tallies. `--summarize` turns many records into one
table per rule, split by optimisation level.

What the truth for a parameter or return looks like is computed from its DWARF
type with the System V AMD64 classification (INTEGER, SSE, MEMORY, X87): which
registers it should arrive in, and how many stack words it should take. That
is the same contract the tracer tries to infer, so the two can be compared slot
by slot.

Usage:
    audit_heuristics.py --binary prog.exe --dump prog.json \\
                        [--dtrace prog.dtrace.gz] [--label O0] >> results.jsonl
    audit_heuristics.py --summarize results.jsonl
"""
from __future__ import print_function

import argparse
import gzip
import json
import os
import re
import sys

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[!] needs pyelftools", file=sys.stderr)
    sys.exit(1)

# --- type descriptions --------------------------------------------------------

INT, FLOAT, X87, POINTER, STRUCT, ARRAY, FUNC, OTHER = (
    "int", "float", "x87", "pointer", "struct", "array", "function", "other")

DW_ATE_BOOLEAN, DW_ATE_COMPLEX_FLOAT, DW_ATE_FLOAT = 0x02, 0x03, 0x04
DW_ATE_UNSIGNED = {0x02, 0x07, 0x08, 0x10}     # boolean, unsigned, uchar, UTF
_QUALIFIERS = {"DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
               "DW_TAG_restrict_type", "DW_TAG_atomic_type"}
_POINTERS = {"DW_TAG_pointer_type", "DW_TAG_reference_type",
             "DW_TAG_rvalue_reference_type", "DW_TAG_ptr_to_member_type"}


def _ref(die, attr="DW_AT_type"):
    try:
        return die.get_DIE_from_attribute(attr)
    except Exception:
        return None


def _attr(die, name):
    """An attribute, following abstract_origin/specification when missing.

    Out-of-line copies of inlined functions, and definitions of things declared
    elsewhere, keep their name and type on the DIE they point to.
    """
    seen = set()
    while die is not None and die.offset not in seen:
        seen.add(die.offset)
        if name in die.attributes:
            return die.attributes[name], die
        die = (_ref(die, "DW_AT_abstract_origin")
               or _ref(die, "DW_AT_specification"))
    return None, None


def _uleb(data):
    value = shift = 0
    for b in data:
        value |= (b & 0x7f) << shift
        if not b & 0x80:
            break
        shift += 7
    return value


def _member_offset(die):
    loc = die.attributes.get("DW_AT_data_member_location")
    if loc is None:
        return 0
    if isinstance(loc.value, int):
        return loc.value
    if isinstance(loc.value, list) and loc.value and loc.value[0] == 0x23:
        return _uleb(loc.value[1:])            # DW_OP_plus_uconst, DWARF 2/3
    return 0


def type_of(die, depth=0):
    """A small dict describing a DWARF type; None is void."""
    seen = set()
    while die is not None and die.tag in _QUALIFIERS and die.offset not in seen:
        seen.add(die.offset)
        die = _ref(die)
    if die is None:
        return None
    size_attr = die.attributes.get("DW_AT_byte_size")
    size = size_attr.value if size_attr is not None and isinstance(
        size_attr.value, int) else 0
    tag = die.tag
    if tag == "DW_TAG_base_type":
        enc = die.attributes["DW_AT_encoding"].value
        if enc == DW_ATE_FLOAT:
            return {"k": X87 if size > 8 else FLOAT, "size": size}
        if enc == DW_ATE_COMPLEX_FLOAT:
            half = size // 2
            leaf = {"k": X87 if half > 8 else FLOAT, "size": half}
            return {"k": STRUCT, "size": size,
                    "members": [(0, leaf), (half, leaf)]}
        return {"k": INT, "size": size, "signed": enc not in DW_ATE_UNSIGNED,
                "bool": enc == DW_ATE_BOOLEAN}
    if tag == "DW_TAG_enumeration_type":
        under = type_of(_ref(die), depth + 1) if "DW_AT_type" in die.attributes else None
        signed = under.get("signed") if under and under["k"] == INT else None
        return {"k": INT, "size": size or 4, "signed": signed, "bool": False}
    if tag in _POINTERS:
        return {"k": POINTER, "size": size or 8}
    if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
        members = []
        if depth < 8:
            for m in die.iter_children():
                if m.tag == "DW_TAG_member":
                    md = type_of(_ref(m), depth + 1)
                    if md is not None:
                        members.append((_member_offset(m), md))
        return {"k": STRUCT, "size": size, "members": members,
                "union": tag == "DW_TAG_union_type"}
    if tag == "DW_TAG_array_type":
        elem = type_of(_ref(die), depth + 1)
        count = 1
        for sub in die.iter_children():
            if sub.tag != "DW_TAG_subrange_type":
                continue
            if "DW_AT_count" in sub.attributes and isinstance(
                    sub.attributes["DW_AT_count"].value, int):
                count *= sub.attributes["DW_AT_count"].value
            elif "DW_AT_upper_bound" in sub.attributes and isinstance(
                    sub.attributes["DW_AT_upper_bound"].value, int):
                count *= sub.attributes["DW_AT_upper_bound"].value + 1
            else:
                count = 0
        esize = elem["size"] if elem else 0
        return {"k": ARRAY, "size": size or count * esize, "elem": elem,
                "count": count}
    if tag == "DW_TAG_subroutine_type":
        return {"k": FUNC, "size": 0}
    if tag == "DW_TAG_unspecified_type":
        return {"k": POINTER, "size": 8}
    return {"k": OTHER, "size": size}


# --- System V AMD64 classification -------------------------------------------

def _leaves(desc, base=0, depth=0):
    """(offset, scalar description) for every scalar inside an aggregate."""
    if desc is None or depth > 16:
        return
    if desc["k"] == STRUCT:
        for off, m in desc["members"]:
            yield from _leaves(m, base + off, depth + 1)
    elif desc["k"] == ARRAY:
        elem = desc.get("elem")
        if elem and elem["size"]:
            for i in range(min(desc.get("count", 0), 64)):
                yield from _leaves(elem, base + i * elem["size"], depth + 1)
    else:
        yield base, desc


def eightbytes(desc):
    """'MEMORY', 'X87', or a list of 'INTEGER'/'SSE', one per eightbyte."""
    k = desc["k"]
    if k in (INT, POINTER):
        return ["INTEGER"] * max(1, (desc["size"] + 7) // 8)
    if k == FLOAT:
        return ["SSE"]
    if k == X87:
        return "X87"
    if k in (STRUCT, ARRAY):
        size = desc["size"]
        if size == 0 or size > 16:
            return "MEMORY"
        classes = [None] * ((size + 7) // 8)
        for off, leaf in _leaves(desc):
            if leaf["k"] == X87:
                return "MEMORY"
            cls = "SSE" if leaf["k"] == FLOAT else "INTEGER"
            first = off // 8
            last = min((off + max(leaf["size"], 1) - 1) // 8, len(classes) - 1)
            for i in range(first, last + 1):
                classes[i] = ("INTEGER" if "INTEGER" in (classes[i], cls)
                              else "SSE")
        return [c or "SSE" for c in classes]
    return "MEMORY"


def assign_params(params):
    """Where SysV puts each parameter: registers, stack words, and which
    parameter each integer and SSE register carries (None for a piece of an
    aggregate, whose width and pointer-ness are not one type)."""
    gpr, sse, stack = [], [], 0
    aggregate_in_regs = aggregate_on_stack = False
    for i, d in enumerate(params):
        if d is None:
            continue
        cls = eightbytes(d)
        if cls in ("MEMORY", "X87"):
            stack += max(1, (d["size"] + 7) // 8)
            aggregate_on_stack |= d["k"] in (STRUCT, ARRAY)
            continue
        need_g, need_s = cls.count("INTEGER"), cls.count("SSE")
        if len(gpr) + need_g > 6 or len(sse) + need_s > 8:
            stack += len(cls)
            continue
        single = len(cls) == 1 and d["k"] not in (STRUCT, ARRAY)
        aggregate_in_regs |= d["k"] in (STRUCT, ARRAY)
        for c in cls:
            (gpr if c == "INTEGER" else sse).append((i, d if single else None))
    return {"gpr": gpr, "sse": sse, "stack_words": stack,
            "aggregate_in_regs": aggregate_in_regs,
            "aggregate_on_stack": aggregate_on_stack}


def return_class(desc):
    """'void', 'int', 'pointer', 'float', 'x87', 'memory', 'int128', or
    'aggregate:<classes>' for a small struct returned in registers."""
    if desc is None:
        return "void"
    cls = eightbytes(desc)
    if cls == "X87":
        return "x87"
    if cls == "MEMORY":
        return "memory"
    if desc["k"] in (STRUCT, ARRAY):
        return "aggregate:" + "+".join(cls)
    if cls == ["SSE"]:
        return "float"
    if desc["k"] == POINTER:
        return "pointer"
    return "int128" if len(cls) == 2 else "int"


# --- ground truth from the binary ---------------------------------------------

def _name(die):
    a, _ = _attr(die, "DW_AT_name")
    return a.value.decode(errors="replace") if a is not None else None


def dwarf_functions(elf):
    """{low_pc: {name, params, variadic, ret}} for every out-of-line function."""
    out = {}
    if not elf.has_dwarf_info():
        return out
    for cu in elf.get_dwarf_info().iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_subprogram":
                continue
            low = die.attributes.get("DW_AT_low_pc")
            if low is None:
                continue
            kids = [c for c in die.iter_children()]
            params = [c for c in kids if c.tag == "DW_TAG_formal_parameter"]
            variadic = any(c.tag == "DW_TAG_unspecified_parameters" for c in kids)
            origin = _ref(die, "DW_AT_abstract_origin")
            if not params and origin is not None:
                okids = list(origin.iter_children())
                params = [c for c in okids if c.tag == "DW_TAG_formal_parameter"]
                variadic = variadic or any(
                    c.tag == "DW_TAG_unspecified_parameters" for c in okids)
            types = []
            for p in params:
                t_attr, owner = _attr(p, "DW_AT_type")
                types.append(type_of(_ref(owner)) if t_attr is not None else None)
            r_attr, r_owner = _attr(die, "DW_AT_type")
            ret = type_of(_ref(r_owner)) if r_attr is not None else None
            out[low.value] = {"name": _name(die), "params": types,
                              "variadic": variadic, "ret": ret}
    return out


def dwarf_globals(elf):
    """{address: {name, size, shape}} for every statically allocated variable."""
    out = {}
    if not elf.has_dwarf_info():
        return out
    for cu in elf.get_dwarf_info().iter_CUs():
        for die in cu.iter_DIEs():
            if die.tag != "DW_TAG_variable":
                continue
            loc = die.attributes.get("DW_AT_location")
            if loc is None or not isinstance(loc.value, list) or not loc.value:
                continue
            if loc.value[0] != 0x03 or len(loc.value) < 9:     # DW_OP_addr
                continue
            addr = int.from_bytes(bytes(loc.value[1:9]), "little")
            t_attr, owner = _attr(die, "DW_AT_type")
            desc = type_of(_ref(owner)) if t_attr is not None else None
            if desc is None or not desc["size"]:
                continue
            out[addr] = {"name": _name(die), "size": desc["size"],
                         "shape": global_shape(desc)}
    return out


def global_shape(desc):
    if desc["k"] == ARRAY:
        elem = desc.get("elem") or {}
        return ("array-of-struct" if elem.get("k") in (STRUCT, ARRAY)
                else "array")
    return "struct" if desc["k"] == STRUCT else "scalar"


def symtab_functions(elf):
    """{address: name} of every FUNC symbol with code, the truth for discovery."""
    out = {}
    st = elf.get_section_by_name(".symtab")
    if st is None:
        return out
    for s in st.iter_symbols():
        if (s["st_info"]["type"] == "STT_FUNC" and s["st_value"]
                and s["st_shndx"] != "SHN_UNDEF"):
            out[s["st_value"]] = s.name
    return out


# --- the tracer's own values ----------------------------------------------------

def read_dtrace(path):
    """{ppt: [ {var: int} ]} for scalar values only; arrays and junk dropped."""
    if not path or not os.path.exists(path):
        return {}
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as f:
        lines = f.read().replace("\r", "").split("\n")
    out, i, n = {}, 0, len(lines)
    in_decls = False
    while i < n:
        line = lines[i]
        if line.startswith("ppt "):
            in_decls = True
        elif line == "":
            in_decls = False
        elif not in_decls and ":::" in line and not line.startswith(" "):
            ppt, sample = line, {}
            i += 1
            if i < n and lines[i] == "this_invocation_nonce":
                i += 2
            while i + 1 < n and lines[i] != "":
                var, val = lines[i], lines[i + 1]
                try:
                    sample[var] = int(val)
                except ValueError:
                    pass
                i += 3 if (i + 2 < n and lines[i + 2] in ("0", "1", "2")) else 2
            out.setdefault(ppt, []).append(sample)
            continue
        i += 1
    return out


# --- grading ---------------------------------------------------------------------

STATE_CHANGING = {
    "memcpy", "memmove", "memset", "bzero", "strcpy", "strncpy", "strcat",
    "strncat", "strdup", "strndup", "sprintf", "snprintf", "vsprintf",
    "sscanf", "scanf", "fscanf", "fgets", "gets", "fgetc", "getc", "getchar",
    "fread", "read", "fopen", "open", "close", "fclose", "fseek", "ftell",
    "rewind", "ungetc", "strtol", "strtoul", "strtod", "atof", "strtok",
    "qsort", "bsearch", "rand", "srand", "random", "srandom", "time",
    "clock", "gettimeofday", "getenv", "toupper", "tolower", "strlen",
    "strcmp", "strncmp", "memcmp", "strchr", "strrchr", "strstr",
    "isalpha", "isdigit", "isspace", "isupper", "islower", "isalnum",
    "__ctype_b_loc", "__ctype_toupper_loc", "__ctype_tolower_loc",
    "sqrt", "sin", "cos", "tan", "exp", "log", "pow", "fabs", "floor",
    "ceil", "atan", "atan2", "fmod", "log10", "sinh", "cosh", "tanh", "asin",
    "acos", "setjmp", "_setjmp", "longjmp", "signal", "pthread_create",
}
OUTPUT_ONLY = {"printf", "puts", "putchar", "fprintf", "fputs", "fputc",
               "putc", "fwrite", "fflush", "write", "perror", "vprintf",
               "vfprintf", "__printf_chk", "__fprintf_chk", "__sprintf_chk"}
CLONE = re.compile(r"\.(isra|constprop|part|cold|lto_priv)\b")


def _bump(tally, key, n=1):
    tally[key] = tally.get(key, 0) + n


def _example(examples, rule, text, limit=6):
    lst = examples.setdefault(rule, [])
    if len(lst) < limit:
        lst.append(text)


def _matrix(tally, truth, guess):
    _bump(tally, ("tp" if guess else "fn") if truth else ("fp" if guess else "tn"))


def grade(binary, dump, dtrace_path=None, label=None, discovery=True,
          globals_dump=None):
    """One graded record. `globals_dump`, when given, supplies the globals
    checks: audit_corpus.py traces functions with --ignore-globals, whose
    per-sample snapshots are what make long runs expensive, and globals in a
    second, shorter run."""
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        truth = dwarf_functions(elf)
        gtruth = dwarf_globals(elf)
        symfuncs = symtab_functions(elf)

    rules, ex = {}, {}
    rule = lambda name: rules.setdefault(name, {})   # noqa: E731
    values = read_dtrace(dtrace_path)
    funcs = dump["functions"]
    by_addr = {f["addr"]: f for f in funcs}

    cov = rule("coverage")
    cov["functions_known"] = len(funcs)
    cov["functions_executed"] = sum(1 for f in funcs if f.get("enters"))
    cov["with_dwarf"] = sum(1 for f in funcs if f["addr"] in truth)

    for f in funcs:
        t = truth.get(f["addr"])
        if t is None or not f.get("enters") or "n_reg" not in f:
            continue
        where = f"{os.path.basename(binary)}:{f['name']}"
        clone = bool(CLONE.search(f["name"]))
        a = assign_params(t["params"])

        # H5, H7, H8: integer-register and stack arity
        tally = rule("H5-H8 arity")
        if clone:
            _bump(tally, "skipped_compiler_clone")
        elif t["variadic"]:
            _bump(tally, "skipped_variadic")
        else:
            want = (len(a["gpr"]), a["stack_words"])
            got = (f["n_reg"], f["n_stack"])
            kind = "exact" if got == want else ("under" if got < want else "over")
            _bump(tally, kind)
            if a["aggregate_on_stack"] or a["aggregate_in_regs"]:
                _bump(tally, f"struct_by_value_{kind}")
            if kind != "exact":
                _example(ex, "H5-H8 arity", f"{where} want {want} got {got}")

        # H11: SSE arity
        tally = rule("H11 sse arity")
        if not (clone or t["variadic"]):
            want, got = len(a["sse"]), f.get("sse_arity", 0)
            kind = "exact" if got == want else ("under" if got < want else "over")
            _bump(tally, kind)
            if kind != "exact":
                _example(ex, "H11 sse arity", f"{where} want {want} got {got}")

        # H9 width, H17 pointer verdict, H10 unsigned values: per integer register
        widths, kinds = f.get("arg_width", {}), f.get("slot_kinds", [])
        enter = values.get(f"..{f['name']}():::ENTER", [])
        for idx, (pi, d) in enumerate(a["gpr"]):
            if clone or d is None or idx >= f["n_reg"]:
                continue
            w = widths.get(str(idx))
            if w is not None and d["size"]:
                want = d["size"] * 8
                _bump(rule("H9 arg width"),
                      "exact" if w == want else ("wider" if w > want else "narrower"))
                if w < want:
                    _example(ex, "H9 arg width", f"{where} arg{idx} want {want} got {w}")
            if idx < len(kinds) and kinds[idx] in ("pointer", "scalar"):
                _matrix(rule("H17 pointer"), d["k"] == POINTER,
                        kinds[idx] == "pointer")
                if (d["k"] == POINTER) != (kinds[idx] == "pointer"):
                    _example(ex, "H17 pointer",
                             f"{where} arg{idx} is {d['k']} called {kinds[idx]}")
            if (d["k"] == INT and d.get("signed") is False and d["size"] >= 4
                    and not d.get("bool")):
                seen = [s[f"arg{idx}"] for s in enter if f"arg{idx}" in s]
                if seen:
                    neg = any(v < 0 for v in seen)
                    _bump(rule("H10 unsigned args"),
                          "shown_negative" if neg else "never_negative")
                    if neg:
                        _example(ex, "H10 unsigned args", f"{where} arg{idx}")

        # Returns: H13, H14, H15, H16, width, pointer
        rc = return_class(t["ret"])
        if rc.startswith("aggregate") or rc in ("memory", "int128", "x87"):
            _bump(rule("H13 unrepresented returns"), rc.split(":")[0])
            _example(ex, "H13 unrepresented returns", f"{where} {rc}")
        if f.get("exits") and f.get("return_emitted") is not None:
            if f.get("caller_checks"):
                _matrix(rule("H14 void"), rc != "void", bool(f["return_emitted"]))
                if (rc != "void") != bool(f["return_emitted"]):
                    _example(ex, "H14 void", f"{where} truth {rc}")
            else:
                _bump(rule("H14 void"), "no_caller_observed")
            if rc in ("int", "pointer", "float") and f["return_emitted"]:
                kind = f.get("return_kind")
                _matrix(rule("H16 float return"), rc == "float", kind == "float")
                if (rc == "float") != (kind == "float"):
                    _example(ex, "H16 float return", f"{where} truth {rc} got {kind}")
                if kind in ("pointer", "scalar") and rc in ("int", "pointer"):
                    _matrix(rule("pointer return"), rc == "pointer", kind == "pointer")
                if rc == "int" and f.get("ret_width"):
                    want = t["ret"]["size"] * 8
                    w = f["ret_width"]
                    _bump(rule("return width"),
                          "exact" if w == want else ("wider" if w > want else "narrower"))
                if (rc == "int" and t["ret"].get("signed") is not None
                        and t["ret"]["size"] >= 4 and not t["ret"].get("bool")):
                    unsigned = t["ret"].get("signed") is False
                    _matrix(rule("H15 unsigned return"), unsigned,
                            bool(f.get("ret_unsigned")))
                    if unsigned != bool(f.get("ret_unsigned")):
                        _example(ex, "H15 unsigned return",
                                 f"{where} unsigned={unsigned}")
                    exits = values.get(f"..{f['name']}():::EXIT0", [])
                    rets = [s["return"] for s in exits if "return" in s]
                    if unsigned and t["ret"]["size"] >= 4 and rets:
                        _bump(rule("H15 unsigned return values"),
                              "shown_negative" if any(v < 0 for v in rets)
                              else "never_negative")

        # H3: pairing, judged only when the run ended on its own
        if not dump.get("hit_insn_limit"):
            unpaired = f.get("enters", 0) - f.get("exits", 0)
            if unpaired > 0:
                _bump(rule("H3 pairing"), "unpaired_enters", unpaired)

    _bump(rule("H3 pairing"), "ret_mismatches", dump.get("ret_mismatches", 0))

    # H30, H32: globals
    gsrc = globals_dump if globals_dump is not None else dump
    objs = {g["addr"]: g for g in gsrc.get("globals", [])}
    spans = sorted((g["addr"], g["addr"] + g["size"], g) for g in objs.values())
    for addr, gt in sorted(gtruth.items()):
        o = objs.get(addr)
        ext = rule("H30 global extent")
        if o is None:
            covering = [g for lo, hi, g in spans if lo <= addr < hi]
            _bump(ext, "merged" if covering else "absent")
            continue
        _bump(ext, "exact" if o["size"] == gt["size"] else "wrong_size")
        _bump(rule("H32 global shape"), f"{gt['shape']}->{o['shape']}")
        if gt["shape"] != o["shape"]:
            _example(ex, "H32 global shape",
                     f"{os.path.basename(binary)}:{gt['name']} "
                     f"{gt['shape']} -> {o['shape']}")

    # H37, H38: calls
    calls = rule("H37 skipped calls")
    for label_, n in dump.get("skipped_by_target", {}).items():
        name = label_.split(":", 1)[1] if label_.startswith("indirect:") else label_
        if label_ == "indirect":
            continue
        cat = ("state_changing" if name in STATE_CHANGING
               else "output_only" if name in OUTPUT_ONLY else "other")
        _bump(calls, cat, n)
        _bump(calls, f"name:{name}", n)
    ind = rule("H38 indirect calls")
    for c in dump.get("indirect_calls", []):
        if c["is_function"]:
            cat = "into_program"
            callee = by_addr.get(c["target"], {}).get("name", hex(c["target"]))
            _example(ex, "H38 indirect calls",
                     f"{os.path.basename(binary)} -> {callee} x{c['count']}")
        elif c["target"] is None:
            cat = "unresolved"
        else:
            cat = "library_or_other"
        _bump(ind, cat, c["count"])

    if discovery:
        _grade_discovery(binary, symfuncs, rules, ex)

    return {"program": os.path.basename(binary), "label": label,
            "binary": binary,
            "run": {k: dump.get(k) for k in ("instructions", "hit_insn_limit",
                                              "samples", "skipped_calls",
                                              "ret_mismatches")},
            "rules": rules, "examples": ex}


def _grade_discovery(binary, symfuncs, rules, ex):
    """H1 prologue scanning and H2 main recovery, as a stripped binary sees it."""
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    try:
        from tracer.elfload import find_functions
        from tracer.emulate import discover_main_via_emulation
        from tracer.log import Logger
    except Exception as e:                           # pragma: no cover
        rules["H1 discovery"] = {"error": str(e)[:80]}
        return
    log = Logger(quiet=True)
    try:
        found, is64, entry, segs = find_functions(binary, set(), log,
                                                  force_prologue_scan=True)
    except Exception as e:
        rules["H1 discovery"] = {"error": str(e)[:80]}
        return
    found = set(found)
    real = set(symfuncs)
    tally = rules.setdefault("H1 discovery", {})
    _bump(tally, "real_functions", len(real))
    _bump(tally, "found", len(found & real))
    _bump(tally, "missed", len(real - found))
    _bump(tally, "false_starts", len(found - real))
    for a in sorted(real - found)[:4]:
        _example(ex, "H1 discovery", f"{os.path.basename(binary)} missed {symfuncs[a]}")
    main = [a for a, n in symfuncs.items() if n == "main"]
    if main:
        try:
            got = discover_main_via_emulation(segs, is64, entry, 0x7fff00000000,
                                              0x100000, log)
        except Exception:
            got = None
        rules.setdefault("H2 main", {})
        _bump(rules["H2 main"], "right" if got == main[0]
              else "not_found" if got is None else "wrong")


# --- summary ------------------------------------------------------------------------

def summarize(paths):
    records = []
    for p in paths:
        with open(p) as f:
            records += [json.loads(line) for line in f if line.strip()]
    labels = sorted({r.get("label") or "-" for r in records})
    by_rule = {}
    for r in records:
        lab = r.get("label") or "-"
        for name, tally in r["rules"].items():
            dest = by_rule.setdefault(name, {}).setdefault(lab, {})
            for k, v in tally.items():
                if isinstance(v, (int, float)):
                    dest[k] = dest.get(k, 0) + v
    print(f"{len(records)} program runs; labels: {', '.join(labels)}\n")
    for name in sorted(by_rule):
        print(f"== {name}")
        keys = sorted({k for t in by_rule[name].values() for k in t
                       if not k.startswith("name:")})
        if keys:
            print("   " + "label".ljust(8) + "".join(k[:22].rjust(24) for k in keys))
            for lab in labels:
                t = by_rule[name].get(lab, {})
                print("   " + lab.ljust(8) + "".join(
                    str(t.get(k, 0)).rjust(24) for k in keys))
        names = {}
        for t in by_rule[name].values():
            for k, v in t.items():
                if k.startswith("name:"):
                    names[k[5:]] = names.get(k[5:], 0) + v
        if names:
            top = sorted(names.items(), key=lambda kv: -kv[1])[:12]
            print("   top: " + ", ".join(f"{k} {v}" for k, v in top))
        print()
    examples = {}
    for r in records:
        for rule_name, lst in r.get("examples", {}).items():
            examples.setdefault(rule_name, []).extend(
                f"[{r.get('label')}] {e}" for e in lst)
    print("== examples of wrong or unrepresented cases")
    for rule_name in sorted(examples):
        print(f"   {rule_name}:")
        for e in examples[rule_name][:8]:
            print(f"      {e}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--binary")
    p.add_argument("--dump")
    p.add_argument("--dtrace")
    p.add_argument("--globals-dump",
                   help="a second dump to take the globals checks from")
    p.add_argument("--label")
    p.add_argument("--no-discovery", action="store_true",
                   help="skip the H1/H2 checks, which re-scan the binary")
    p.add_argument("--summarize", nargs="+", metavar="RESULTS_JSONL")
    a = p.parse_args(argv)
    if a.summarize:
        summarize(a.summarize)
        return 0
    if not (a.binary and a.dump):
        p.error("--binary and --dump are required unless --summarize is given")
    with open(a.dump) as f:
        dump = json.load(f)
    gdump = None
    if a.globals_dump:
        with open(a.globals_dump) as f:
            gdump = json.load(f)
    record = grade(a.binary, dump, a.dtrace, a.label,
                   discovery=not a.no_discovery, globals_dump=gdump)
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
