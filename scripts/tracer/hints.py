"""Outside type hints for arguments and returns (--type-hints), checked by the run.

Pure. A hint file names, per function and argument, one or more CANDIDATE
C types (from a model such as ReSym, or any other source). The tracer applies
a candidate's effect only when the run does not refute it AND every surviving
candidate agrees on that effect; otherwise it abstains. A type never changes
how the program executes, only how its memory is read, so one run tests every
candidate at once.

File format:
    {"functions": {"0x401136": {"args": {"0": [TYPE, ...], ...},
                                "return": [TYPE, ...]}}}
    TYPE = {"kind": "pointer", "pointee": {"kind": "char|int|float|struct|pointer|void",
                                           "size": n, "signed": bool}}
         | {"kind": "int", "size": n, "signed": bool} | {"kind": "float", "size": n}
Argument keys are the tracer's integer-class argument index (arg0 = rdi).

Effects:
    ("string",)                    char *: the argument is a C string
    ("array", w, kind, signed)     T * with T an int/float of width w: T[] elements
    None                           any other type: no change to the output
"""
import json

from .classify import FLOAT, SINT, UINT, STRUCT, ARRAY, SCALAR as T_SCALAR, ABSTAIN
from .memmap import POINTER, SCALAR

STRING = "string"
ARRAY_EFFECT = "array"
TEXT = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
MAX_STRING = 4096
N_REG_ARGS = 6


def load(path):
    """{(func_addr, raw_index): [candidate, ...]}. raw_index follows the
    tracer's raw vector: 0 = rax (return), 1 + i = integer register arg i."""
    with open(path) as fh:
        data = json.load(fh)
    out = {}
    for faddr, spec in (data.get("functions") or {}).items():
        a = int(faddr, 16) if isinstance(faddr, str) else int(faddr)
        for k, cands in (spec.get("args") or {}).items():
            i = int(k)
            if 0 <= i < N_REG_ARGS and cands:
                out[(a, 1 + i)] = list(cands)
        if spec.get("return"):
            out[(a, 0)] = list(spec["return"])
    return out


def effect(c):
    """The output change a candidate type asks for (see module doc)."""
    if not c or c.get("kind") != "pointer":
        return None
    p = c.get("pointee") or {}
    pk = p.get("kind")
    if pk == "char":
        return (STRING,)
    w = p.get("size")
    if pk == "float" and w in (4, 8):
        return (ARRAY_EFFECT, w, FLOAT, None)
    if pk == "int" and w in (1, 2, 4, 8):
        return (ARRAY_EFFECT, w, UINT if p.get("signed") is False else SINT,
                p.get("signed") is not False)
    return None


def is_cstring(blob):
    """True if blob starts with a NUL-terminated run of text (possibly empty)."""
    if blob is None:
        return False
    end = blob.find(b"\0", 0, MAX_STRING)
    if end < 0:
        return False
    return all(b in TEXT for b in blob[:end])


def refuted(c, slot_kind, slot_nonzero, string_bad, site_type):
    """Does the run contradict candidate c?

    slot_kind     POINTER / SCALAR from the slot's values (memmap.classify_slot)
    slot_nonzero  the slot ever held a non-zero value
    string_bad    number of non-null values that were NOT a C string
    site_type     classify.TypeInfo of the pointee the run observed, or None
    """
    is_ptr = c.get("kind") == "pointer"
    if is_ptr and slot_kind != POINTER and slot_nonzero:
        return "held a non-address"
    if not is_ptr and slot_kind == POINTER:
        return "held an address"
    e = effect(c)
    if e and e[0] == STRING and string_bad:
        return "not a C string"
    if e and e[0] == ARRAY_EFFECT and site_type is not None:
        w = e[1]
        fields = [f for f in site_type.fields if f.kind != ABSTAIN]
        if site_type.shape == STRUCT and len(fields) >= 2:
            return "pointee is a struct"
        if site_type.shape in (STRUCT, ARRAY, T_SCALAR) and any(f.width != w for f in fields):
            return "pointee width differs"
        if any((f.kind == FLOAT) != (e[2] == FLOAT) for f in fields
               if f.kind in (FLOAT, SINT, UINT)):
            return "pointee float/int differs"
    return None


def select(cands, slot_kind, slot_nonzero, string_bad, site_type):
    """(effect or None, status, [reasons]). status: applied / contested /
    no-effect / all-refuted."""
    survivors, reasons = [], []
    for c in cands:
        r = refuted(c, slot_kind, slot_nonzero, string_bad, site_type)
        if r:
            reasons.append(r)
        else:
            survivors.append(c)
    if not survivors:
        return None, "all-refuted", reasons
    effects = {effect(c) for c in survivors}
    if len(effects) > 1:
        return None, "contested", reasons
    e = effects.pop()
    if e is None:
        return None, "no-effect", reasons
    if e[0] == STRING and slot_kind != POINTER and slot_nonzero:
        return None, "all-refuted", reasons
    return e, "applied", reasons


def wants_string(cands):
    return any((effect(c) or (None,))[0] == STRING for c in cands)


# SCALAR re-exported for callers that classify slots
__all__ = ["load", "effect", "is_cstring", "refuted", "select", "wants_string",
           "STRING", "ARRAY_EFFECT", "POINTER", "SCALAR"]
