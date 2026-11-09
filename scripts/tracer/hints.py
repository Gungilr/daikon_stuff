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

from .classify import (FLOAT, SINT, UINT, STRUCT, ARRAY, SCALAR as T_SCALAR, ABSTAIN,
                       POINTER as F_POINTER, ARRAY_FIELD, FieldType, TypeInfo)
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


def load_all(path):
    """{"slots": load()'s map, "globals": {addr: [candidate, ...]},
    "observed_only": bool} - the full file, struct layouts included."""
    with open(path) as fh:
        data = json.load(fh)
    globs = {}
    for a, cands in (data.get("globals") or {}).items():
        if cands:
            globs[int(a, 16) if isinstance(a, str) else int(a)] = list(cands)
    return {"slots": load(path), "globals": globs,
            "observed_only": bool(data.get("observed_fields_only"))}


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


# ------------------------------------------------------------ struct layouts
HINT_EVIDENCE = "type hint"


def struct_layout(c):
    """The struct layout a candidate carries for what it points at, or None."""
    if not c or c.get("kind") != "pointer":
        return None
    p = c.get("pointee") or {}
    return p if p.get("kind") == "struct" and p.get("fields") else None


def _int_kind(f):
    return UINT if f.get("signed") is False else SINT


def leaves(layout):
    """[(FieldType, nested struct layout or None)] for a hinted struct layout."""
    out = []
    for f in layout.get("fields") or []:
        off, size, k = f.get("off"), f.get("size"), f.get("kind")
        if not isinstance(off, int) or not size:
            continue
        if k == "int":
            out.append((FieldType(off, size, _int_kind(f), f.get("signed") is not False,
                                  evidence=HINT_EVIDENCE), None))
        elif k == "float":
            out.append((FieldType(off, size, FLOAT, evidence=HINT_EVIDENCE), None))
        elif k == "pointer":
            pe = f.get("pointee") or {}
            hint = "cstring" if pe.get("kind") == "char" else None
            nested = pe if pe.get("kind") == "struct" and pe.get("fields") else None
            out.append((FieldType(off, 8, F_POINTER, evidence=HINT_EVIDENCE, hint=hint), nested))
        elif k == "chararray":
            out.append((FieldType(off, size, ARRAY_FIELD, True, evidence=HINT_EVIDENCE,
                                  stride=1, count=size, elem_kind=SINT, hint="chararray"), None))
        elif k == "array":
            e = f.get("elem") or {}
            w = e.get("size")
            ek = {"float": FLOAT, "pointer": F_POINTER}.get(e.get("kind"), _int_kind(e))
            if w and f.get("count"):
                out.append((FieldType(off, size, ARRAY_FIELD, e.get("signed") is not False,
                                      evidence=HINT_EVIDENCE, stride=w, count=f["count"],
                                      elem_kind=ek), None))
    return out


def _kclass(kind):
    if kind == FLOAT:
        return "f"
    if kind in (SINT, UINT):
        return "i"
    if kind == F_POINTER:
        return "p"
    return None


def merge(site, layout, observed, *, stride=None, count=None, observed_only=False):
    """(TypeInfo, [(pointer field, nested layout)]) for a hinted layout the
    run does not contradict, or (None, reason). `stride`/`count` make it an array of `layout` structs.

    Refuted by an observed field with exactly a hinted field's offset and
    width but another kind, or by an access past the hinted size. A wide
    access over several hinted fields (a copy, a zeroing store) is not a
    contradiction: those are the run's own known false fields.
    """
    size = layout.get("size") or 0
    hl = leaves(layout)
    obs = [f for f in (observed.fields if observed is not None else [])]
    unit = stride or size

    def local(o):
        return o % unit if stride and unit else o

    by_pos = {(f.offset, f.width): f for f, _ in hl}
    for o in obs:
        if o.kind == ABSTAIN or o.kind == ARRAY_FIELD:
            continue
        off = local(o.offset)
        if size and not stride and o.offset + o.width > size:
            return None, "accessed past the hinted size"
        h = by_pos.get((off, o.width))
        if h is not None and _kclass(h.kind) and _kclass(o.kind) \
                and _kclass(h.kind) != _kclass(o.kind):
            return None, f"field +{off} is {o.kind}, hint says {h.kind}"
    kept = []
    for f, nested in hl:
        if observed_only:
            touched = any(local(o.offset) < f.offset + f.width
                          and f.offset < local(o.offset) + o.width for o in obs)
            if not touched:
                continue
        if f.kind == F_POINTER:
            for o in obs:
                if local(o.offset) == f.offset and o.width == 8 and o.targets:
                    f.targets = tuple(o.targets)
                    break
        kept.append((f, nested))
    if not kept:
        return None, "no field left"
    fields = [f for f, _ in kept]
    if stride:
        t = TypeInfo(site, ARRAY, stride * (count or 0), fields, stride=stride, count=count,
                     elem_struct=True, hinted=True)
    else:
        t = TypeInfo(site, STRUCT, size, fields, hinted=True)
    return t, [(f, n) for f, n in kept if n is not None]
