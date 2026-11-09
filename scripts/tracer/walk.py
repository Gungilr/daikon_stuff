"""One typed traversal from every root (phase 11, step 4).

Pure. Replaces three special cases - argument pointees, the pointer-valued
return, pointer-holding globals - with one walk over classified site types
(classify.TypeInfo), to a depth limit, with a visited set because recursive
data structures are real (`n1->next->prev == n1`).

Naming follows Kvasir exactly, because representation is the interface:
    p              the pointer                       hashcode
    p[..]          the object, a one-element array   hashcode[]   (struct)
                                                     int[] etc.  (array / scalar)
    p[..].offK     a field                           int[]
    p[..].offK->offJ   a field of the object a pointer field points at
    g.offK         a field of a struct-valued global int
Offsets stand in for field names, which stripping destroys; the scorer maps
them to DWARF names.

A Var carries a PATH, evaluated against one sample's captured memory:
    ("ptr",)          value of the root pointer
    ("deref", k)      load the 8-byte pointer at current + k, continue there
    ("field", k, w, kind, signed)
Context "one" = Kvasir's one-element array; "seq" = a real array.
"""
import struct

from .classify import ARRAY, STRUCT, SCALAR, POINTER, FLOAT, SINT, UINT, ABSTAIN, ARRAY_FIELD
from .shadow import defined, last_defined_element

NONSENSICAL = "nonsensical"


class Var:
    __slots__ = ("name", "dec_type", "rep_type", "var_kind", "enclosing", "array",
                 "comp", "path", "leaf")

    def __init__(self, name, dec_type, rep_type, comp, path, leaf, var_kind="variable",
                 enclosing=None, array=None):
        self.name = name
        self.dec_type = dec_type
        self.rep_type = rep_type
        self.var_kind = var_kind
        self.enclosing = enclosing
        self.array = array
        self.comp = comp
        self.path = path        # list of ops from the root
        self.leaf = leaf        # ("hash",) | ("field", w, kind, signed) | ("seq", stride, w, kind, signed, count)

    def __repr__(self):
        return f"Var({self.name} {self.rep_type})"


def _scalar_types(kind, in_array):
    sfx = "[]" if in_array else ""
    if kind == FLOAT:
        return "double" + sfx, "double" + sfx, "float"
    if kind == POINTER:
        return "void*" + sfx, "hashcode" + sfx, "pointer"
    return "int" + sfx, "int" + sfx, "scalar"


def plan_pointer_root(name, site, types, depth, *, in_array=False, path=None,
                      visited=None, string_sites=frozenset()):
    """Vars for the object a pointer-valued root points at (the root itself
    is declared by the caller). [] when the type is unknown or ambiguous."""
    path = list(path or [])
    visited = set(visited or ())
    T = types.get(site)
    if T is None or depth < 1 or site in visited:
        return []
    visited.add(site)
    obj = f"{name}[..]"
    if T.shape == ARRAY and T.elem_struct:
        # Array of structs: the elements as hashcodes, then one sequence per
        # field across the elements - Kvasir's `::globalFoo[..].age`.
        out = [Var(obj, "void*[]", "hashcode[]", "pointer[]", path,
                   ("seqhash", T.stride, T.count), var_kind="array",
                   enclosing=name, array=1)]
        for f in T.fields:
            if f.kind == ABSTAIN or f.kind == ARRAY_FIELD:
                continue        # Daikon has no arrays of arrays
            fname = f"{obj}.off{f.offset}"
            if f.kind == POINTER and (f.hint == "cstring" or (
                    f.targets and f.targets[0][0] in string_sites)):
                out.append(Var(fname, "char*[]", "java.lang.String[]", "string[]", path,
                               ("seqstring", T.stride, f.offset, T.count),
                               var_kind=f"field off{f.offset}", enclosing=obj, array=1))
                continue
            dec, rep_, comp = _scalar_types(f.kind, True)
            out.append(Var(fname, dec, rep_, comp, path,
                           ("seqfield", T.stride, f.offset, f.width, f.kind, f.signed,
                            T.count),
                           var_kind=f"field off{f.offset}", enclosing=obj, array=1))
        return out
    if T.shape == ARRAY:
        e = T.fields[0]
        if e.kind in (ABSTAIN,) or e.kind not in (SINT, UINT, FLOAT, POINTER):
            return []
        dec, rep, comp = _scalar_types(e.kind, True)
        return [Var(obj, dec, rep, comp + "[]", path, ("seq", T.stride, e.width, e.kind,
                                                        e.signed, T.count),
                    var_kind="array", enclosing=name, array=1)]
    if T.shape == SCALAR:
        f = T.fields[0]
        if f.kind == ABSTAIN:
            return []
        dec, rep, comp = _scalar_types(f.kind, True)
        out = [Var(obj, dec, rep, comp + "[]", path,
                   ("field", f.width, f.kind, f.signed), var_kind="array",
                   enclosing=name, array=1)]
        return out
    if T.shape != STRUCT:
        return []
    out = [Var(obj, "void*[]", "hashcode[]", "pointer[]", path, ("hash",),
               var_kind="array", enclosing=name, array=1)]
    out += _struct_fields(obj, T, types, depth, path, visited, in_array=True,
                          sep=".", string_sites=string_sites)
    return out


def _struct_fields(prefix, T, types, depth, path, visited, *, in_array, sep,
                   string_sites):
    out = []
    for f in T.fields:
        if f.kind == ABSTAIN:
            continue
        fname = f"{prefix}{sep}off{f.offset}"
        arr = 1 if in_array else None
        if f.kind == ARRAY_FIELD and f.hint == "chararray":
            # A hinted char[N] member: Kvasir prints it as a string.
            out.append(Var(fname, "char*" + ("[]" if in_array else ""),
                           "java.lang.String" + ("[]" if in_array else ""),
                           "string", path, ("inline_string", f.offset, f.count),
                           var_kind=f"field off{f.offset}", enclosing=prefix, array=arr))
            continue
        if f.kind == ARRAY_FIELD:
            # Daikon has no arrays of arrays, so an embedded array is only
            # expressible outside a sequence context: `g.off8[..]`.
            if in_array:
                continue
            dec, rep, comp = _scalar_types(f.elem_kind, True)
            out.append(Var(fname, dec, "hashcode", "pointer", path, ("addr_at", f.offset),
                           var_kind=f"field off{f.offset}", enclosing=prefix))
            out.append(Var(f"{fname}[..]", dec, rep, comp + "[]", path + [("off", f.offset)],
                           ("seq", f.stride, f.stride, f.elem_kind, f.signed, f.count),
                           var_kind="array", enclosing=fname, array=1))
            continue
        if f.kind == POINTER and (f.hint == "cstring" or (
                f.targets and f.targets[0][0] in string_sites)):
            out.append(Var(fname, "char*" + ("[]" if in_array else ""),
                           "java.lang.String" + ("[]" if in_array else ""),
                           "string", path, ("string", f.offset),
                           var_kind=f"field off{f.offset}", enclosing=prefix, array=arr))
            continue
        dec, rep, comp = _scalar_types(f.kind, in_array)
        out.append(Var(fname, dec, rep, comp, path, ("field_at", f.offset, f.width,
                                                     f.kind, f.signed),
                       var_kind=f"field off{f.offset}", enclosing=prefix, array=arr))
        if f.kind == POINTER and depth > 1 and f.targets:
            tsite, toff = f.targets[0]
            if toff != 0 or len({t[0] for t in f.targets}) != 1:
                continue      # points into the middle, or at several types: abstain
            TT = types.get(tsite)
            if TT is None or TT.shape != STRUCT or tsite in visited:
                continue
            sub_path = path + [("deref", f.offset)]
            out += _struct_fields(fname, TT, types, depth - 1, sub_path,
                                  visited | {tsite}, in_array=in_array, sep="->",
                                  string_sites=string_sites)
    return out


def plan_struct_global(name, site, types, depth, string_sites=frozenset()):
    """Vars for a global whose OWN storage is a struct: `g.offK` fields."""
    T = types.get(site)
    if T is None or T.shape != STRUCT or (len(T.fields) < 2 and not T.hinted):
        return []
    return _struct_fields(name, T, types, depth, [], {site}, in_array=False,
                          sep=".", string_sites=string_sites)


# ------------------------------------------------------------------ values
class Memory:
    """One sample's captured memory: {base: bytes} regions."""

    def __init__(self, regions, masks=None, poison=None):
        self.regions = sorted(regions.items())
        self.masks = masks or {}     # region base -> definedness (shadow)
        # --poison-uninitialized: a value made only of the fill byte was never
        # written, and is nonsensical rather than a number.
        self.poison = poison

    def read(self, addr, n, check=True):
        """Bytes, or None if not captured - or, with shadow memory, if any
        byte was never written (Kvasir prints such a value as nonsensical)."""
        for base, blob in self.regions:
            if base <= addr and addr + n <= base + len(blob):
                o = addr - base
                if check and not defined(self.masks.get(base), o, n):
                    return None
                raw = blob[o:o + n]
                if check and self.poison is not None and raw == bytes([self.poison]) * n:
                    return None
                return raw
        return None

    def defined_elements(self, addr, stride):
        """With shadow memory: elements from addr up to the last defined one."""
        for base, blob in self.regions:
            if base <= addr < base + len(blob):
                m = self.masks.get(base)
                if m is None:
                    return None
                return last_defined_element(m[addr - base:], stride)
        return None

    def extent(self, addr):
        """Bytes captured from addr to the end of its region."""
        for base, blob in self.regions:
            if base <= addr < base + len(blob):
                return base + len(blob) - addr
        return 0

    def cstring(self, addr, limit=4096):
        for base, blob in self.regions:
            if base <= addr < base + len(blob):
                o = addr - base
                end = blob.find(b"\0", o, o + limit)
                if end < 0:
                    return None
                try:
                    return blob[o:end].decode("latin-1")
                except Exception:
                    return None
        return None


def _decode(raw, width, kind, signed):
    if raw is None:
        return None
    if kind == FLOAT:
        if width == 4:
            return struct.unpack("<f", raw)[0]
        return struct.unpack("<d", raw)[0]
    v = int.from_bytes(raw, "little")
    if kind == POINTER:
        return v
    if signed is not False and v >= 1 << (8 * width - 1):
        v -= 1 << (8 * width)
    return v


def _follow(mem, ptr, path):
    cur = ptr
    for op in path:
        if op[0] == "off":
            cur += op[1]
            continue
        if op[0] == "deref":
            raw = mem.read(cur + op[1], 8)
            if raw is None:
                return None
            cur = int.from_bytes(raw, "little")
            if not cur:
                return None
    return cur


def _quote(s):
    """A dtrace string literal; \r must be escaped, a raw one would end the line."""
    return '"' + (s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
                  .replace("\r", "\\r")) + '"'


def value_of(var, mem, root, in_array):
    """The dtrace value of one Var given the root (pointer value, or the
    address of a struct global), or NONSENSICAL."""
    if not root:
        return NONSENSICAL
    base = _follow(mem, root, var.path)
    if base is None:
        return NONSENSICAL
    leaf = var.leaf
    wrap = (lambda v: [v]) if in_array else (lambda v: v)
    if leaf[0] == "hash":
        return wrap(base) if mem.read(base, 1, check=False) is not None else NONSENSICAL
    if leaf[0] == "addr_at":
        return base + leaf[1]
    if leaf[0] == "field":
        _, w, kind, signed = leaf
        v = _decode(mem.read(base, w), w, kind, signed)
        return NONSENSICAL if v is None else wrap(v)
    if leaf[0] == "field_at":
        _, off, w, kind, signed = leaf
        v = _decode(mem.read(base + off, w), w, kind, signed)
        return NONSENSICAL if v is None else wrap(v)
    if leaf[0] == "inline_string":
        raw = mem.read(base + leaf[1], leaf[2])
        if raw is None:
            return NONSENSICAL
        end = raw.find(b"\0")
        return wrap(_quote(raw[:end if end >= 0 else len(raw)].decode("latin-1")))
    if leaf[0] == "string":
        raw = mem.read(base + leaf[1], 8)
        if raw is None:
            return NONSENSICAL
        p = int.from_bytes(raw, "little")
        s = mem.cstring(p) if p else None
        return NONSENSICAL if s is None else wrap(_quote(s))
    if leaf[0] in ("seqhash", "seqfield", "seqstring"):
        stride, count = leaf[1], leaf[-1]
        avail = mem.extent(base) // stride if stride else 0
        n = min(count, avail) if count else avail
        if n <= 0:
            return NONSENSICAL
        out = []
        for i in range(n):
            ea = base + i * stride
            if leaf[0] == "seqhash":
                out.append(ea)
            elif leaf[0] == "seqfield":
                _, _, off, w, kind, signed, _ = leaf
                v = _decode(mem.read(ea + off, w), w, kind, signed)
                if v is None:
                    return NONSENSICAL
                out.append(v)
            else:
                raw = mem.read(ea + leaf[2], 8)
                p = int.from_bytes(raw, "little") if raw else 0
                s = mem.cstring(p) if p else None
                out.append(_quote(s) if s is not None else "null")
        return out
    if leaf[0] == "seq":
        _, stride, w, kind, signed, count = leaf
        avail = mem.extent(base) // stride if stride else 0
        n = min(count, avail) if count else avail
        d = mem.defined_elements(base, stride)
        if d is not None:
            n = min(n, d)
        if n <= 0:
            return NONSENSICAL
        seq = []
        for i in range(n):
            v = _decode(mem.read(base + i * stride, w), w, kind, signed)
            if v is None:
                break
            seq.append(v)
        return seq if seq else NONSENSICAL
    return NONSENSICAL


# ----------------------------------------------------------------- capture
def capture(roots, lookup, read, max_depth, *, obj_cap=1024, total_cap=65536):
    """Regions reachable from root pointer values, for one sample.

    lookup(addr) -> (base, extent) of the object an address falls in, or None
    read(addr, n) -> bytes or None
    Captures BROADLY (every pointer-shaped 8-byte word inside a captured
    object is followed, to max_depth) because the layout - which words are
    pointers - is only decided at finalize, after the bytes are gone.
    """
    regions = {}
    total = 0
    frontier = [(r, 0) for r in roots if r]
    seen = set()
    while frontier:
        ptr, d = frontier.pop()
        hit = lookup(ptr)
        if hit is None:
            continue
        base, extent = hit
        start = ptr if base is None else base
        if start in seen:
            continue
        seen.add(start)
        n = min(extent if base is None else extent, obj_cap)
        if n <= 0 or total + n > total_cap:
            continue
        blob = read(start, n)
        if blob is None:
            continue
        regions[start] = blob
        total += len(blob)
        if d < max_depth:
            for o in range(0, len(blob) - 7, 8):
                v = int.from_bytes(blob[o:o + 8], "little")
                if v and v not in seen:
                    frontier.append((v, d + 1))
    return regions
