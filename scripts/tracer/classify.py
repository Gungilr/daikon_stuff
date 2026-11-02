"""Field and shape classification of site layouts (phase 11, step 3).

Pure. Turns a layout.SiteLayout into a TypeInfo: is this type an array, a
struct, or a single scalar; and for each field, is it a pointer (and to which
sites), a float, a signed or unsigned integer - or ambiguous.

Every class needs positive run-time evidence, and conflicting evidence yields
ABSTAIN rather than a choice: for a fuzzing consumer an invented fact is worse
than an absent one.

  pointer   the value stored there resolved to a live object
  float     an SSE instruction moved it (movss = 4 bytes, movsd = 8)
  signed    loaded with movsx/movsxd;  unsigned: loaded with movzx
  array     one instruction walked >= MIN_ARRAY_ELEMENTS offsets at a constant
            stride (Howard's rule: fewer looped elements is a struct)
  union     one offset used as two incompatible classes -> ABSTAIN
"""
from collections import Counter

from .layout import SEXT, ZEXT, SSE

POINTER, FLOAT, SINT, UINT, ABSTAIN = "pointer", "float", "int", "uint", "abstain"
ARRAY_FIELD = "array_field"     # an array embedded in a struct: `s.c[]`
ARRAY, STRUCT, SCALAR, UNKNOWN = "array", "struct", "scalar", "unknown"

MIN_ARRAY_ELEMENTS = 4     # Howard, NDSS'11: < 4 looped elements -> struct
POINTER_WIDTH = 8


class FieldType:
    __slots__ = ("offset", "width", "kind", "signed", "targets", "evidence",
                 "stride", "count", "elem_kind")

    def __init__(self, offset, width, kind, signed=None, targets=(), evidence="",
                 stride=None, count=None, elem_kind=None):
        self.offset = offset
        self.width = width
        self.kind = kind
        self.signed = signed
        self.targets = tuple(targets)
        self.evidence = evidence
        self.stride = stride          # ARRAY_FIELD only
        self.count = count
        self.elem_kind = elem_kind

    def __repr__(self):
        t = f" ->{list(self.targets)}" if self.targets else ""
        s = "" if self.signed is None else (" signed" if self.signed else " unsigned")
        return f"Field(+{self.offset} {self.width}B {self.kind}{s}{t})"


class TypeInfo:
    def __init__(self, site, shape, size=None, fields=(), stride=None, count=None,
                 elem_struct=False):
        self.site = site
        self.shape = shape
        self.size = size
        self.fields = list(fields)        # struct/scalar fields, or the element
        self.stride = stride              # arrays
        self.count = count                # arrays with a known extent
        # Array of structs: `fields` are the ELEMENT's fields, offsets within
        # one element of `stride` bytes.
        self.elem_struct = elem_struct

    def pointer_fields(self):
        return [f for f in self.fields if f.kind == POINTER and f.targets]

    def __repr__(self):
        extra = f" stride={self.stride} count={self.count}" if self.shape == ARRAY else ""
        return f"TypeInfo({self.site!r} {self.shape} size={self.size}{extra} {self.fields})"


def classify_field(offset, ev):
    """FieldType for one offset's evidence, or None if there is nothing usable."""
    if not ev.widths:
        return None
    width = ev.widths.most_common(1)[0][0]
    if len(ev.widths) > 1:
        # Two widths at one offset: a wide copy (memcpy-style 8-byte moves) over
        # narrower fields, or a union. Take the narrowest width that was read
        # or written by more than one instruction class, else abstain.
        widths = sorted(ev.widths)
        width = widths[0]
    cls = ev.classes
    targets = [t for t, _ in ev.targets.most_common()]
    sse = cls.get(SSE, 0)
    is_ptr = bool(targets) and POINTER_WIDTH in ev.widths
    if sse and is_ptr:
        return FieldType(offset, width, ABSTAIN, evidence="sse and pointer at one offset")
    if is_ptr:
        return FieldType(offset, POINTER_WIDTH, POINTER, targets=targets,
                         evidence="stored value resolved to an object")
    if sse:
        if cls.get(SEXT, 0) or cls.get(ZEXT, 0):
            return FieldType(offset, width, ABSTAIN, evidence="sse and extending loads")
        return FieldType(offset, width if width in (4, 8) else 8, FLOAT,
                         evidence="moved by SSE")
    signed = None
    if cls.get(SEXT, 0) and not cls.get(ZEXT, 0):
        signed = True
    elif cls.get(ZEXT, 0) and not cls.get(SEXT, 0):
        signed = False
    return FieldType(offset, width, SINT if signed is not False else UINT,
                     signed=signed, evidence="integer access")


def _drop_overlaps(fields):
    """Keep non-overlapping fields; a field covered by a wider one is dropped
    in favour of whichever has more accesses (the other was a copy or a
    sub-access). Overlap that cannot be resolved that way is ABSTAIN."""
    out = []
    for f in sorted(fields, key=lambda f: (f.offset, -f.width)):
        if out and f.offset < out[-1].offset + out[-1].width:
            prev = out[-1]
            if prev.kind == ABSTAIN or f.kind == ABSTAIN:
                continue
            # A narrower access inside a wider field: keep the wider one if it
            # is a pointer or float (which narrow accesses cannot be), else
            # keep the narrower fields (a wide move copied several of them).
            if prev.kind in (POINTER, FLOAT):
                continue
            out[-1] = FieldType(prev.offset, f.offset - prev.offset, prev.kind,
                                prev.signed, prev.targets, prev.evidence) \
                if f.offset > prev.offset else f
            if f.offset > prev.offset:
                out.append(f)
            continue
        out.append(f)
    return [f for f in out if f.width > 0]


def classify(layout):
    """TypeInfo for a SiteLayout."""
    raw = []
    for off in sorted(layout.fields):
        ft = classify_field(off, layout.fields[off])
        if ft is not None and off >= 0:
            raw.append(ft)
    if not raw:
        return TypeInfo(layout.site, UNKNOWN, layout.size)

    runs = _strided_runs(layout)
    if runs:
        start, stride, n = max(runs, key=lambda r: (r[2], -r[0]))
        span_end = start + n * stride
        inside = [f for f in raw if start <= f.offset < span_end]
        outside = [f for f in raw if not (start <= f.offset < span_end)]
        if start == 0 and not outside:
            elem = _array_element(inside, stride)
            if elem is not None:
                cnt = (layout.size // stride) if layout.size else n
                return TypeInfo(layout.site, ARRAY, layout.size, [elem],
                                stride=stride, count=cnt)
        elif outside and inside:
            elem = _array_element(inside, stride)
            if elem is not None and elem.kind in (SINT, UINT, FLOAT, POINTER):
                af = FieldType(start, stride, ARRAY_FIELD, elem.signed, elem.targets,
                               "strided run inside a struct", stride=stride, count=n,
                               elem_kind=elem.kind)
                fields = _drop_overlaps(outside) + [af]
                return TypeInfo(layout.site, STRUCT, layout.size,
                                sorted(fields, key=lambda f: f.offset))

    uni = _uniform_tiling(raw, layout.size)
    if uni is not None:
        w, n = uni
        e = raw[0]
        sg = _merged_sign(raw)
        kind = _kclass(e.kind) if e.kind in (SINT, UINT) else e.kind
        if kind == SINT and sg is False:
            kind = UINT
        return TypeInfo(layout.site, ARRAY, layout.size,
                        [FieldType(0, w, kind, sg, e.targets, "uniform tiling")],
                        stride=w, count=(layout.size // w) if layout.size else n)

    strides = layout.strides()
    if strides:
        stride, _ = strides.most_common(1)[0]
        walked = layout.max_elements_walked(stride)
        widths = {f.width for f in raw}
        kinds = {f.kind for f in raw}
        uniform = len(widths) == 1 and len(kinds) == 1 and stride in widths
        n = (layout.size // stride) if layout.size and stride else None
        if walked >= MIN_ARRAY_ELEMENTS or (uniform and n and n >= MIN_ARRAY_ELEMENTS
                                            and walked >= 2):
            elem = _array_element(raw, stride)
            if elem is not None:
                return TypeInfo(layout.site, ARRAY, layout.size, [elem],
                                stride=stride, count=n)

    per = _period(raw, layout.size)
    if per is not None:
        p, elem_fields = per
        return TypeInfo(layout.site, ARRAY, layout.size, elem_fields, stride=p,
                        count=layout.size // p, elem_struct=True)

    fields = _drop_overlaps(raw)
    if len(fields) == 1 and fields[0].offset == 0 and (
            layout.size is None or layout.size <= fields[0].width):
        return TypeInfo(layout.site, SCALAR, layout.size, fields)
    return TypeInfo(layout.site, STRUCT, layout.size, fields)


def _array_element(raw, stride):
    """The element type of an array of `stride`-byte elements, folding every
    observed field onto [0, stride). Elements that disagree -> None (struct
    with a strided loop, or a union): the caller falls back to STRUCT."""
    by_off = {}
    for f in raw:
        o = f.offset % stride
        prev = by_off.get(o)
        if prev is None:
            by_off[o] = f
        elif _kclass(prev.kind) != _kclass(f.kind) or prev.width != f.width:
            return None
    if len(by_off) == 1 and 0 in by_off:
        e = by_off[0]
        return FieldType(0, e.width, e.kind, e.signed, e.targets, e.evidence)
    # array of structs: keep only the first element's layout as the element
    return FieldType(0, stride, STRUCT, evidence="array of structs")


def _strided_runs(layout):
    """[(start, stride, elements)] walked by ONE instruction in one object,
    >= MIN_ARRAY_ELEMENTS elements at a constant stride."""
    best = {}
    for offs in layout.pc_offsets.values():
        if len(offs) < MIN_ARRAY_ELEMENTS:
            continue
        srt = sorted(offs)
        diffs = {b - a for a, b in zip(srt, srt[1:])}
        if len(diffs) != 1:
            continue
        stride = diffs.pop()
        if stride <= 0:
            continue
        key = (srt[0], stride)
        best[key] = max(best.get(key, 0), (srt[-1] - srt[0]) // stride + 1)
    return [(st, sd, n) for (st, sd), n in best.items()]


def _kclass(kind):
    """Signed and unsigned integers of one width are one kind for SHAPE
    decisions; one zero-extending load must not split an array of shorts."""
    return SINT if kind in (SINT, UINT) else kind


def _merged_sign(fields):
    signs = {f.signed for f in fields if f.signed is not None}
    return signs.pop() if len(signs) == 1 else None


def _uniform_tiling(raw, size):
    """(width, elements) if every field has one width and kind and they tile
    contiguously from 0, >= MIN_ARRAY_ELEMENTS of them: an array, not a
    struct of N identical fields. A run Kvasir prints as a sequence."""
    if len(raw) < MIN_ARRAY_ELEMENTS:
        return None
    sig = {(f.width, _kclass(f.kind)) for f in raw}
    if len(sig) != 1:
        return None
    w, kind = sig.pop()
    if kind == ABSTAIN or w <= 0:
        return None
    offs = sorted(f.offset for f in raw)
    if offs[0] != 0 or any(b - a != w for a, b in zip(offs, offs[1:])):
        return None
    if size and size % w:
        return None
    return w, len(offs)


def _period(raw, size):
    """(period, element fields) if the fields repeat as an array of structs.

    No instruction walked these elements (each was accessed at a constant
    address - `g[0].age = 13; g[1].age = 23`), so there is no stride; the
    evidence is the layout repeating. Required: the period divides the extent,
    >= 2 elements carry fields, every carrying element has the SAME field
    signature, and an element has >= 2 fields - a plain scalar tiling stays a
    struct, as before (that int[4]-vs-struct ambiguity is not resolved here).
    """
    if not size or len(raw) < 4:
        return None
    for p in range(8, size // 2 + 1, 4):
        if size % p:
            continue
        sigs = []
        ok = True
        for k in range(size // p):
            lo, hi = k * p, (k + 1) * p
            sig = tuple((f.offset - lo, f.width, _kclass(f.kind)) for f in raw
                        if lo <= f.offset < hi)
            if any(f.offset + f.width > hi for f in raw if lo <= f.offset < hi):
                ok = False
                break
            sigs.append(sig)
        if not ok:
            continue
        carrying = [g for g in sigs if g]
        if len(carrying) >= 2 and len(carrying[0]) >= 2 and all(g == carrying[0] for g in carrying):
            k0 = sigs.index(carrying[0])
            elem = [FieldType(f.offset - k0 * p, f.width, f.kind, f.signed, f.targets,
                              f.evidence)
                    for f in raw if k0 * p <= f.offset < (k0 + 1) * p]
            return p, elem
    return None


def classify_all(layouts):
    return {site: classify(lay) for site, lay in layouts.items()}


# ------------------------------------------------------------------ strings
def looks_like_string(blob, min_len=1, max_len=4096):
    """True if blob starts with >= min_len printable bytes then a NUL."""
    if not blob:
        return False
    end = blob.find(b"\0")
    if end < min_len or end > max_len:
        return False
    return all(32 <= c < 127 or c in (9, 10, 13) for c in blob[:end])
