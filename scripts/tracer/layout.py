"""Per-allocation-site layouts from attributed memory accesses (phase 11, step 2).

Pure. The emulator attributes every load and store to an object
(objects.ObjectTable) and reports it here keyed by the object's SITE - the
allocating call for heap blocks, the address for globals, the (function,
frame offset) slot for stack objects. All instances of one site are one type,
so evidence from every function and every call that touched any of them pools
into a single layout. That is what a per-(function, argument) footprint could
never do: a callee that only reads p->a still learns p->b from the caller that
wrote it, without guessing an extent, because the extent belongs to the site.

Keys
  ("heap", pc)            heap block allocated by the call at pc
  ("global", addr)        a global object (resolved at finalize)
  ("stack", func, off)    a stack object at frame offset off of func
Raw keys, resolved by finalize():
  ("graw",)               data-section access, offset = absolute address
  ("sframe", func)        another function's frame, offset = frame offset
"""
from collections import Counter, defaultdict

INT, SEXT, ZEXT, SSE = "int", "sext", "zext", "sse"


class FieldEvidence:
    __slots__ = ("widths", "classes", "reads", "writes", "targets", "zeros", "plain")

    def __init__(self):
        self.widths = Counter()
        self.classes = Counter()
        self.reads = 0
        self.writes = 0
        self.targets = Counter()     # target site -> count (pointer values)
        self.zeros = 0               # 8-byte values that were 0 (NULL or 0L)
        self.plain = 0               # 8-byte non-zero values pointing nowhere

    def merge(self, other):
        self.widths.update(other.widths)
        self.classes.update(other.classes)
        self.reads += other.reads
        self.writes += other.writes
        self.targets.update(other.targets)
        self.zeros += other.zeros
        self.plain += other.plain

    @property
    def count(self):
        return self.reads + self.writes


class SiteLayout:
    """Everything observed about one type."""

    def __init__(self, site):
        self.site = site
        self.fields = defaultdict(FieldEvidence)       # offset -> evidence
        # (instance, pc) -> {offsets}: which offsets ONE instruction walked in
        # ONE object. `p->a; p->b` uses one instruction per field; `a[i]` uses
        # one instruction for many offsets - the stride evidence.
        self.pc_offsets = defaultdict(set)
        self.size = None                                 # min observed extent
        self.instances = set()

    def note_size(self, size):
        if size is not None and size > 0:
            self.size = size if self.size is None else min(self.size, size)

    def strides(self):
        """{stride: number of (instance, pc) groups walking it}."""
        out = Counter()
        for offs in self.pc_offsets.values():
            if len(offs) < 2:
                continue
            s = sorted(offs)
            diffs = {b - a for a, b in zip(s, s[1:])}
            if len(diffs) == 1:
                out[diffs.pop()] += 1
            else:
                from math import gcd
                g = 0
                for d in diffs:
                    g = gcd(g, d)
                if g:
                    out[g] += 1
        return out

    def max_elements_walked(self, stride):
        """Most offsets one instruction touched in one object at this stride."""
        best = 0
        for offs in self.pc_offsets.values():
            if len(offs) >= 2:
                s = sorted(offs)
                if all((b - a) % stride == 0 for a, b in zip(s, s[1:])):
                    best = max(best, len(offs))
        return best


class Evidence:
    """Accumulates attributed accesses during a run."""

    def __init__(self):
        self._acc = defaultdict(FieldEvidence)     # (key, off) -> evidence
        self._pcs = defaultdict(set)               # (key, instance, pc) -> {off}
        self._sizes = {}                           # key -> min size
        self._instances = defaultdict(set)         # key -> {instance}
        self.stack_roots = defaultdict(set)        # func -> {frame offsets}

    def note_access(self, key, off, width, write, cls, pc, instance, target=None,
                    word=None):
        ev = self._acc[(key, off)]
        ev.widths[width] += 1
        ev.classes[cls] += 1
        if write:
            ev.writes += 1
        else:
            ev.reads += 1
        if target is not None:
            ev.targets[target] += 1
        elif word is not None:
            if word:
                ev.plain += 1
            else:
                ev.zeros += 1
        self._pcs[(key, instance, pc)].add(off)
        self._instances[key].add(instance)

    def note_size(self, key, size):
        if size is not None and size > 0:
            prev = self._sizes.get(key)
            self._sizes[key] = size if prev is None else min(prev, size)

    def note_stack_root(self, func, frame_off):
        """A pointer to frame offset frame_off of func was handed out."""
        self.stack_roots[func].add(frame_off)

    # ---------------------------------------------------------------- finish
    def layouts(self, resolve_global=None):
        """{site: SiteLayout}.

        resolve_global(addr) -> (site, offset, size) | None maps a raw data
        address onto a global object. Stack frame offsets are carved into
        objects at the registered stack roots: an object starts at a root and
        ends at the next root above it or at the saved-rbp slot (-8), so one
        local's fields never absorb a neighbour's.
        """
        out = {}

        def get(site):
            lay = out.get(site)
            if lay is None:
                lay = out[site] = SiteLayout(site)
            return lay

        def carve_stack(func, frame_off):
            roots = sorted(r for r in self.stack_roots.get(func, ()) if r <= frame_off)
            if not roots:
                return None
            base = roots[-1]
            above = sorted(r for r in self.stack_roots.get(func, ()) if r > base)
            limit = above[0] if above else -8
            if frame_off >= limit:
                return None
            return ("stack", func, base), frame_off - base, limit - base

        def place(key, off):
            if key[0] == "graw":
                if resolve_global is None:
                    return None
                return resolve_global(off)
            if key[0] == "sframe":
                return carve_stack(key[1], off)
            return key, off, self._sizes.get(key)

        def map_target(t):
            if t is None:
                return None
            tkey, toff = t
            p = place(tkey, toff)
            return (p[0], p[1]) if p else None

        for (key, off), ev in self._acc.items():
            p = place(key, off)
            if p is None:
                continue
            site, o, size = p
            lay = get(site)
            fe = lay.fields[o]
            fe.widths.update(ev.widths)
            fe.classes.update(ev.classes)
            fe.reads += ev.reads
            fe.writes += ev.writes
            fe.zeros += ev.zeros
            fe.plain += ev.plain
            for t, n in ev.targets.items():
                mt = map_target(t)
                if mt is not None:
                    fe.targets[mt] += n
            lay.note_size(size)
            lay.instances |= self._instances.get(key, set())
        for (key, inst, pc), offs in self._pcs.items():
            for off in offs:
                p = place(key, off)
                if p is None:
                    continue
                site, o, _ = p
                if site in out:
                    out[site].pc_offsets[(inst, pc)].add(o)
        for key, size in self._sizes.items():
            if key[0] not in ("graw", "sframe"):
                get(key).note_size(size)
        return out
