"""Memory objects and pointer provenance (phase 11, step 1).

Pure: no Unicorn, no capstone. The emulator feeds events in; this module
answers "which object does this address belong to, at what offset".

Three earlier mechanisms (--infer-from-caller, --deref-globals,
--struct-globals) recovered real accesses and still lost precision, for one
shared reason: an access was credited to the wrong object, or to an object
with no known extent. The dereference path was keyed by (function, argument)
rather than by the object the bytes belong to. This table is the missing
object model.

Object kinds and their extents:
  heap    exact, from the allocator model; site = PC of the allocating call
  global  exact from .symtab, else whatever the global table resolves
  stack   one object per live frame, bounded by the frames around it - the
          bound --infer-from-caller never had
  rodata  one object over .rodata, for string evidence only

Type identity is the SITE, not the object (Howard, NDSS'11): every object
allocated by the same call, or the same global, or the same local slot of the
same function's frame, is the same type. Layout evidence pools across all of
them.
"""
import bisect

HEAP, GLOBAL, STACK, RODATA = "heap", "global", "stack", "rodata"


class MemObject:
    __slots__ = ("id", "kind", "base", "size", "site", "alive")

    def __init__(self, oid, kind, base, size, site):
        self.id = oid
        self.kind = kind
        self.base = base
        self.size = size
        self.site = site
        self.alive = True

    def contains(self, addr):
        return self.base <= addr < self.base + self.size

    def __repr__(self):
        return (f"MemObject(#{self.id} {self.kind} 0x{self.base:x}+{self.size} "
                f"site={self.site!r}{'' if self.alive else ' dead'})")


class ObjectTable:
    """Interval map from address to object, plus the live stack frames.

    Heap, global and rodata objects never overlap each other (the arena is
    mapped apart from the image), so they live in one sorted list. Stack
    frames are handled separately because their bounds move with rsp.
    """

    def __init__(self):
        self._objs = {}          # id -> MemObject
        self._bases = []         # sorted bases of non-stack objects
        self._by_base = {}       # base -> MemObject (latest)
        self._next = 1
        # Live frames, innermost last: (entry_rsp, func_addr, MemObject).
        # entry_rsp points at the return address the call pushed.
        self._frames = []
        self._stack_lo = None
        self._stack_hi = None

    # ------------------------------------------------------------ registry
    def _new(self, kind, base, size, site):
        obj = MemObject(self._next, kind, base, size, site)
        self._next += 1
        self._objs[obj.id] = obj
        return obj

    def add(self, kind, base, size, site):
        """Register a heap, global or rodata object."""
        if size is None or size <= 0:
            size = 1   # malloc(0) still returns a unique, freeable pointer
        obj = self._new(kind, base, size, site)
        if base not in self._by_base:
            bisect.insort(self._bases, base)
        self._by_base[base] = obj
        return obj

    def kill(self, base):
        """free(): the object stops resolving. Its record (and site) remain."""
        obj = self._by_base.get(base)
        if obj is not None and obj.alive:
            obj.alive = False
            return obj
        return None

    def get(self, oid):
        return self._objs.get(oid)

    def objects(self):
        return list(self._objs.values())

    # ------------------------------------------------------------- frames
    def set_stack(self, lo, hi):
        self._stack_lo, self._stack_hi = lo, hi

    def push_frame(self, entry_rsp, func_addr):
        """Open the frame of a function just entered.

        Its upper bound is entry_rsp: the return address and everything above
        belong to the CALLER. That one bound is what stops a callee's
        footprint, or a caller-initialised object, from spilling into the
        caller's caller.
        """
        obj = self._new(STACK, entry_rsp, 0, None)
        self._frames.append((entry_rsp, func_addr, obj))
        return obj

    def pop_frame(self):
        if self._frames:
            _, _, obj = self._frames.pop()
            obj.alive = False
            return obj
        return None

    def frame_depth(self):
        return len(self._frames)

    def _frame_for(self, addr):
        """(index, entry_rsp, func_addr, obj) of the frame holding addr.

        Frame k spans [entry_rsp of frame k+1 + 8, entry_rsp of frame k).
        The innermost frame extends downward without a lower bound (rsp moves
        within it, plus the 128-byte red zone).
        """
        if self._stack_lo is None or not (self._stack_lo <= addr < self._stack_hi):
            return None
        frames = self._frames
        for k in range(len(frames) - 1, -1, -1):
            entry_rsp, func_addr, obj = frames[k]
            lo = frames[k + 1][0] + 8 if k + 1 < len(frames) else self._stack_lo
            if lo <= addr < entry_rsp:
                return k, entry_rsp, func_addr, obj
        return None

    # -------------------------------------------------------------- lookup
    def lookup(self, addr):
        """(MemObject, offset) for a live object containing addr, else None.

        Stack addresses resolve to their frame; the offset is then relative to
        the frame's entry rsp (negative), and the SITE of anything found there
        is (func_addr, offset) - the same local slot of the same function is
        the same type on every call.
        """
        f = self._frame_for(addr)
        if f is not None:
            _, entry_rsp, func_addr, obj = f
            return obj, addr - entry_rsp
        i = bisect.bisect_right(self._bases, addr) - 1
        if i >= 0:
            obj = self._by_base.get(self._bases[i])
            if obj is not None and obj.alive and obj.contains(addr):
                return obj, addr - obj.base
        return None

    def frame_owner(self, addr):
        """func_addr of the frame holding a stack address, else None."""
        f = self._frame_for(addr)
        return f[2] if f is not None else None

    def innermost_func(self):
        return self._frames[-1][1] if self._frames else None

    def stack_site(self, addr):
        """Type identity for an object starting at a stack address."""
        f = self._frame_for(addr)
        if f is None:
            return None
        _, entry_rsp, func_addr, _ = f
        return ("stack", func_addr, addr - entry_rsp)

    def stack_extent(self, addr):
        """Bytes from addr to the top of its frame: the most a stack object
        starting there can occupy. None off the stack."""
        f = self._frame_for(addr)
        if f is None:
            return None
        return f[1] - addr

    def site_of(self, addr):
        """Site of the object an address points INTO, with the offset.

        A pointer into the middle of a heap block is (site, offset>0): the
        same type, a field or element inside it.
        """
        f = self._frame_for(addr)
        if f is not None:
            return ("stack", f[2], addr - f[1]), 0
        r = self.lookup(addr)
        if r is None:
            return None
        obj, off = r
        return obj.site, off
