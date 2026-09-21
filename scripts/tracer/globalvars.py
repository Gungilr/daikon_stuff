"""Global variable recovery from a stripped binary (tier 8).

Pure - no third-party imports, so it is unit-testable without an emulator.

Why this module exists
----------------------
Measured on Daikon's own Kvasir test suite: **80.5% of everything the oracle
says is about global variables** (4462 of 5543 facts). The tracer emitted none,
which capped recall at 4% no matter how well the rest worked. Our own fixture
corpus has no globals at all, which is why the gap stayed invisible for eight
phases - and why `plans/README.md` carried a wrong justification for that long.

What survives stripping
-----------------------
`strip --strip-all` removes `.symtab`, so the NAMES are gone for good. It does
NOT remove section headers, so `.data`, `.bss` and `.rodata` still declare
exactly which address ranges hold globals. That gives the haystack; the work
here is finding the objects in it.

Two signals, neither sufficient alone:

  * **RIP-relative operands.** At -O0 gcc addresses a global as
    `mov 0x2f3a(%rip),%eax`, so the target address is computable statically.
    These mark object STARTS with high precision - on `GlobalTest` the scan
    finds 6 of 6 - but only for objects referenced by their base. An array
    touched solely as `arr[5]` yields base+20 and no base, so the scan alone
    found only 64% of DWARF's globals across the suite.

  * **Observed accesses.** Every load and store the program makes, keyed by
    address. Complete for what the run touched, but says nothing about where
    one object ends and the next begins: eighteen `int` globals and one
    `int[18]` produce identical access sets.

Combining them: RIP targets propose boundaries, accesses fill in the layout
between boundaries. Neither invents an object the other has not seen.

What still cannot be recovered
------------------------------
Two adjacent same-width globals that are never addressed by their base are
indistinguishable from a two-element array. `GlobalTest` has `globalDouble`,
`globalLong` and `globalStr` at consecutive 8-byte addresses with no padding;
only the RIP references keep them apart. When they are missing, this module
prefers to SPLIT rather than merge - see `_split_on_gaps` - because an invented
array is a wrong noun in a way that a scalar is not.
"""

# A global object is emitted as an array only if the evidence tiles it
# uniformly AND there is more than one element. A lone 4-byte access is a
# scalar `int`, not an `int[1]`, and calling it an array manufactures a
# `size(g[]) == 1` fact the oracle never states.
MIN_ARRAY_ELEMENTS = 2

# Accesses further apart than this are different objects even with no other
# evidence. gcc pads between globals, so a run of untouched bytes is a real
# signal; 16 is the largest alignment gcc routinely inserts between scalars.
MAX_INTERNAL_GAP = 16

# The largest object still treated as a single value. One machine word: an
# 8-byte `double` or pointer is a scalar, not a two-element int array, even
# when nothing in the run read it.
MAX_SCALAR_SIZE = 8


class GlobalObject:
    """One recovered global: where it is, how wide, and what shape."""

    __slots__ = ("address", "size", "width", "fields")

    def __init__(self, address, size, width=None, fields=()):
        self.address = address
        self.size = size
        self.width = width          # element width when this is an array
        self.fields = tuple(fields)  # [(offset, width)] when struct-shaped

    @property
    def is_array(self):
        return self.width is not None

    @property
    def is_scalar(self):
        return self.width is None and len(self.fields) <= 1

    @property
    def name(self):
        """Stable machine name. The scorer maps it to a DWARF name by address.

        Hex, because two globals four bytes apart must not collide, and because
        an address is the only identity a stripped binary leaves us.
        """
        return f"g_0x{self.address:x}"

    def count(self):
        return (self.size // self.width) if self.width else 0

    def __repr__(self):
        shape = (f"array[{self.count()}]x{self.width}" if self.is_array
                 else ("scalar" if self.is_scalar else f"struct{list(self.fields)}"))
        return f"<{self.name} size={self.size} {shape}>"

    def __eq__(self, other):
        return (isinstance(other, GlobalObject)
                and (self.address, self.size, self.width, self.fields)
                == (other.address, other.size, other.width, other.fields))


def _split_on_gaps(hits):
    """Break [(offset, width)] into runs separated by more than MAX_INTERNAL_GAP.

    gcc pads between globals, so a long untouched stretch is positive evidence
    of a boundary rather than merely absent evidence of contiguity.
    """
    runs, cur, end = [], [], None
    for off, w in hits:
        if end is not None and off - end > MAX_INTERNAL_GAP:
            runs.append(cur)
            cur = []
        cur.append((off, w))
        end = max(end or 0, off + w)
    if cur:
        runs.append(cur)
    return runs


def _shape(run):
    """(size, width, fields) for one contiguous run of accesses at run[0][0]."""
    base = run[0][0]
    rel = [(off - base, w) for off, w in run]
    # Drop overlaps, widest first, so a 8-byte read covering two 4-byte reads
    # wins rather than producing three fields.
    rel.sort(key=lambda ow: (ow[0], -ow[1]))
    fields, end = [], 0
    for off, w in rel:
        if off < end:
            continue
        fields.append((off, w))
        end = off + w
    size = end

    if len(fields) >= MIN_ARRAY_ELEMENTS:
        width = fields[0][1]
        expected = 0
        tiles = True
        for off, w in fields:
            if w != width or off != expected:
                tiles = False
                break
            expected += w
        if tiles:
            return size, width, ()
    return size, None, tuple(fields)


class GlobalTable:
    """Accumulates evidence, then resolves it into objects at finalize time.

    Follows the project's standing shape: capture broadly, emit narrowly.
    Boundaries and accesses arrive in any order during emulation; nothing is
    decided until `objects()` is called, because an access late in the run can
    change an object's extent.
    """

    def __init__(self, max_object_size=4096, struct_globals=False):
        self._regions = []     # [(lo, hi)] writable/readable data ranges
        self._starts = set()   # RIP-relative targets: proposed object bases
        self._widths = {}      # address -> widest access seen
        self._symbols = []     # [(addr, size)] exact extents from .symtab
        self._ptr_slots = {}   # addr -> {offsets holding a pointer-shaped value}
        self.max_object_size = max_object_size
        # Mechanism C is opt-in: measured, it did not improve shape accuracy.
        self.struct_globals = struct_globals

    # ---- evidence ----
    def add_region(self, lo, size):
        if size > 0:
            self._regions.append((lo, lo + size))

    def in_data(self, address):
        return any(lo <= address < hi for lo, hi in self._regions)

    def add_start(self, address):
        """A RIP-relative operand targeted this address."""
        if self.in_data(address):
            self._starts.add(address)

    def add_symbol(self, address, size):
        """An exact object extent from .symtab.

        This is the one fact the stripped path cannot reconstruct. An `int[18]`
        and eighteen adjacent `int`s produce identical access evidence; only a
        recorded size separates them. Present for an unstripped binary, absent
        otherwise, and the tool reports which path it took.
        """
        if size > 0 and self.in_data(address):
            self._symbols.append((address, size))

    @property
    def has_symbols(self):
        return bool(self._symbols)

    def note_access(self, address, width):
        """The program read or wrote `width` bytes at `address`."""
        if width > 0 and self.in_data(address):
            if width > self._widths.get(address, 0):
                self._widths[address] = width

    # ---- resolution ----
    def _width_for(self, addr, size):
        """(element width, was it observed?) for a symbol of known extent.

        Whether the width was OBSERVED matters as much as its value. A guessed
        width must never turn a single machine word into an array: `double
        globalDouble` is 8 bytes that nothing read, and calling it `int[2]`
        both invents a `size(g[]) == 2` fact and reports two halves of a float
        as integers.
        """
        seen = {}
        for a, w in self._widths.items():
            if addr <= a < addr + size:
                seen[w] = seen.get(w, 0) + 1
        if seen:
            return sorted(seen, key=lambda w: (-seen[w], w))[0], True
        # No evidence. A size divisible by four is assumed `int`-shaped, the
        # commonest case, but this only ever applies to objects too large to
        # be a single word.
        return (4 if size % 4 == 0 else 1), False

    def fields_within(self, addr, size):
        """[(offset, width)] observed inside [addr, addr+size), overlaps dropped."""
        hits = sorted((a - addr, w) for a, w in self._widths.items()
                      if addr <= a < addr + size)
        # Widest access at an offset wins, so an 8-byte read covering two
        # 4-byte reads is one field rather than three.
        hits.sort(key=lambda ow: (ow[0], -ow[1]))
        out, end = [], 0
        for off, w in hits:
            if off < end:
                continue
            out.append((off, min(w, size - off)))
            end = off + w
        return out

    def note_pointer_slot(self, addr, offset):
        """An 8-aligned slot inside a global holds a pointer-shaped value."""
        self._ptr_slots.setdefault(addr, set()).add(offset)

    def looks_like_a_struct(self, addr, size):
        """Positive evidence that this extent holds members of mixed kinds.

        Two signals, and the second is the one that works:

        1. **Heterogeneous access widths.** An 8-byte read at offset 0 and a
           4-byte read at offset 8 is `struct desc {int *p; int n;}`, not
           `int[4]`. Measured: too weak on its own. Statically-initialised
           structs are never written at run time, so there are no accesses to
           be heterogeneous - `static struct desc foo = {array1, 42}` produced
           no evidence at all - and an int array copied eight bytes at a time
           produces mixed widths while being a perfectly good array.

        2. **A pointer-shaped value at SOME but not all 8-aligned slots.** A
           struct holding a pointer and an int has one; an `int[150]` has none,
           because small integers are not mapped addresses. An array OF
           pointers has one in every slot, which is how it stays an array.

        Signal 2 reads the object's bytes, so the emulator feeds it in through
        `note_pointer_slot`; this module stays pure.
        """
        slots = self._ptr_slots.get(addr, set())
        if slots:
            total = size // 8
            if len(slots) < total:        # some but not all -> mixed members
                return True
            return False                  # all -> an array of pointers
        widths = {w for _, w in self.fields_within(addr, size)}
        return len(widths) > 1

    def objects_from_symbols(self):
        """Objects with exact extents, when .symtab survived."""
        out = []
        for addr, size in sorted(set(self._symbols)):
            width, observed = self._width_for(addr, size)
            fits_a_word = size <= MAX_SCALAR_SIZE
            if (self.struct_globals and size > MAX_SCALAR_SIZE
                    and self.looks_like_a_struct(addr, size)):
                out.append(GlobalObject(addr, size,
                                        fields=self.fields_within(addr, size)))
            elif fits_a_word and (not observed or width >= size):
                out.append(GlobalObject(addr, size))            # scalar
            elif size % width == 0 and size // width >= MIN_ARRAY_ELEMENTS:
                out.append(GlobalObject(addr, size, width))     # array
            else:
                out.append(GlobalObject(addr, size))            # opaque scalar
        return out

    def objects(self):
        """Recovered globals, ascending by address.

        An object is anchored at a RIP target where one exists, because that is
        the compiler telling us where the object begins. Accesses with no
        anchor below them start their own object - otherwise a global only ever
        touched at an offset would be lost entirely.
        """
        if self._symbols:
            return self.objects_from_symbols()
        if not self._widths:
            return []
        addrs = sorted(self._widths)
        anchors = sorted(a for a in self._starts if self.in_data(a))

        # Assign every access to the nearest anchor at or below it.
        groups = {}
        for a in addrs:
            below = [x for x in anchors if x <= a]
            key = below[-1] if below else a
            # An anchor too far below is a different object that we simply
            # never saw the start of; do not glue the two together.
            if a - key > self.max_object_size:
                key = a
            groups.setdefault(key, []).append((a, self._widths[a]))

        out = []
        for key in sorted(groups):
            for run in _split_on_gaps(sorted(groups[key])):
                size, width, fields = _shape(run)
                if size <= 0:
                    continue
                out.append(GlobalObject(run[0][0], size, width, fields))
        return out
