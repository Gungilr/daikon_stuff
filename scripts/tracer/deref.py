"""Struct layout recovery from observed memory accesses.

Pure - no third-party imports, so layout inference is unit-testable without an
emulator.

A pointer argument's fields are discovered by watching which offsets the
function actually reads through it. Two things make this less obvious than it
sounds, both established by measurement:

  * The dereference does not happen through the argument register. At -O0 the
    pointer is spilled and reloaded into a scratch register first, so `rdi` is
    never dereferenced at all. Attribution has to be by VALUE - the effective
    address of the access, compared against what the argument held - which is
    done by the caller; this module only accumulates the resulting offsets.

  * Fields the function never touches are invisible. `heap_read` computes
    `p->a * 2` and never reads `b`, so a pure footprint recovers one field
    where Kvasir reports facts about two. When the allocation size is known
    (tier 5 records it) the unobserved tail can be inferred instead - that is
    what `infer_tail` does, and it is the second and larger payoff from having
    an allocator model.
"""


class GlobalAccessMap:
    """Every memory access in the trace, keyed by absolute address.

    Exists for the pointee a function never touches. `identity_ptr(int *p)
    { return p; }` dereferences nothing, and `maybe(pair_t *p)` reads only
    `p->a` - yet the CALLER initialised the object immediately before the call.
    The per-function footprint cannot see that; an address-keyed map can.

    This is how the tracer approximates what Kvasir takes from types: Kvasir
    dereferences because the declared type is a pointer, we dereference because
    something, somewhere, accessed that memory.

    Temporal aliasing is the hazard - a stack address holds different objects
    at different times - so the caller consults this only when the per-function
    footprint is EMPTY, never to override directly observed evidence, and
    always within a bound. Heap addresses are safe by construction: the arena
    never reuses a freed block.
    """

    def __init__(self):
        self._widths = {}

    def note(self, address, width):
        if width > 0 and width > self._widths.get(address, 0):
            self._widths[address] = width

    def layout_at(self, base, bound):
        """[(offset, width)] for accesses within [base, base+bound)."""
        if not base or bound <= 0:
            return []
        hits = {a - base: w for a, w in self._widths.items()
                if base <= a < base + bound}
        if not hits:
            return []
        fields, end = [], 0
        for off in sorted(hits):
            if off < end:
                continue
            fields.append((off, hits[off]))
            end = off + hits[off]
        return fields


class FootprintTracker:
    """Accumulates (offset, width) accesses per (function, argument)."""

    def __init__(self):
        self._widths = {}   # (func_addr, arg_index) -> {offset: width}

    def note_access(self, func_addr, arg_index, offset, width):
        """Record one read through an argument pointer.

        Widest wins at a given offset: a narrow access may be a partial read of
        a wider field. Note this is the OPPOSITE of the tier-3 argument-width
        rule, where the first observation wins because the -O0 prologue spill
        names the parameter's true width. Different evidence, different rule.
        """
        if offset < 0 or width <= 0:
            return
        slots = self._widths.setdefault((func_addr, arg_index), {})
        if width > slots.get(offset, 0):
            slots[offset] = width

    def observed(self, func_addr, arg_index):
        return dict(self._widths.get((func_addr, arg_index), {}))

    def layout(self, func_addr, arg_index, object_size=None, infer_tail=False):
        """Resolve accesses into a list of non-overlapping (offset, width).

        Overlaps are resolved lowest-offset-first: a field starting inside an
        already-accepted field is dropped rather than split, since a struct
        cannot have overlapping members and the wider access is the more
        likely reading.
        """
        slots = self._widths.get((func_addr, arg_index))
        if not slots:
            return []

        fields = []
        end_of_last = 0
        for offset in sorted(slots):
            if offset < end_of_last:
                continue                      # subsumed by the previous field
            width = slots[offset]
            if object_size is not None and offset + width > object_size:
                width = object_size - offset  # never read past the allocation
                if width <= 0:
                    break
            fields.append((offset, width))
            end_of_last = offset + width

        if infer_tail and object_size is not None and fields:
            fields.extend(_infer_tail(fields, end_of_last, object_size))
        return fields


def _infer_tail(fields, end_of_last, object_size):
    """Fill an allocation's unread tail with slots of the commonest width.

    `heap_read` reads 4 bytes at offset 0 of an 8-byte allocation; the
    remaining 4 bytes are a field the function simply never touched. Without
    this, every invariant about that field stays out of reach.

    A heuristic, not a deduction - the tail could be one wider member whose low
    half was read - which is why the caller gates it behind a flag.
    """
    if end_of_last >= object_size:
        return []
    counts = {}
    for _, w in fields:
        counts[w] = counts.get(w, 0) + 1
    # Commonest width, tie-broken toward the narrower one so a stray wide
    # access cannot swallow the whole tail as a single field.
    step = min(sorted(counts, key=lambda w: (-counts[w], w))[:1] or [4])
    out, pos = [], end_of_last
    while pos + step <= object_size:
        out.append((pos, step))
        pos += step
    return out


# Byte written over freshly mapped stack pages and arena allocations when
# --poison-uninitialized is on. A field still reading this pattern was never
# written by the program, so reporting a number for it would be a fabrication.
POISON_BYTE = 0xAB


def is_poison(chunk):
    return bool(chunk) and all(b == POISON_BYTE for b in chunk)


# The widest value that is a single number. Daikon's `int` rep-type is a signed
# 64-bit long, so nothing wider can be reported as one value - and an object
# wider than a machine word is not a scalar anyway. Before this cap, `space`
# had a 2000-byte global with no recovered shape, read whole with
# int.from_bytes, and the run died in the WRITER after a complete and correct
# emulation: "Exceeds the limit (4300 digits) for integer string conversion".
MAX_VALUE_BYTES = 8


def decode_field(blob, offset, width, signed=True, poisoned=False):
    """Decode one field out of captured pointee bytes.

    None when the bytes are absent, truncated, wider than one machine word, or
    - with poisoning on - still hold the fill pattern, meaning the program
    never wrote them. Valgrind reports `nonsensical` for exactly that case;
    without the check the tracer invents a value, which is the one way its
    output can be untrue rather than merely incomplete.
    """
    if blob is None or offset + width > len(blob):
        return None
    if width > MAX_VALUE_BYTES:
        return None
    chunk = blob[offset:offset + width]
    if poisoned and is_poison(chunk):
        return None
    return int.from_bytes(chunk, "little", signed=signed)


# --- array-versus-struct ----------------------------------------------------

def uniform_layout(fields):
    """Element width if the fields tile the object uniformly from 0, else None.

    Necessary but nowhere near sufficient for an array: a struct of two ints
    tiles exactly as an array of two ints does. Used only as a precondition.
    """
    if len(fields) < 2:
        return None
    width = fields[0][1]
    expected = 0
    for offset, w in fields:
        if w != width or offset != expected:
            return None
        expected += w
    return width


def element_count(fields, object_size=None):
    """How many elements the pointee holds, or None.

    Prefers the allocation size: a function that reads only the first two
    entries of a five-element array has a footprint covering 8 of 20 bytes, and
    counting from the footprint would report 2.
    """
    width = uniform_layout(fields)
    if width is None:
        return None
    if object_size is not None and object_size >= width:
        return object_size // width
    return len(fields)


def observed_widths(fields):
    """Access widths seen, commonest first."""
    counts = {}
    for _, w in fields:
        counts[w] = counts.get(w, 0) + 1
    return sorted(counts, key=lambda w: (-counts[w], w))


def array_width_from_allocation(fields, call_records):
    """Element width if length x width == allocation size on EVERY call.

    The second array discriminator, for pointees whose footprint does not tile.
    `varying_len(int *arr, int n)` reads only `arr[n-1]`, giving offsets 8 and
    16 across two calls - non-contiguous, so uniform_layout declines. But the
    allocation size and the length argument agree exactly on both calls:

        n = 5, allocation 20, width 4  ->  5 * 4 == 20
        n = 3, allocation 12, width 4  ->  3 * 4 == 12

    That is arguably stronger evidence of an array than contiguous tiling, and
    it needs no footprint coverage at all.

    `call_records` is [(allocation_size_or_None, {int argument values})] per
    observed call. Per-call rather than aggregated: the sizes and lengths vary
    together, and aggregating loses the pairing - for varying_len the minimum
    size is 12 while one call had n = 5, so an aggregated check fails.
    """
    widths = observed_widths(fields)
    if not widths or not call_records:
        return None
    usable = [(size, ints) for size, ints in call_records if size]
    if not usable:
        return None
    for w in widths:
        if w <= 0:
            continue
        if all(size % w == 0 and (size // w) in ints and size // w >= 2
               for size, ints in usable):
            return w
    return None


def strided_access_seen(pc_offsets):
    """True when ONE instruction touched two or more offsets in the object.

    The only dynamic signal that separates `struct {int a, b;}` from `int[2]`,
    which are identical in extent, offsets and widths. `p->a; p->b` compiles to
    two instructions each at a constant displacement; `arr[i]` in a loop is one
    instruction walking many offsets.

    Measured on the corpora before being built:

        test08  pair_t struct   2 instructions, 1 offset each
        test13  sum_array       1 instruction, 5 offsets
        test13  two_fields      2 instructions, 1 offset each

    Positive evidence only. Silence means the program never iterated the
    object, not that it is a struct - a caller-initialised array reads one
    element per instruction and looks exactly like a struct from here.
    """
    return any(len(offs) >= 2 for offs in (pc_offsets or {}).values())


def looks_like_array(fields, object_size, candidate_lengths,
                     tile_implies_array=False, pc_offsets=None):
    """True when the pointee should be modelled as a sequence, not a struct.

    `int p[2]` and `struct {int a, b;}` are genuinely indistinguishable from
    access patterns - same offsets, same widths - so no heuristic separates
    them and pretending otherwise would be false precision. What IS observable
    is the dominant C idiom: an array parameter travels with its length.

    `candidate_lengths` is, per observed call, the set of integer argument
    values seen at that call. An array is claimed only when some argument
    equals the element count on EVERY call, which keeps the failure mode safe:
    no length argument means no array claim, so a lone struct pointer stays a
    struct.

    A fixed-size array passed without a length is modelled as a struct.

    That was called "a stated limit, not a wrong guess" for eight phases, and
    measurement says otherwise: in SCORING terms it is the most expensive
    default available. `returnIntSum(int a, int* b)` over a 6-element stack
    array emits six `.offK` facts that match nothing AND loses the one real
    `b[] == [...]` - seven points of damage for one decision. Emitting nothing
    would cost one; emitting the array form costs nothing when it is right.

    `tile_implies_array` switches that default: a footprint that tiles
    uniformly into 2+ equal elements is called an array even with no length
    argument to corroborate it.
    """
    count = element_count(fields, object_size)
    if count is None or count < 2:
        return False
    # Direct evidence beats the length heuristic and beats any default: one
    # instruction that walked several offsets IS an iteration over elements.
    if strided_access_seen(pc_offsets):
        return True
    if not candidate_lengths:
        return bool(tile_implies_array)
    if tile_implies_array:
        return True
    return all(count in lengths for lengths in candidate_lengths)


def decode_sequence(blob, width, count, signed=True, poisoned=False):
    """Decode `count` elements of `width` bytes, stopping at the blob's end."""
    out = []
    for i in range(count):
        v = decode_field(blob, i * width, width, signed=signed,
                         poisoned=poisoned)
        if v is None:
            break
        out.append(v)
    return out
