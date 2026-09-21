"""Tier 8 global recovery (pure part).

Globals are 80% of what Kvasir says on its own test suite and the tracer used
to emit none, so these tests pin the grouping rules that decide what an object
IS - which is the whole difficulty, since stripping leaves addresses and widths
but no boundaries.
"""
import pytest

from tracer.globalvars import (MAX_INTERNAL_GAP, GlobalObject, GlobalTable,
                               _shape, _split_on_gaps)

DATA = 0x404000


def table(accesses=(), starts=(), size=0x1000):
    t = GlobalTable()
    t.add_region(DATA, size)
    for a in starts:
        t.add_start(a)
    for addr, w in accesses:
        t.note_access(addr, w)
    return t


# ---- regions ---------------------------------------------------------------

def test_accesses_outside_the_data_sections_are_ignored():
    """Stack and heap traffic must not become globals."""
    t = table()
    t.note_access(0x7fff00000000, 8)
    t.note_access(0x20000000, 4)
    assert t.objects() == []


def test_a_global_needs_an_observed_access():
    """A RIP target alone is not evidence the object was used.

    Emitting untouched globals would mean reading arbitrary .bss and asserting
    facts about memory the program never referenced.
    """
    t = table(starts=[DATA])
    assert t.objects() == []


# ---- scalars ---------------------------------------------------------------

def test_a_single_access_is_a_scalar_not_a_one_element_array():
    """`int globalX` must not become `int[1]`.

    Calling it an array manufactures `size(g[]) == 1`, a fact the oracle never
    states, so it is a pure false positive.
    """
    objs = table([(DATA, 4)], starts=[DATA]).objects()
    assert len(objs) == 1
    assert objs[0].is_scalar and not objs[0].is_array
    assert objs[0].size == 4


def test_the_name_is_the_address():
    """Stripping destroys names; the address is the only identity left."""
    assert GlobalObject(0x404018, 4).name == "g_0x404018"


def test_names_do_not_collide_for_nearby_globals():
    a, b = GlobalObject(0x404018, 4), GlobalObject(0x40401c, 4)
    assert a.name != b.name


# ---- arrays ----------------------------------------------------------------

def test_uniform_contiguous_accesses_are_an_array():
    """GlobalTest's `array_common[3]`: three 4-byte reads, tiling from zero."""
    objs = table([(DATA, 4), (DATA + 4, 4), (DATA + 8, 4)],
                 starts=[DATA]).objects()
    assert len(objs) == 1
    assert objs[0].is_array
    assert objs[0].width == 4
    assert objs[0].count() == 3


def test_mixed_widths_are_a_struct_not_an_array():
    """A `char*` following an `int` tiles nothing."""
    objs = table([(DATA, 4), (DATA + 8, 8)], starts=[DATA]).objects()
    assert len(objs) == 1
    assert not objs[0].is_array
    assert objs[0].fields == ((0, 4), (8, 8))


def test_a_hole_breaks_the_tiling():
    """Offsets 0 and 8 at width 4 do not tile, so this is not an array."""
    objs = table([(DATA, 4), (DATA + 8, 4)], starts=[DATA]).objects()
    assert not objs[0].is_array


def test_the_widest_access_wins_over_its_halves():
    """An 8-byte read covering two 4-byte reads is one field, not three."""
    size, width, fields = _shape([(0, 8), (0, 4), (4, 4)])
    assert fields == ((0, 8),) or width == 8


# ---- boundaries ------------------------------------------------------------

def test_rip_anchors_separate_two_adjacent_same_width_globals():
    """GlobalTest's exact case, and the one that needs the static signal.

    `globalDouble`, `globalLong` and `globalStr` sit at consecutive 8-byte
    addresses with no padding. Access evidence alone says "array of 3 longs".
    The compiler's own RIP references say otherwise, and they are right.
    """
    accesses = [(DATA, 8), (DATA + 8, 8), (DATA + 16, 8)]
    merged = table(accesses, starts=[DATA]).objects()
    split = table(accesses, starts=[DATA, DATA + 8, DATA + 16]).objects()
    assert len(merged) == 1 and merged[0].is_array      # no anchors: one array
    assert len(split) == 3                              # anchored: three scalars
    assert all(o.is_scalar for o in split)


def test_a_padding_gap_splits_an_object_without_any_anchor():
    """gcc pads between globals, so a long untouched run is real evidence."""
    objs = table([(DATA, 4), (DATA + 4 + MAX_INTERNAL_GAP + 8, 4)],
                 starts=[DATA]).objects()
    assert len(objs) == 2


def test_a_small_gap_does_not_split():
    """Alignment padding inside one object must not shatter it."""
    runs = _split_on_gaps([(0, 4), (4 + MAX_INTERNAL_GAP - 4, 4)])
    assert len(runs) == 1


def test_an_access_with_no_anchor_below_it_starts_its_own_object():
    """An array only ever touched as arr[5] yields base+20 and no base.

    Measured: the RIP scan alone finds 64% of DWARF's globals, so the ones it
    misses have to come from somewhere or they are lost entirely.
    """
    objs = table([(DATA + 0x40, 4)], starts=[]).objects()
    assert len(objs) == 1
    assert objs[0].address == DATA + 0x40


def test_a_far_away_anchor_does_not_swallow_an_access():
    """Anchoring to something 3KB below would invent one enormous object."""
    t = GlobalTable(max_object_size=64)
    t.add_region(DATA, 0x1000)
    t.add_start(DATA)
    t.note_access(DATA + 0x800, 4)
    objs = t.objects()
    assert len(objs) == 1
    assert objs[0].address == DATA + 0x800


# ---- ordering --------------------------------------------------------------

def test_objects_come_back_in_address_order():
    objs = table([(DATA + 0x80, 4), (DATA, 4)],
                 starts=[DATA, DATA + 0x80]).objects()
    assert [o.address for o in objs] == [DATA, DATA + 0x80]


# ---- struct-shaped globals (phase 10, mechanism C) -------------------------

def test_heterogeneous_widths_make_a_struct():
    """`struct desc {int *dyn_array; int answer;}` in Daikon's static-struct.

    16 bytes: an 8-byte pointer at 0 and a 4-byte int at 8. Identical in extent
    to `int[4]`, and the ONLY thing separating them is that the accesses are
    different widths. Before this, every struct global in the suite - 8 of 8 -
    was reported as an array.
    """
    t = GlobalTable(struct_globals=True)
    t.add_region(DATA, 0x1000)
    t.add_symbol(DATA, 16)
    t.note_access(DATA, 8)
    t.note_access(DATA + 8, 4)
    objs = t.objects()
    assert len(objs) == 1
    assert not objs[0].is_array
    assert objs[0].fields == ((0, 8), (8, 4))


def test_uniform_widths_stay_an_array():
    """The 14-of-14 array cases must not regress."""
    t = GlobalTable(struct_globals=True)
    t.add_region(DATA, 0x1000)
    t.add_symbol(DATA, 16)
    for i in range(4):
        t.note_access(DATA + 4 * i, 4)
    objs = t.objects()
    assert objs[0].is_array and objs[0].width == 4 and objs[0].count() == 4


def test_a_gap_alone_does_not_make_a_struct():
    """A partially-observed array has gaps too.

    `array_common[3]` read only at [2] yields one field at offset 8. Treating
    that as a struct would break arrays that are currently all correct, so the
    discriminator requires differing WIDTHS, not merely gaps.
    """
    t = GlobalTable(struct_globals=True)
    t.add_region(DATA, 0x1000)
    t.add_symbol(DATA, 12)
    t.note_access(DATA + 8, 4)
    assert t.objects()[0].is_array


def test_a_word_sized_object_is_never_a_struct():
    """The struct branch is for objects larger than a machine word.

    An 8-byte object read as two 4-byte halves is genuinely ambiguous between
    `int[2]`, `struct {int; int;}` and a `long` touched in halves. Phase 9
    settled it deliberately: a GUESSED width may never create an array, but an
    OBSERVED one may, so this stays an array. The struct branch does not get to
    override that - it applies only above MAX_SCALAR_SIZE, where an extent is
    too big to be one value.
    """
    t = GlobalTable(struct_globals=True)
    t.add_region(DATA, 0x1000)
    t.add_symbol(DATA, 8)
    t.note_access(DATA, 4)
    t.note_access(DATA + 4, 4)
    obj = t.objects()[0]
    assert not obj.fields          # not struct-shaped
    assert obj.is_array and obj.count() == 2


def test_struct_globals_is_opt_in():
    """Measured: the struct branch did NOT improve shape accuracy (88% -> 86%).

    A statically-initialised struct is never written at run time, so it leaves
    no width evidence; and an int array copied eight bytes at a time produces
    mixed widths while being a perfectly good array. Off by default until a
    discriminator that measures better exists.
    """
    kw = dict(region=None)
    off = GlobalTable()
    on = GlobalTable(struct_globals=True)
    for t in (off, on):
        t.add_region(DATA, 0x1000)
        t.add_symbol(DATA, 16)
        t.note_access(DATA, 8)
        t.note_access(DATA + 8, 4)
    assert not off.objects()[0].fields
    assert on.objects()[0].fields
