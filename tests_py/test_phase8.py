"""Phase 8 recovery mechanisms (pure parts).

Each of these was planned only after checking the signal against a real binary,
so the tests below encode measured behaviour rather than assumed behaviour.
"""
from tracer.deref import (POISON_BYTE, GlobalAccessMap,
                          array_width_from_allocation, decode_field,
                          decode_sequence, is_poison, observed_widths)
from tracer.infer import SIGNED_OPS, UNSIGNED_OPS, ArityTracker

F = 0x401000


# ---- C: array detection via allocation size --------------------------------

def test_length_times_width_equals_allocation():
    """varying_len's exact case: a footprint that does not tile.

    It reads only arr[n-1], giving offsets 8 and 16 across two calls, so the
    uniform-tiling discriminator declines. But n * 4 equals the allocation on
    both calls, which is arguably stronger evidence of an array.
    """
    fields = [(8, 4), (16, 4)]
    calls = [(20, {5}), (12, {3})]
    assert array_width_from_allocation(fields, calls) == 4


def test_unrelated_integer_does_not_imply_an_array():
    """two_fields(p, 99): the int exists but never equals the element count."""
    assert array_width_from_allocation([(0, 4), (4, 4)], [(8, {99})]) is None


def test_every_call_must_agree():
    """Coinciding on one call is not evidence."""
    assert array_width_from_allocation([(0, 4)], [(20, {5}), (12, {99})]) is None


def test_no_allocation_size_means_no_claim():
    """Stack arrays have no allocation record, so this discriminator abstains."""
    assert array_width_from_allocation([(0, 4)], [(None, {5})]) is None


def test_single_element_is_never_an_array():
    assert array_width_from_allocation([(0, 4)], [(4, {1})]) is None


def test_observed_widths_orders_by_frequency():
    assert observed_widths([(0, 4), (4, 4), (8, 8)])[0] == 4


# ---- B: global access map --------------------------------------------------

def test_global_map_records_by_address():
    """For the pointee a callee never touches but the caller initialised."""
    g = GlobalAccessMap()
    g.note(0x1000, 4)
    g.note(0x1004, 4)
    assert g.layout_at(0x1000, 8) == [(0, 4), (4, 4)]


def test_global_map_widest_access_wins():
    g = GlobalAccessMap()
    g.note(0x1000, 4)
    g.note(0x1000, 8)
    assert g.layout_at(0x1000, 8) == [(0, 8)]


def test_global_map_respects_its_bound():
    """The bound is what stops a stack lookup swallowing neighbouring locals -
    measured over-reach on identity_ptr is why the unbounded form is opt-in."""
    g = GlobalAccessMap()
    g.note(0x1000, 4)
    g.note(0x1100, 4)
    assert g.layout_at(0x1000, 8) == [(0, 4)]


def test_global_map_drops_overlaps():
    g = GlobalAccessMap()
    g.note(0x1000, 8)
    g.note(0x1004, 4)
    assert g.layout_at(0x1000, 16) == [(0, 8)]


def test_global_map_empty_for_unknown_address():
    assert GlobalAccessMap().layout_at(0x1000, 64) == []
    assert GlobalAccessMap().layout_at(0, 64) == []


# ---- E: definedness poisoning ----------------------------------------------

def test_poison_pattern_is_detected():
    assert is_poison(bytes([POISON_BYTE]) * 4)


def test_partially_written_bytes_are_not_poison():
    assert not is_poison(bytes([POISON_BYTE, POISON_BYTE, 0, POISON_BYTE]))


def test_poisoned_field_decodes_to_none():
    """Valgrind reports `nonsensical` for memory the program never wrote.

    Without this the tracer reports a number for it, which is the one way its
    output can be untrue rather than merely incomplete.
    """
    blob = bytes([POISON_BYTE]) * 8
    assert decode_field(blob, 0, 4, poisoned=True) is None


def test_poison_is_ignored_when_the_flag_is_off():
    blob = bytes([POISON_BYTE]) * 4
    assert decode_field(blob, 0, 4, poisoned=False) is not None


def test_real_values_survive_poison_checking():
    blob = (7).to_bytes(4, "little") + bytes([POISON_BYTE]) * 4
    assert decode_field(blob, 0, 4, poisoned=True) == 7
    assert decode_field(blob, 4, 4, poisoned=True) is None


def test_sequence_stops_at_poison():
    blob = (1).to_bytes(4, "little") + bytes([POISON_BYTE]) * 4
    assert decode_sequence(blob, 4, 2, poisoned=True) == [1]


# ---- A: signedness from consuming operations -------------------------------

def test_logical_shift_implies_unsigned():
    """Verified on the corpus: big_unsigned's caller emits `shr` on the result."""
    t = ArityTracker()
    t.note_instruction(F, "mov", [], ["eax"])
    t.note_return_signedness(F, "shr")
    assert t.return_is_unsigned(F) is True


def test_arithmetic_shift_implies_signed():
    t = ArityTracker()
    t.note_return_signedness(F, "sar")
    assert t.return_is_unsigned(F) is False


def test_unsigned_and_signed_comparisons_are_distinguished():
    u, s = ArityTracker(), ArityTracker()
    u.note_return_signedness(F, "seta")     # set-if-above: unsigned
    s.note_return_signedness(F, "setg")     # set-if-greater: signed
    assert u.return_is_unsigned(F) is True
    assert s.return_is_unsigned(F) is False


def test_unknown_opcode_leaves_the_signed_default():
    """A value never shifted, compared or widened carries no signal."""
    t = ArityTracker()
    t.note_return_signedness(F, "add")
    assert t.return_is_unsigned(F) is False


def test_opcode_tables_do_not_overlap():
    assert not (UNSIGNED_OPS & SIGNED_OPS)
