"""Struct layout recovery from access footprints (pure - no Unicorn)."""
from tracer.deref import MAX_VALUE_BYTES, FootprintTracker, decode_field

F = 0x401000


def tracker(*accesses):
    """accesses: (arg_index, offset, width) tuples."""
    t = FootprintTracker()
    for arg, off, width in accesses:
        t.note_access(F, arg, off, width)
    return t


# ---- basic merging ---------------------------------------------------------

def test_two_adjacent_fields():
    """stack_read reads offsets 0 and 4, four bytes each."""
    t = tracker((0, 0, 4), (0, 4, 4))
    assert t.layout(F, 0) == [(0, 4), (4, 4)]


def test_repeated_access_does_not_duplicate_a_field():
    t = tracker((0, 0, 4), (0, 0, 4), (0, 0, 4))
    assert t.layout(F, 0) == [(0, 4)]


def test_single_field():
    """heap_read reads only offset 0; the second field is invisible."""
    assert tracker((0, 0, 4)).layout(F, 0) == [(0, 4)]


def test_no_accesses_gives_empty_layout():
    assert FootprintTracker().layout(F, 0) == []


def test_arguments_are_tracked_independently():
    t = tracker((0, 0, 4), (1, 0, 8))
    assert t.layout(F, 0) == [(0, 4)]
    assert t.layout(F, 1) == [(0, 8)]


# ---- width conflicts -------------------------------------------------------

def test_widest_wins_at_the_same_offset():
    """A narrow access may be a partial read of a wider field.

    Opposite of the tier-3 argument-width rule, where FIRST wins because the
    -O0 prologue spill names the parameter's true width.
    """
    t = tracker((0, 0, 4), (0, 0, 8))
    assert t.layout(F, 0) == [(0, 8)]


def test_overlapping_field_is_dropped_not_split():
    """A struct cannot have overlapping members; keep the wider reading."""
    t = tracker((0, 0, 8), (0, 4, 4))
    assert t.layout(F, 0) == [(0, 8)]


def test_zero_and_negative_are_ignored():
    t = tracker((0, -4, 4), (0, 0, 0), (0, 0, 4))
    assert t.layout(F, 0) == [(0, 4)]


# ---- object-size bounding --------------------------------------------------

def test_access_is_truncated_at_the_allocation_end():
    """Never claim a field extends past what was allocated."""
    t = tracker((0, 0, 8))
    assert t.layout(F, 0, object_size=4) == [(0, 4)]


def test_access_entirely_past_the_allocation_is_dropped():
    t = tracker((0, 0, 4), (0, 16, 4))
    assert t.layout(F, 0, object_size=8) == [(0, 4)]


# ---- tail inference --------------------------------------------------------

def test_tail_inference_recovers_an_unread_field():
    """heap_read's case exactly: 4 bytes read of an 8-byte allocation.

    Without the allocation size this field is unrecoverable, which is the
    second and larger payoff from having an allocator model.
    """
    t = tracker((0, 0, 4))
    assert t.layout(F, 0, object_size=8, infer_tail=True) == [(0, 4), (4, 4)]


def test_tail_inference_is_off_by_default():
    t = tracker((0, 0, 4))
    assert t.layout(F, 0, object_size=8) == [(0, 4)]


def test_tail_inference_needs_a_known_size():
    """Stack pointers have no allocation record, so nothing can be inferred."""
    t = tracker((0, 0, 4))
    assert t.layout(F, 0, object_size=None, infer_tail=True) == [(0, 4)]


def test_tail_inference_fills_several_slots():
    t = tracker((0, 0, 4))
    assert t.layout(F, 0, object_size=16, infer_tail=True) == [
        (0, 4), (4, 4), (8, 4), (12, 4)]


def test_tail_inference_does_nothing_when_fully_observed():
    t = tracker((0, 0, 4), (0, 4, 4))
    assert t.layout(F, 0, object_size=8, infer_tail=True) == [(0, 4), (4, 4)]


def test_tail_inference_uses_the_commonest_width():
    t = tracker((0, 0, 8), (0, 8, 8))
    assert t.layout(F, 0, object_size=24, infer_tail=True) == [
        (0, 8), (8, 8), (16, 8)]


def test_tail_inference_does_not_overrun():
    """A partial slot at the end is left alone rather than claimed."""
    t = tracker((0, 0, 4))
    assert t.layout(F, 0, object_size=6, infer_tail=True) == [(0, 4)]


# ---- decoding --------------------------------------------------------------

def test_decode_little_endian_signed():
    blob = (1).to_bytes(4, "little") + (2).to_bytes(4, "little")
    assert decode_field(blob, 0, 4) == 1
    assert decode_field(blob, 4, 4) == 2


def test_decode_negative():
    blob = (-1 & 0xFFFFFFFF).to_bytes(4, "little")
    assert decode_field(blob, 0, 4) == -1


def test_decode_past_the_blob_returns_none():
    """A truncated capture must not fabricate a value."""
    assert decode_field(b"\x01\x00\x00\x00", 4, 4) is None


def test_decode_of_missing_blob_returns_none():
    assert decode_field(None, 0, 4) is None


def test_a_field_wider_than_a_machine_word_decodes_to_none():
    """An 1800-byte object is not a scalar, and no single Daikon value can hold
    it. `space` crashed in the writer on exactly this before the cap."""
    blob = bytes(2000)
    assert decode_field(blob, 0, 2000) is None
    assert decode_field(blob, 0, MAX_VALUE_BYTES) == 0      # 8 bytes is fine
    assert decode_field(blob, 0, MAX_VALUE_BYTES + 1) is None
