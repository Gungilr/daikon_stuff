"""Array-versus-struct classification (pure - no Unicorn)."""
from tracer.deref import (decode_sequence, element_count, looks_like_array,
                          strided_access_seen, uniform_layout)

FIVE = [(0, 4), (4, 4), (8, 4), (12, 4), (16, 4)]
TWO = [(0, 4), (4, 4)]


# ---- uniform tiling (necessary, not sufficient) ----------------------------

def test_uniform_fields_report_their_width():
    assert uniform_layout(FIVE) == 4
    assert uniform_layout(TWO) == 4


def test_mixed_widths_are_not_uniform():
    assert uniform_layout([(0, 4), (4, 8)]) is None


def test_a_gap_breaks_uniformity():
    """An array is contiguous; a hole means the fields are not elements."""
    assert uniform_layout([(0, 4), (8, 4)]) is None


def test_single_field_is_not_uniform():
    assert uniform_layout([(0, 4)]) is None


def test_empty_is_not_uniform():
    assert uniform_layout([]) is None


# ---- element count ---------------------------------------------------------

def test_count_comes_from_the_allocation_size():
    """A function reading only the first two entries of a five-element array
    has a footprint covering 8 of 20 bytes; counting the footprint would say 2."""
    assert element_count(TWO, object_size=20) == 5


def test_count_falls_back_to_the_footprint_without_a_size():
    """Stack pointers have no allocation record."""
    assert element_count(FIVE, object_size=None) == 5


def test_count_is_none_when_not_uniform():
    assert element_count([(0, 4), (4, 8)], 12) is None


# ---- the discriminator -----------------------------------------------------

def test_correlated_length_makes_it_an_array():
    """sum_array(arr, 5) over a 20-byte allocation of 4-byte elements."""
    assert looks_like_array(FIVE, 20, [{5}]) is True


def test_no_integer_argument_means_no_array_claim():
    """The safe failure mode: a lone struct pointer stays a struct.

    This is what keeps stack_read, heap_read and pair_sum correctly modelled.
    """
    assert looks_like_array(TWO, 8, []) is False
    assert looks_like_array(TWO, 8, [set()]) is False


def test_an_unrelated_integer_does_not_trigger_it():
    """two_fields(p, 99): the argument exists but never equals the count."""
    assert looks_like_array(TWO, 8, [{99}]) is False


def test_the_length_must_match_on_EVERY_call():
    """Coinciding once is not evidence; it has to hold throughout."""
    assert looks_like_array(FIVE, 20, [{5}, {5}]) is True
    assert looks_like_array(FIVE, 20, [{5}, {3}]) is False


def test_extra_arguments_do_not_prevent_a_match():
    """Any argument equalling the count is enough, not all of them."""
    assert looks_like_array(FIVE, 20, [{5, 99}]) is True


def test_a_single_element_is_never_an_array():
    """Guards the coincidence where some argument happens to be 1."""
    assert looks_like_array([(0, 4)], 4, [{1}]) is False


def test_non_uniform_layout_is_never_an_array():
    assert looks_like_array([(0, 4), (4, 8)], 12, [{2}]) is False


# ---- decoding --------------------------------------------------------------

def test_decode_sequence():
    blob = b"".join(i.to_bytes(4, "little") for i in (1, 2, 3, 4, 5))
    assert decode_sequence(blob, 4, 5) == [1, 2, 3, 4, 5]


def test_decode_sequence_stops_at_the_blob_end():
    """A truncated capture yields what was actually read, never padding."""
    blob = b"".join(i.to_bytes(4, "little") for i in (1, 2))
    assert decode_sequence(blob, 4, 5) == [1, 2]


def test_decode_sequence_handles_negatives():
    blob = (-1 & 0xFFFFFFFF).to_bytes(4, "little") + (2).to_bytes(4, "little")
    assert decode_sequence(blob, 4, 2) == [-1, 2]


def test_decode_sequence_of_missing_blob_is_empty():
    assert decode_sequence(None, 4, 5) == []


# ---- strided access: the struct-vs-array discriminator ---------------------

def test_one_instruction_walking_offsets_is_an_array():
    """test13's sum_array: a single load in a loop touched 5 offsets."""
    assert strided_access_seen({0x401180: {0, 4, 8, 12, 16}})


def test_one_instruction_per_offset_is_a_struct():
    """test08's pair_t: `p->a` and `p->b` are two instructions, one offset each.

    This is the case that makes a blanket array default catastrophic - measured
    at 155 matched facts down to 98 on the fixture corpus.
    """
    assert not strided_access_seen({0x401176: {0}, 0x40117e: {4}})


def test_no_evidence_is_not_array_evidence():
    """Silence means the program never iterated, not that it is a struct."""
    assert not strided_access_seen({})
    assert not strided_access_seen(None)


def test_strided_evidence_overrides_a_missing_length_argument():
    """A loop over the object is stronger evidence than a length parameter."""
    fields = [(0, 4), (4, 4), (8, 4)]
    assert not looks_like_array(fields, 12, [])          # no signal at all
    assert looks_like_array(fields, 12, [],
                            pc_offsets={0x401180: {0, 4, 8}})
