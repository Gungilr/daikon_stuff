"""Value classification against the emulated address space (pure)."""
from tracer.memmap import POINTER, SCALAR, MemoryMap, classify_slot

STACK_LO, STACK_SIZE = 0x7fff00000000, 0x100000
IMAGE_LO, IMAGE_SIZE = 0x400000, 0x2000


def _map():
    m = MemoryMap()
    m.add_region(IMAGE_LO, IMAGE_SIZE, "image")
    m.add_region(STACK_LO, STACK_SIZE, "stack")
    return m


def test_value_inside_stack_is_pointer():
    assert _map().classify(STACK_LO + 0x800) == POINTER


def test_value_inside_image_is_pointer():
    assert _map().classify(IMAGE_LO + 0x10) == POINTER


def test_region_boundaries_are_half_open():
    m = _map()
    assert m.classify(STACK_LO) == POINTER                  # first byte
    assert m.classify(STACK_LO + STACK_SIZE - 1) == POINTER  # last byte
    assert m.classify(STACK_LO + STACK_SIZE) == SCALAR       # one past the end
    assert m.classify(STACK_LO - 1) == SCALAR


def test_small_integers_are_scalars():
    """Zero is excluded: it is NULL, a distinct verdict. See
    test_null_has_its_own_verdict."""
    m = _map()
    for v in (1, 5, 42, 4095):
        assert m.classify(v) == SCALAR


def test_null_is_not_a_pointer():
    """Null carries no address, so it can never make a slot a pointer on its
    own. It is not a SCALAR either - see test_null_has_its_own_verdict for why
    that distinction matters."""
    assert _map().classify(0) != POINTER


def test_empty_map_classifies_everything_scalar():
    assert MemoryMap().classify(0x7fff00000000) == SCALAR


def test_zero_size_region_is_ignored():
    m = MemoryMap()
    m.add_region(0x1000, 0, "empty")
    assert m.classify(0x1000) == SCALAR


def test_region_of_reports_the_kind():
    m = _map()
    assert m.region_of(STACK_LO + 8) == "stack"
    assert m.region_of(IMAGE_LO + 8) == "image"
    assert m.region_of(0x10) is None


# ---- slot aggregation ------------------------------------------------------

def test_slot_is_pointer_only_if_every_sample_agreed():
    assert classify_slot([POINTER, POINTER]) == POINTER


def test_one_scalar_sighting_demotes_the_slot():
    """A register reused for a pointer and a counter is not safely a pointer."""
    assert classify_slot([POINTER, SCALAR, POINTER]) == SCALAR


def test_unobserved_slot_is_scalar():
    assert classify_slot([]) == SCALAR


# ---- null is neutral, not scalar (review 2026-09-17, B1) -------------------

def test_null_has_its_own_verdict():
    """It used to be SCALAR, justified by the malloc stub returning 0 for every
    heap allocation. Tier 5 replaced the stub with a real allocator, so a null
    argument now means the program genuinely passed NULL."""
    from tracer.memmap import NULL
    assert _map().classify(0) == NULL


def test_null_does_not_demote_a_pointer_slot():
    """A function called once with a valid pointer and once with NULL still
    takes a pointer. Treating NULL as disqualifying cost the pointee for EVERY
    call to that function, not just the null one."""
    from tracer.memmap import NULL
    assert classify_slot([POINTER, NULL]) == POINTER
    assert classify_slot([NULL, POINTER]) == POINTER


def test_a_real_scalar_still_demotes():
    """A register reused for a pointer and a counter is not safely a pointer."""
    from tracer.memmap import NULL
    assert classify_slot([POINTER, SCALAR]) == SCALAR
    assert classify_slot([POINTER, NULL, SCALAR]) == SCALAR


def test_all_null_is_not_a_pointer():
    """No positive evidence. This is what keeps tier-3 heap arguments scalar
    while the allocator is absent and every heap pointer reads as 0."""
    from tracer.memmap import NULL
    assert classify_slot([NULL, NULL]) == SCALAR
