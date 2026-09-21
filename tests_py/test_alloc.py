"""Emulated heap allocator (pure - no Unicorn)."""
import pytest

from tracer.alloc import ALIGNMENT, Arena

BASE = 0x20000000
SIZE = 0x10000


def arena(size=SIZE):
    return Arena(BASE, size)


# ---- basic allocation ------------------------------------------------------

def test_allocation_is_inside_the_arena():
    a = arena()
    p = a.malloc(8)
    assert a.owns(p)


def test_addresses_are_aligned():
    a = arena()
    for n in (1, 7, 8, 9, 16, 17, 100):
        assert a.malloc(n) % ALIGNMENT == 0


def test_addresses_strictly_increase():
    a = arena()
    seen = [a.malloc(8) for _ in range(20)]
    assert seen == sorted(seen)
    assert len(set(seen)) == 20


def test_blocks_never_overlap():
    a = arena()
    prev_end = 0
    for n in (1, 64, 3, 200, 8):
        p = a.malloc(n)
        assert p >= prev_end
        prev_end = p + n


def test_malloc_zero_returns_a_unique_non_null_pointer():
    """glibc does this, and free() must accept the result."""
    a = arena()
    p, q = a.malloc(0), a.malloc(0)
    assert p and q and p != q
    assert a.free(p) is True


def test_negative_size_returns_null():
    assert arena().malloc(-1) == 0


# ---- non-reuse (the deliberate design choice) ------------------------------

def test_freed_memory_is_never_reissued():
    """Deliberate, and matches the oracle rather than glibc.

    Kvasir runs under Valgrind, whose allocator adds redzones and delays reuse.
    On tests/test08.c - ten malloc/free cycles of an 8-byte struct - Kvasir
    observed ten DISTINCT addresses. A recycling model would return one address
    ten times and manufacture a constant-pointer invariant the oracle does not
    report.
    """
    a = arena()
    first = a.malloc(8)
    a.free(first)
    assert a.malloc(8) != first


def test_ten_alloc_free_cycles_give_ten_distinct_addresses():
    """The exact shape of test08's loop."""
    a = arena()
    seen = []
    for _ in range(10):
        p = a.malloc(8)
        seen.append(p)
        a.free(p)
    assert len(set(seen)) == 10


# ---- free ------------------------------------------------------------------

def test_free_null_is_a_legal_noop():
    assert arena().free(0) is True


def test_double_free_reports_false_without_raising():
    """A traced program may be buggy; emulation must not abort."""
    a = arena()
    p = a.malloc(8)
    assert a.free(p) is True
    assert a.free(p) is False


def test_free_of_a_foreign_pointer_reports_false():
    assert arena().free(0xDEADBEEF) is False


def test_live_excludes_freed_blocks():
    a = arena()
    p, q = a.malloc(8), a.malloc(8)
    a.free(p)
    assert set(a.live()) == {q}


# ---- size_of: the deliverable tiers 6 and 7 consume ------------------------

def test_size_of_round_trips():
    a = arena()
    assert a.size_of(a.malloc(24)) == 24


def test_size_of_unknown_pointer_is_none():
    assert arena().size_of(0xDEADBEEF) is None


def test_size_of_survives_free():
    """A trace may still reference a freed pointer."""
    a = arena()
    p = a.malloc(24)
    a.free(p)
    assert a.size_of(p) == 24


# ---- calloc ----------------------------------------------------------------

def test_calloc_reports_the_byte_count_to_zero():
    a = arena()
    p, nzero = a.calloc(4, 8)
    assert p and nzero == 32
    assert a.size_of(p) == 32


def test_calloc_overflow_returns_null():
    a = arena()
    p, nzero = a.calloc(1 << 62, 1 << 62)
    assert p == 0 and nzero == 0


# ---- realloc ---------------------------------------------------------------

def test_realloc_growing_copies_the_old_size():
    a = arena()
    p = a.malloc(8)
    q, ncopy = a.realloc(p, 32)
    assert q and q != p
    assert ncopy == 8, "must copy only what the old block held"
    assert a.size_of(q) == 32


def test_realloc_shrinking_copies_the_new_size():
    a = arena()
    p = a.malloc(64)
    q, ncopy = a.realloc(p, 16)
    assert ncopy == 16, "must not copy past the new block"


def test_realloc_null_behaves_as_malloc():
    a = arena()
    p, ncopy = a.realloc(0, 16)
    assert p and ncopy == 0
    assert a.size_of(p) == 16


def test_realloc_frees_the_old_block():
    a = arena()
    p = a.malloc(8)
    q, _ = a.realloc(p, 32)
    assert set(a.live()) == {q}


# ---- exhaustion ------------------------------------------------------------

def test_exhaustion_returns_null_rather_than_running_past_the_arena():
    """Handing out addresses past the mapped region would let writes succeed
    silently via the lazy-map hook. Returning 0 degrades to exactly the
    pre-tier-5 behavior instead."""
    a = arena(size=64)
    assert a.malloc(32)
    assert a.malloc(32)
    assert a.malloc(32) == 0
    assert a.stats()["exhausted"] is True


def test_allocations_stay_within_bounds_up_to_exhaustion():
    a = arena(size=256)
    while True:
        p = a.malloc(16)
        if p == 0:
            break
        assert BASE <= p and p + 16 <= BASE + 256


def test_stats_counts():
    a = arena()
    p = a.malloc(8)
    a.malloc(8)
    a.free(p)
    st = a.stats()
    assert st["allocations"] == 2 and st["live"] == 1
