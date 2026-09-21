"""Signed-value correction: widths, sign extension, and return detection.

Pure - no Unicorn. Guards the defect that was latent through tiers 0-2: an
`int` occupies the low 32 bits of a register and writes to eax zero-extend, so
-1 arrives as 0x00000000FFFFFFFF and reads back as 4294967295.
"""
import pytest

from tracer.infer import ArityTracker, canonical_reg, reg_width, sign_extend

F = 0x401000


# ---- sign extension --------------------------------------------------------

@pytest.mark.parametrize("value,width,expected", [
    (0xFFFFFFFF, 32, -1),
    (0xFFFFFFFE, 32, -2),
    (0x7FFFFFFF, 32, 2147483647),      # largest positive int: must NOT flip
    (0x80000000, 32, -2147483648),     # smallest negative int
    (0, 32, 0),
    (1, 32, 1),
    (0xFF, 8, -1),
    (0x7F, 8, 127),
    (0xFFFF, 16, -1),
])
def test_sign_extend(value, width, expected):
    assert sign_extend(value, width) == expected


def test_64_bit_values_pass_through():
    """Pointers must not be sign-extended - a stack address is not negative."""
    addr = 140733194432488
    assert sign_extend(addr, 64) == addr
    assert sign_extend(0xFFFFFFFF, 64) == 4294967295


def test_sign_extend_is_idempotent_on_already_signed():
    assert sign_extend(sign_extend(0xFFFFFFFF, 32) & 0xFFFFFFFF, 32) == -1


# ---- register widths -------------------------------------------------------

@pytest.mark.parametrize("name,width", [
    ("rdi", 64), ("edi", 32), ("di", 16), ("dil", 8),
    ("rax", 64), ("eax", 32), ("ax", 16), ("al", 8), ("ah", 8),
    ("r8", 64), ("r8d", 32), ("r8w", 16), ("r8b", 8),
    ("rbp", 64), ("ebp", 32), ("bp", 16), ("bpl", 8),
])
def test_reg_width(name, width):
    assert reg_width(name) == width


def test_width_and_parent_are_independent():
    """edi maps to rdi for identity, but must still report 32 bits."""
    assert canonical_reg("edi") == "rdi"
    assert reg_width("edi") == 32
    assert reg_width("rdi") == 64


def test_unknown_register_defaults_to_64():
    assert reg_width("xmm0") == 64


# ---- argument width tracking ----------------------------------------------

def test_first_read_sets_the_width():
    """At -O0 the first read is the prologue spill, naming the true width."""
    t = ArityTracker()
    t.note_instruction(F, "mov", ["edi"], [])
    assert t.arg_width(F, 0) == 32


def test_first_read_wins_over_a_later_wider_one():
    """A later whole-register move must not widen a 32-bit argument to 64.

    Widest-wins would skip the sign correction for a genuine int.
    """
    t = ArityTracker()
    t.note_instruction(F, "mov", ["edi"], [])     # int spill
    t.note_instruction(F, "mov", ["rdi"], [])     # whole-register forward
    assert t.arg_width(F, 0) == 32


def test_pointer_argument_stays_64():
    t = ArityTracker()
    t.note_instruction(F, "mov", ["rdi"], [])
    assert t.arg_width(F, 0) == 64


def test_unobserved_argument_defaults_to_64():
    """64 means "do not touch", the safe default."""
    assert ArityTracker().arg_width(F, 3) == 64


# ---- return width ----------------------------------------------------------

def test_return_width_from_last_rax_write():
    t = ArityTracker()
    t.note_instruction(F, "mov", ["rbp"], ["rax"])   # 64-bit
    t.note_instruction(F, "add", ["edx"], ["eax"])   # 32-bit, later => wins
    assert t.return_width(F) == 32


def test_call_clobber_does_not_count_as_a_return_write():
    """The caller-saved clobber is bookkeeping, not an observed write.

    Letting it set the width would make every post-call function look 64-bit.
    """
    t = ArityTracker()
    t.note_instruction(F, "add", ["edx"], ["eax"])
    t.note_instruction(F, "call", [], [])
    assert t.return_width(F) == 32


def test_return_width_defaults_to_64():
    assert ArityTracker().return_width(F) == 64


# ---- void detection --------------------------------------------------------

def test_no_observed_caller_means_assume_returns_value():
    """Absence of evidence is not evidence of void.

    main has no caller in the trace; defaulting to void would strip its
    `return` and delete `return == 0`, the invariant that matches Kvasir.
    """
    t = ArityTracker()
    t.note_instruction(F, "mov", [], ["eax"])
    assert t.returns_value(F) is True


def test_caller_consuming_rax_means_non_void():
    t = ArityTracker()
    t.note_caller_observation(F, True)
    assert t.returns_value(F) is True


def test_caller_discarding_rax_means_void():
    t = ArityTracker()
    t.note_caller_observation(F, False)
    assert t.returns_value(F) is False


def test_one_consuming_caller_outvotes_several_discarding_ones():
    """Used anywhere means it has a return value."""
    t = ArityTracker()
    t.note_caller_observation(F, False)
    t.note_caller_observation(F, True)
    t.note_caller_observation(F, False)
    assert t.returns_value(F) is True
