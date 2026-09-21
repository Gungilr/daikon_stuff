"""Argument detection logic, driven by synthetic instruction streams.

Pure - no Unicorn, no binaries. Each test feeds the sequence of
(mnemonic, reads, writes) a real function would produce.
"""
import pytest

from tracer.schema import MAX_STACK_PROBE
from tracer.infer import (CALLER_SAVED, REG_ARG_ORDER, ArityTracker,
                          canonical_reg, sign_extend)

F = 0x401000


def run(*instructions):
    """instructions: (mnemonic, reads, writes) or (mnemonic, reads, writes, slot)."""
    t = ArityTracker()
    for insn in instructions:
        mnem, reads, writes = insn[0], insn[1], insn[2]
        slot = insn[3] if len(insn) > 3 else None
        t.note_instruction(F, mnem, reads, writes, stack_slot=slot)
    return t


# ---- sub-register canonicalization ----------------------------------------
# The single most load-bearing detail: Capstone reports the sub-register the
# instruction names, so an `int` argument in rdi appears as `edi`. Matching on
# "rdi" alone finds nothing and reports arity 0 for every integer function.

@pytest.mark.parametrize("name,parent", [
    ("rdi", "rdi"), ("edi", "rdi"), ("di", "rdi"), ("dil", "rdi"),
    ("rsi", "rsi"), ("esi", "rsi"), ("sil", "rsi"),
    ("rdx", "rdx"), ("edx", "rdx"), ("dl", "rdx"), ("dh", "rdx"),
    ("rcx", "rcx"), ("ecx", "rcx"), ("cl", "rcx"),
    ("r8", "r8"), ("r8d", "r8"), ("r8w", "r8"), ("r8b", "r8"),
    ("r9", "r9"), ("r9d", "r9"),
    ("rax", "rax"), ("eax", "rax"), ("al", "rax"), ("ah", "rax"),
    ("r15", "r15"), ("r15d", "r15"),
])
def test_canonical_reg(name, parent):
    assert canonical_reg(name) == parent


def test_canonical_reg_is_case_insensitive():
    assert canonical_reg("EDI") == "rdi"


def test_canonical_reg_passes_through_unknown():
    assert canonical_reg("xmm0") == "xmm0"


def test_arity_found_via_subregisters_only():
    """Exactly what gcc -O0 emits for six(int,int,int,int,int,int)."""
    t = run(
        ("push", ["rsp", "rbp"], ["rsp"]),
        ("mov", ["rsp"], ["rbp"]),
        ("mov", ["rbp", "edi"], []),
        ("mov", ["rbp", "esi"], []),
        ("mov", ["rbp", "edx"], []),
        ("mov", ["rbp", "ecx"], []),
        ("mov", ["rbp", "r8d"], []),
        ("mov", ["rbp", "r9d"], []),
    )
    assert t.arity(F) == (6, 0)


# ---- use before def --------------------------------------------------------

def test_read_before_write_is_an_argument():
    assert run(("mov", ["edi"], ["eax"])).arity(F) == (1, 0)


def test_write_then_read_is_not_an_argument():
    t = run(("xor", [], ["edi"]), ("mov", ["edi"], ["eax"]))
    assert t.arity(F) == (0, 0)


def test_write_via_one_subregister_covers_the_parent():
    """Writing edi zeroes the upper half of rdi; a later read is not incoming."""
    t = run(("xor", [], ["edi"]), ("mov", ["rdi"], ["rax"]))
    assert t.arity(F) == (0, 0)


def test_read_and_write_same_register_counts_as_read_first():
    """`add esi, edi` reads esi before writing it, so esi is still an argument.

    esi is arg2 and edi is arg1, so the expected arity is 2 - had this used edx
    (arg3) as the source, contiguity would correctly report 3.
    """
    assert run(("add", ["esi", "edi"], ["esi"])).arity(F) == (2, 0)


def test_callee_saved_registers_are_never_arguments():
    t = run(("push", ["rbx"], []), ("mov", ["r12", "rbp", "rsp"], ["rax"]))
    assert t.arity(F) == (0, 0)


# ---- call clobbering -------------------------------------------------------

def test_call_clobbers_caller_saved():
    """A read of rdi AFTER a nested call sees the callee's leftovers."""
    t = run(("call", [], []), ("mov", ["edi"], ["eax"]))
    assert t.arity(F) == (0, 0)


def test_argument_read_before_a_call_still_counts():
    t = run(("mov", ["edi"], ["eax"]), ("call", [], []), ("mov", ["esi"], ["eax"]))
    assert t.arity(F) == (1, 0), "pre-call read lost, or post-call read counted"


def test_caller_saved_set_covers_the_abi():
    for reg in REG_ARG_ORDER:
        assert reg in CALLER_SAVED
    assert "rbx" not in CALLER_SAVED


# ---- contiguity ------------------------------------------------------------

def test_highest_index_implies_all_lower():
    """Only arg6 (r9) is read; args 1-5 must still be reported."""
    assert run(("mov", ["r9d"], ["eax"])).arity(F) == (6, 0)


def test_hole_in_the_middle_is_filled():
    t = run(("mov", ["edi"], ["eax"]), ("mov", ["ecx"], ["eax"]))
    assert t.arity(F) == (4, 0), "arg2/arg3 unread but must be implied by arg4"


def test_trailing_dead_argument_is_not_recoverable_by_contiguity():
    """Contiguity fills holes, it cannot see past the last USED argument.

    At -O0 the prologue spill is what rescues this case, not this rule.
    """
    assert run(("mov", ["edi"], ["eax"])).arity(F) == (1, 0)


# ---- stack arguments -------------------------------------------------------

def test_stack_slot_read_implies_six_register_args():
    """The ABI only spills to the stack once all six registers are in use."""
    assert run(("mov", ["rbp"], ["eax"], 0)).arity(F) == (6, 1)


def test_highest_stack_slot_implies_all_lower():
    """stack8's dead 7th argument: only slot 1 is read, both must be reported."""
    assert run(("mov", ["rbp"], ["eax"], 1)).arity(F) == (6, 2)


def test_many_stack_slots():
    """twelve(): only the 12th argument is read."""
    assert run(("mov", ["rbp"], ["eax"], 5)).arity(F) == (6, 6)


def test_stack_arity_cannot_exceed_the_capture_window():
    """A struct passed BY VALUE reads far past any argument count.

    `baz(struct foo f)` in Daikon's own Kvasir suite takes ONE parameter, a
    252-byte struct, and reads ~32 stack slots for it. Arity must stay inside
    the raw vector: naming slot 31 was an IndexError at finalize time, after a
    complete and correct emulation. Clamping states the limit instead.
    """
    assert run(("mov", ["rbp"], ["eax"], 31)).arity(F) == (6, MAX_STACK_PROBE)


# ---- accumulation ----------------------------------------------------------

def test_evidence_unions_across_invocations():
    """A parameter used on only one path still counts."""
    t = ArityTracker()
    t.note_instruction(F, "mov", ["edi"], ["eax"])
    t.note_instruction(F, "mov", ["edx"], ["eax"])
    assert t.arity(F) == (3, 0)


def test_functions_are_tracked_independently():
    t = ArityTracker()
    t.note_instruction(0x1000, "mov", ["edi"], ["eax"])
    t.note_instruction(0x2000, "mov", ["r9d"], ["eax"])
    assert t.arity(0x1000) == (1, 0)
    assert t.arity(0x2000) == (6, 0)


def test_zero_argument_function():
    t = run(("mov", [], ["eax"]), ("ret", ["rsp"], ["rsp"]))
    assert t.arity(F) == (0, 0)


def test_unseen_function_reports_zero_not_error():
    assert ArityTracker().arity(0xdead) == (0, 0)


def test_seen_and_functions_accessors():
    t = run(("mov", ["edi"], ["eax"]))
    assert t.seen(F) and not t.seen(0xdead)
    assert t.functions() == [F]


def test_a_64_bit_value_stays_inside_the_declared_type():
    """Daikon's `int` rep-type is a SIGNED 64-bit long.

    Emitting 12370169555311111083 for a variable declared `int` puts a value
    outside the declared range into the trace and leaves the consumer to wrap
    it. Daikon does wrap it - which is how this survived - but depending on
    that is depending on unspecified behaviour. Found by auditing our own
    output against our own recorded samples.
    """
    assert sign_extend(12370169555311111083, 64) == -6076574518398440533
    assert sign_extend((1 << 64) - 1, 64) == -1
    assert sign_extend(1 << 63, 64) == -(1 << 63)
    assert sign_extend(42, 64) == 42          # small values untouched
    assert sign_extend(0x7fff00000000, 64) == 0x7fff00000000   # a stack pointer
