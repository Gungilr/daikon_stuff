"""Variable schemas: which machine slots become Daikon variables, in what order.

Pure - no third-party imports. Two consumers must agree on NUM_STACK_ARG_SLOTS
(the name list below, and the stack-read loop in emulate.py). They are kept
together here because a mismatch is silent: the writer zips names against
values, so a short list drops trailing variables without raising.
"""

# Register variable names used in the Daikon trace, in order.
# These reflect the SysV x86-64 ABI (first 6 int args in registers).
# SysV x86-64 ABI: rax holds the return value; rdi/rsi/rdx/rcx/r8/r9 hold
# the first six integer arguments. We deliberately do NOT trace rsp/rbp:
# their values are an artifact of the emulator's stack placement, not a
# property of the program, so including them only manufactures spurious
# constant invariants (rsp == <fixed base>) and noise ordering relations.
#
# Note on arity: because a stripped binary doesn't tell us how many
# arguments a function actually takes, we always trace all six arg
# registers. For a 2-arg function, rcx/r8/r9 will read whatever was left
# in them (often 0), producing facts like `rcx == 0`. That is NOT noise to
# be filtered - it is the visible symptom of tier-3's arity-blindness, and
# belongs in the capability map rather than being hidden.
#
# Arguments seven and beyond are passed on the stack. We hook the function's
# first instruction (before the prologue), so rsp points at the return
# address and stack args sit just above it: arg7 at [rsp+8], arg8 at
# [rsp+16], etc. We capture a fixed window of NUM_STACK_ARG_SLOTS of these
# as stack0, stack1, ... For a function that takes fewer args, these slots
# read whatever happens to be on the stack (saved regs / caller locals) -
# the same arity-blindness as the upper registers, not a correctness bug.
NUM_STACK_ARG_SLOTS = 4

# How many stack words to capture per sample at tier 2+. The raw vector is
# captured BEFORE arity is known and sliced down at finalize time, so the probe
# must be wider than the fixed tier-0 window - `twelve()` in tests/test10.c has
# six stack arguments and needs them all.
#
# It is also a hard CEILING on reportable stack arity, which is why it lives
# here rather than in the emulator: `infer.arity()` must not name a slot the
# raw vector has no room for. A struct passed BY VALUE reads far past any
# plausible argument count (`baz(struct foo f)` in the Kvasir suite spans 32
# slots for one parameter), and before the clamp that was an IndexError at
# finalize time, after a complete and correct emulation.
MAX_STACK_PROBE = 12

REG_VARS_X64 = [
    "rax",  # return value
    "rdi",  # arg 1
    "rsi",  # arg 2
    "rdx",  # arg 3
    "rcx",  # arg 4
    "r8",   # arg 5
    "r9",   # arg 6
] + [f"stack{i}" for i in range(NUM_STACK_ARG_SLOTS)]  # args 7, 8, ...

# 32-bit cdecl passes all arguments on the stack, so general-purpose
# registers are not a reliable view of arguments here (eax is the return
# value; fastcall would use ecx/edx). We still drop esp/ebp for the same
# stack-artifact reason as the 64-bit case. The 32-bit register snapshot
# is inherently weak - another data point for the map.
REG_VARS_X86 = [
    "eax",
    "ebx",
    "ecx",
    "edx",
]
