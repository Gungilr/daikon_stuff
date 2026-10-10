"""Argument detection by use-before-def.

Pure - no third-party imports, so it is unit-testable without an emulator.

A register that a function READS before ever WRITING must have been set by the
caller, so it carried an incoming argument. Only the six SysV integer argument
registers are considered, and that restriction is what makes the heuristic
sound: they are caller-saved, so unlike rbx or r12 a callee never reads one
merely to preserve it across its own body.

Two things this module exists to get right, both established by measurement
rather than from the ABI documents:

  * Capstone reports the SUB-REGISTER an instruction actually names. At -O0 an
    `int` argument arrives in rdi but is read as `edi`, and the sixth arrives in
    r9 but is read as `r9d`. Matching on "rdi" alone finds nothing and reports
    arity 0 for every integer function - a failure that looks like a precision
    win, because the output gets smaller and cleaner. Canonicalization to the
    64-bit parent is therefore load-bearing, not cosmetic.

  * Trailing dead arguments are invisible, so the count comes from the HIGHEST
    index observed rather than the set of indices observed. `stack8` in
    tests/test07.c reads its 8th argument and never touches its 7th (which is
    dead and, being a stack argument, is never spilled). A set-union rule yields
    {1..6, 8} - a hole, and arity 7. The ABI allocates argument slots
    contiguously, so observing the 8th proves the 7th exists.
"""
from .schema import MAX_STACK_PROBE

# SysV x86-64 integer argument registers, in order.
REG_ARG_ORDER = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

# SysV x86-64 passes float and double arguments in xmm0-xmm7, NUMBERED
# INDEPENDENTLY of the integer registers: in `f(int a, double b, int c)`, `a`
# is rdi, `c` is rsi and `b` is xmm0. A detector that looks only at the six
# integer registers therefore reports `float mul(float a, float b)` as taking
# NO arguments at all - measured on Daikon's FloatTest, 8 functions out of 8.
SSE_ARG_ORDER = [f"xmm{i}" for i in range(8)]

# The mnemonic that moves a float argument also states its width, which the
# register name never does: xmm0 is 128 bits whether it carries a float or a
# double. `movss`/`cvtss2sd` mean 4 bytes, `movsd`/`cvtsd2ss` mean 8.
SSE_SINGLE_OPS = {"movss", "addss", "subss", "mulss", "divss", "cvtss2sd",
                  "ucomiss", "comiss", "cvtsi2ss", "cvttss2si", "sqrtss"}
SSE_DOUBLE_OPS = {"movsd", "addsd", "subsd", "mulsd", "divsd", "cvtsd2ss",
                  "ucomisd", "comisd", "cvtsi2sd", "cvttsd2si", "sqrtsd"}

# Clobbered across a call. A caller that reads rdi AFTER a nested call is
# reading whatever the callee left behind, not an incoming argument.
CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"}

# Signedness is not visible in a value - the bits are identical - but it IS
# visible in the operations applied to one. gcc picks a different opcode for
# signed and unsigned operands:
#
#     unsigned x >> 3   ->  shr      int x >> 3   ->  sar
#     unsigned x > 100  ->  seta     int x > 100  ->  setg
#
# Verified on the corpus: big_unsigned's caller emits `shr $0x1c,%eax` on the
# returned value, which is the whole signal needed to stop sign-extending it.
UNSIGNED_OPS = {"shr", "div", "seta", "setae", "setb", "setbe", "setna",
                "setnae", "setnb", "setnbe", "ja", "jae", "jb", "jbe",
                "cmova", "cmovae", "cmovb", "cmovbe", "movzx"}
SIGNED_OPS = {"sar", "idiv", "setg", "setge", "setl", "setle", "setng",
              "setnge", "setnl", "setnle", "jg", "jge", "jl", "jle",
              "cmovg", "cmovge", "cmovl", "cmovle", "movsx", "movsxd",
              "cdq", "cqo", "cdqe", "cwde", "cltq"}


# Width in bits of each register name, keyed by its sub-register form. Tier 2
# canonicalizes `edi` to `rdi` and throws this away; tier 3 needs it back,
# because a 32-bit value sitting in a 64-bit register is the whole reason
# negative ints read back as ~4 billion.
_REG_WIDTH = {}


def _build_subreg_map():
    """Explicit (name, width) per family. Spelled out rather than derived from
    suffix rules: `dil` is 8-bit while `bpl` is 8-bit and `bp` is 16, and any
    rule compact enough to cover those is too clever to trust."""
    families = {
        "rax": [("eax", 32), ("ax", 16), ("al", 8), ("ah", 8)],
        "rbx": [("ebx", 32), ("bx", 16), ("bl", 8), ("bh", 8)],
        "rcx": [("ecx", 32), ("cx", 16), ("cl", 8), ("ch", 8)],
        "rdx": [("edx", 32), ("dx", 16), ("dl", 8), ("dh", 8)],
        "rsi": [("esi", 32), ("si", 16), ("sil", 8)],
        "rdi": [("edi", 32), ("di", 16), ("dil", 8)],
        "rbp": [("ebp", 32), ("bp", 16), ("bpl", 8)],
        "rsp": [("esp", 32), ("sp", 16), ("spl", 8)],
    }
    for n in range(8, 16):
        families[f"r{n}"] = [(f"r{n}d", 32), (f"r{n}w", 16), (f"r{n}b", 8)]

    m = {}
    for parent, kids in families.items():
        m[parent] = parent
        _REG_WIDTH[parent] = 64
        for name, width in kids:
            m[name] = parent
            _REG_WIDTH[name] = width
    return m


_SUBREG_TO_PARENT = _build_subreg_map()


def canonical_reg(name):
    """Map any sub-register to its 64-bit parent. Unknown names pass through."""
    return _SUBREG_TO_PARENT.get(name.lower(), name.lower())


def reg_width(name):
    """Width in bits of the register name AS WRITTEN. Unknown names give 64."""
    return _REG_WIDTH.get(name.lower(), 64)


def sign_extend(value, width):
    """Reinterpret the low `width` bits of an unsigned value as two's complement.

    The tracer reads whole 64-bit registers, but an `int` occupies the low 32
    bits and writes to `eax` zero-extend. So -1 arrives as 0x00000000FFFFFFFF
    and is reported as 4294967295 unless corrected here - and Daikon then infers
    `> 0` where the truth is `< 0`.

    Signedness at narrower widths is only observable through a consuming
    opcode (see `note_return_signedness`). Sign-extending is right for `int`,
    the overwhelmingly common case, and wrong for a large `unsigned` that
    nothing shifts or compares. That is a deliberate, documented trade.

    At width 64 there is no trade to make. Daikon's `int` rep-type is a signed
    64-bit long, so a value at or above 2^63 is OUTSIDE the range we declared
    and we would be relying on the consumer to wrap it for us. It does, which
    is why this went unnoticed - found by auditing our own output against our
    own samples, where `arg8 one of { -6076574518398440533L, 0 }` was reported
    for a trace that literally contains 12370169555311111083. Same bits, and an
    implicit dependency on unspecified behaviour either way.
    """
    mask = (1 << width) - 1
    v = value & mask
    if v >> (width - 1):
        v -= 1 << width
    return v


class _FuncState:
    __slots__ = ("written", "max_reg_index", "max_stack_slot", "insn_count",
                 "arg_width", "ret_width", "ret_seen", "caller_reads_rax",
                 "caller_checks", "spill", "ret_unsigned",
                 "max_sse_index", "sse_width", "ret_sse_width", "sse_spill")

    def __init__(self):
        self.written = set()
        self.max_reg_index = -1
        self.max_stack_slot = -1
        # Floating-point arguments, tracked separately because the ABI numbers
        # them separately. -1 means none seen, as for the integer registers.
        self.max_sse_index = -1
        self.sse_width = {}          # sse index -> 4 or 8 bytes
        # Width of the last xmm0 write before `ret`; None means the result is
        # not floating point. xmm0 is the SysV return register for float and
        # double exactly as rax is for integers.
        self.ret_sse_width = None
        self.sse_spill = {}          # sse index -> frame offset of its slot
        self.insn_count = 0
        # index -> width in bits, from the FIRST read of that argument. First
        # rather than widest: at -O0 the first read is the prologue spill, which
        # names the true width (`mov %edi,-0x4(%rbp)` for an int). A later
        # whole-register move would otherwise widen it to 64 and skip the sign
        # fix.
        self.arg_width = {}
        self.ret_width = None        # width of the last rax-family write
        self.ret_seen = False
        self.caller_reads_rax = False
        self.caller_checks = 0       # how many call sites we actually observed
        # index -> frame offset the -O0 prologue spills that argument to.
        # Argument registers are caller-saved and the body reuses them, so the
        # register is garbage by the time the function returns; the spill slot
        # still holds the parameter.
        self.spill = {}
        # True when a consuming instruction proved the return value unsigned.
        self.ret_unsigned = False


class ArityTracker:
    """Accumulates argument evidence per function entry address.

    Keyed by address rather than name because addresses are stable across
    stripped and symbol-bearing builds of the same binary.

    Evidence is unioned across every invocation and every --layouts run, so a
    parameter used on only one path still counts.
    """

    def __init__(self):
        self._funcs = {}

    def _state(self, func_addr):
        if func_addr not in self._funcs:
            self._funcs[func_addr] = _FuncState()
        return self._funcs[func_addr]

    def note_instruction(self, func_addr, mnemonic, reads, writes,
                         stack_slot=None):
        """Record one executed instruction.

        reads/writes are register-name iterables as Capstone reports them
        (sub-register names welcome). stack_slot, when not None, is the index of
        a stack-argument slot the instruction reads - slot 0 is [rbp+0x10].
        """
        st = self._state(func_addr)
        st.insn_count += 1

        # Reads are evaluated against the writes seen SO FAR, before this
        # instruction's own writes are applied. `add eax, edx` reads eax, and if
        # nothing has written eax yet that read is a genuine use-before-def.
        for name in reads:
            reg = canonical_reg(name)
            if reg in st.written:
                continue
            try:
                idx = REG_ARG_ORDER.index(reg)
            except ValueError:
                continue
            if idx > st.max_reg_index:
                st.max_reg_index = idx
            # First read wins - at -O0 that is the prologue spill, which names
            # the argument's true width (`mov %edi,...` for an int).
            if idx not in st.arg_width:
                st.arg_width[idx] = reg_width(name)

        # Floating-point arguments. Same use-before-def rule, separate
        # numbering, and the width comes from the mnemonic rather than the
        # register name - xmm0 is 128 bits whichever type it carries.
        base = (mnemonic or "").split()[0].lower() if mnemonic else ""
        for name in reads:
            reg = name.lower()
            if reg in st.written:
                continue
            try:
                idx = SSE_ARG_ORDER.index(reg)
            except ValueError:
                continue
            if idx > st.max_sse_index:
                st.max_sse_index = idx
            if idx not in st.sse_width:
                if base in SSE_SINGLE_OPS:
                    st.sse_width[idx] = 4
                elif base in SSE_DOUBLE_OPS:
                    st.sse_width[idx] = 8

        if stack_slot is not None and stack_slot > st.max_stack_slot:
            st.max_stack_slot = stack_slot

        for name in writes:
            canon = canonical_reg(name)
            st.written.add(canon)
            # xmm0 is the float/double return register. Last write before the
            # epilogue wins, mirroring how ret_width tracks the rax family.
            if canon == "xmm0":
                if base in SSE_SINGLE_OPS:
                    st.ret_sse_width = 4
                elif base in SSE_DOUBLE_OPS:
                    st.ret_sse_width = 8
            # The last rax-family write before `ret` carries the return value.
            # At -O0 this is always eax or rax (narrow types are computed in
            # eax and truncated by the caller), so it distinguishes a 32-bit
            # int return from a 64-bit long/pointer - which is exactly what the
            # sign correction needs.
            if canon == "rax":
                st.ret_width = reg_width(name)
                st.ret_seen = True

        # A call clobbers every caller-saved register. The clobber must NOT
        # count as a return-value write, so it happens after the loop above.
        if mnemonic == "call":
            st.written |= CALLER_SAVED

    def arity(self, func_addr):
        """Return (n_register_args, n_stack_args) by the contiguity rule."""
        st = self._funcs.get(func_addr)
        if st is None:
            return (0, 0)
        n_reg = st.max_reg_index + 1
        # The raw vector holds MAX_STACK_PROBE stack words, so arity must not
        # name a slot past it. A struct passed BY VALUE reads far beyond any
        # argument count - `baz(struct foo f)` with a 252-byte struct spans 32
        # slots for its ONE parameter - and reporting that arity was an
        # IndexError at finalize time, after a complete and correct emulation.
        # Clamping states the limit instead: slots past the probe were never
        # captured, so there is nothing to emit for them.
        n_stack = min(st.max_stack_slot + 1, MAX_STACK_PROBE)
        # The ABI only spills to the stack once all six argument registers are
        # in use, so any stack argument implies all six registers carry
        # arguments - even if some were dead and never read.
        if n_stack > 0:
            n_reg = len(REG_ARG_ORDER)
        return (n_reg, n_stack)

    def return_sse_width(self, func_addr):
        """4 or 8 if this function returns a float/double, else None."""
        st = self._funcs.get(func_addr)
        return None if st is None else st.ret_sse_width

    def sse_arity(self, func_addr):
        """How many floating-point arguments this function takes."""
        st = self._funcs.get(func_addr)
        return 0 if st is None else st.max_sse_index + 1

    def sse_width(self, func_addr, index):
        """Bytes in SSE argument `index`; 8 (double) when never established.

        Double rather than float because a `double` read as a `float` is
        garbage, while a `float` read as a `double` is at least a well-formed
        number - and -O0 promotes for varargs, making double the commoner case.
        """
        st = self._funcs.get(func_addr)
        if st is None:
            return 8
        return st.sse_width.get(index, 8)

    def note_spill(self, func_addr, index, frame_offset):
        """Record that argument `index` was spilled to [frame_base+offset].

        First spill wins: the prologue store is the one that establishes the
        parameter's home. A later store to the same slot is the program
        assigning to the parameter, which the slot will reflect anyway.
        """
        st = self._state(func_addr)
        if index not in st.spill:
            st.spill[index] = frame_offset

    def note_sse_spill(self, func_addr, index, frame_offset):
        """Record where SSE argument `index` was spilled by the prologue.

        xmm registers are caller-saved and the body reuses xmm0 for every
        arithmetic result, so at `ret` it holds the RETURN value, not the first
        argument - `floatMultiply` reported arg0 == return on every call. The
        identical problem the integer arguments had, with the identical fix.
        """
        st = self._state(func_addr)
        if index not in st.sse_spill:
            st.sse_spill[index] = frame_offset

    def sse_spill_offset(self, func_addr, index):
        """Frame offset of an SSE argument's spill slot, or None."""
        st = self._funcs.get(func_addr)
        return None if st is None else st.sse_spill.get(index)

    def spill_offset(self, func_addr, index):
        """Frame offset of an argument's spill slot, or None if never spilled."""
        st = self._funcs.get(func_addr)
        return None if st is None else st.spill.get(index)

    def arg_width(self, func_addr, index):
        """Width in bits of argument `index`; 64 when never observed."""
        st = self._funcs.get(func_addr)
        if st is None:
            return 64
        return st.arg_width.get(index, 64)

    def return_width(self, func_addr):
        """Width of the value left in rax; 64 when never observed."""
        st = self._funcs.get(func_addr)
        if st is None or st.ret_width is None:
            return 64
        return st.ret_width

    def note_return_signedness(self, func_addr, mnemonic):
        """Record signedness implied by an instruction consuming the result."""
        base = mnemonic.split()[0].lower() if mnemonic else ""
        if base in UNSIGNED_OPS:
            self._state(func_addr).ret_unsigned = True
        elif base in SIGNED_OPS:
            self._state(func_addr).ret_unsigned = False

    def return_is_unsigned(self, func_addr):
        st = self._funcs.get(func_addr)
        return bool(st and st.ret_unsigned)

    def note_caller_observation(self, func_addr, consumed):
        """Record one resolved call site: did the caller consume rax?"""
        st = self._state(func_addr)
        st.caller_checks += 1
        if consumed:
            st.caller_reads_rax = True

    def describe(self, func_addr):
        """Every conclusion about one function, for --dump-inferences.

        Read-only, and None for a function no instruction was attributed to.
        Keys are strings throughout so the result serialises as JSON unchanged.
        """
        st = self._funcs.get(func_addr)
        if st is None:
            return None
        n_reg, n_stack = self.arity(func_addr)
        return {
            "n_reg": n_reg,
            "n_stack": n_stack,
            "max_reg_index": st.max_reg_index,
            "max_stack_slot": st.max_stack_slot,
            "arg_width": {str(k): v for k, v in sorted(st.arg_width.items())},
            "sse_arity": st.max_sse_index + 1,
            "sse_width": {str(k): v for k, v in sorted(st.sse_width.items())},
            "ret_width": st.ret_width,
            "ret_seen": st.ret_seen,
            "ret_unsigned": st.ret_unsigned,
            "ret_sse_width": st.ret_sse_width,
            "caller_checks": st.caller_checks,
            "caller_reads_rax": st.caller_reads_rax,
            "spilled": sorted(st.spill),
            "sse_spilled": sorted(st.sse_spill),
            "insn_count": st.insn_count,
        }

    def returns_value(self, func_addr):
        """Void only when call sites WERE observed and none consumed rax.

        Absence of evidence is not evidence of void. The start function has no
        caller in the trace at all, so a naive default of False would strip
        `return` from main - deleting `return == 0`, which is the one invariant
        that matches Kvasir exactly.
        """
        st = self._funcs.get(func_addr)
        if st is None or st.caller_checks == 0:
            return True
        return st.caller_reads_rax

    def seen(self, func_addr):
        return func_addr in self._funcs

    def functions(self):
        return list(self._funcs)
