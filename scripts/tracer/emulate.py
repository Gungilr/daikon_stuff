"""Unicorn-based emulation driver.

The only module (besides elfload.py) that touches third-party binary-analysis
libraries. Keeping unicorn and capstone confined here is what lets writer.py,
schema.py, and the phase-2/3 inference modules be unit-tested without an
emulator - see tests_py/test_purity.py.

`discover_main_via_emulation` lives here rather than in elfload.py, where it
would fit topically, because it builds its own throwaway Uc sandbox.
"""
from __future__ import print_function

import json
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    from unicorn import (
        Uc, UcError,
        UC_ARCH_X86, UC_MODE_32, UC_MODE_64,
        UC_HOOK_CODE,
        UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED,
    )
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_REG_RBP
    import unicorn.x86_const as UC_X86_CONST
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RIP,
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_EBP, UC_X86_REG_ESP, UC_X86_REG_EIP,
        UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
        UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7,
    )
except ImportError as e:
    print(f"[!] Missing dependency: {e}", file=sys.stderr)
    print("    Install with: pip install unicorn capstone", file=sys.stderr)
    sys.exit(1)

from .alloc import Arena
from .globalvars import GlobalTable
from .deref import (POISON_BYTE, FootprintTracker, GlobalAccessMap,
                    array_width_from_allocation,
                    decode_field, decode_sequence, element_count,
                    looks_like_array, uniform_layout)
from .elfload import (DEFAULT_EXCLUDED, data_sections, data_symbols,
                      find_functions, resolve_plt_stubs)
from .infer import (REG_ARG_ORDER, SSE_ARG_ORDER, ArityTracker,
                    canonical_reg, sign_extend)
from .memmap import NULL, POINTER, SCALAR, MemoryMap, classify_slot
from .schema import (MAX_STACK_PROBE, NUM_STACK_ARG_SLOTS, REG_VARS_X64,
                     REG_VARS_X86)
from .writer import NONSENSICAL, DaikonTraceWriter, VarSpec, legacy_specs

# Allocator functions the tier-5 model intercepts. printf and friends stay
# generically skipped - modelling output has no bearing on invariants.
ALLOCATORS = ("malloc", "calloc", "realloc", "free")

# Library functions modelled in Python rather than executed, joining the same
# PLT-interception table the allocators use. Kept minimal on purpose: measured
# across the blocked programs in Daikon's suite, `tcas` needs only `atoi`, and
# `replace` only `fgets`, so "model libc" is a far smaller job than it sounds.
#
# `exit` is here for correctness, not reach: an unmodelled call returns 0 and
# execution CONTINUES, so an input that lands on an error path would run
# through code the real program never reaches and every later sample would be
# fiction. A mutator hits error paths constantly, which makes this load-bearing
# for fuzzing rather than a nicety.
LIBC_STUBS = ("atoi", "atol", "exit", "_exit", "abort")

# argv lives on its own page, deliberately not on the stack: --layouts shifts
# the stack base per run and must not land on the argument strings.
ARGV_BASE = 0x30000000
ARGV_SIZE = 0x4000

# SysV x86-64 floating-point argument registers, in order. Parallel to
# REG_ARG_ORDER in infer.py and numbered independently of it: in
# `f(int a, double b, int c)`, a is rdi, c is rsi and b is xmm0.
SSE_REGS = (UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3,
            UC_X86_REG_XMM4, UC_X86_REG_XMM5, UC_X86_REG_XMM6, UC_X86_REG_XMM7)

# How far past a pointer to attribute reads, and how many pointee bytes to
# capture, when no allocation record exists (stack and global pointers).
# Deliberately small: an over-wide window swallows accesses to neighbouring
# locals and invents struct fields that do not exist.
DEREF_WINDOW = 64

# Byte offset added to --stack-base for each successive --layouts run.
# Only needs to be nonzero for two layouts' addresses to differ - see the
# --layouts help text for why that alone is enough to break invariants that
# only held because of one fixed memory layout.
LAYOUT_STRIDE = 0x1000000  # 16 MiB, page-aligned


def discover_main_via_emulation(segments, is_64bit, entry_point,
                                stack_base, stack_size, log):
    """Recover main()'s address from a stripped binary by emulating _start.

    On the SysV x86-64 ABI, the C runtime's _start loads main's address into
    RDI immediately before `call __libc_start_main`. We emulate forward from
    the entry point in a throwaway sandbox, stop at the first CALL instruction,
    and read RDI - regardless of which encoding the runtime used to load it
    (mov edi,imm for -no-pie; lea rdi,[rip+disp] for PIE).

    This runs entirely inside Unicorn; the target's code is never executed
    natively, so it stays safe for untrusted binaries. Returns main's address,
    or None if recovery fails.

    Assumes a standard dynamically-linked glibc layout, where the first call
    out of _start is __libc_start_main. Static linking or a non-glibc runtime
    may not match - use --start-addr in that case.
    """
    if not is_64bit:
        # 32-bit crt passes main on the stack, not in a register - unsupported.
        log.verbose("  main-recovery: only supported for x86-64")
        return None

    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
    except UcError as e:
        log.verbose(f"  main-recovery: could not create emulator: {e}")
        return None

    page = 0x1000
    for seg in segments:
        vaddr_a = (seg['vaddr'] // page) * page
        end_a = ((seg['vaddr'] + seg['memsz'] + page - 1) // page) * page
        try:
            mu.mem_map(vaddr_a, end_a - vaddr_a)
            mu.mem_write(seg['vaddr'], seg['data'])
        except UcError:
            pass

    try:
        mu.mem_map(stack_base, stack_size)
    except UcError:
        pass
    mu.reg_write(UC_X86_REG_RSP, stack_base + stack_size - page)

    cs = Cs(CS_ARCH_X86, CS_MODE_64)
    result = {"main": None}

    def on_code(uc, address, size, user_data):
        try:
            code = uc.mem_read(address, size)
        except UcError:
            uc.emu_stop()
            return
        for insn in cs.disasm(code, address):
            if insn.mnemonic == "call":
                # RDI holds main's address at the __libc_start_main call.
                result["main"] = uc.reg_read(UC_X86_REG_RDI)
                uc.emu_stop()
            break

    def on_unmapped(uc, access, addr, size, value, user_data):
        pg = (addr // page) * page
        try:
            uc.mem_map(pg, page)
            uc.mem_write(pg, b"\x00" * page)
            return True
        except UcError:
            return False

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
        on_unmapped,
    )

    try:
        mu.emu_start(entry_point, entry_point + 0x1000, count=200)
    except UcError as e:
        log.verbose(f"  main-recovery: emulation error: {e}")

    main_addr = result["main"]
    if main_addr is None:
        log.verbose("  main-recovery: no call reached from entry point")
        return None

    # Sanity: main should land inside an executable segment.
    in_exec = any(
        (seg["flags"] & 0x1) and seg["vaddr"] <= main_addr < seg["vaddr"] + seg["memsz"]
        for seg in segments
    )
    if not in_exec:
        log.verbose(f"  main-recovery: RDI=0x{main_addr:x} not in an exec segment")
        return None

    return main_addr


class Tracer:
    def __init__(self, args, log):
        self.args = args
        self.log = log
        self.functions = {}
        self.is_64bit = True
        self.entry_point = 0
        self.segments = []
        self.call_stack = []
        self.pending = []           # buffered samples; schema decided at finalize
        self.arity = ArityTracker()
        self.memmap = MemoryMap()
        self.slot_values = {}       # (func_addr, raw_index) -> running verdict
        self._pending_rax_watch = None   # (callee_addr, insns_remaining)
        self.arena = None
        self._layout_index = 0
        self.alloc_stubs = {}       # PLT stub address -> allocator name
        self.libc_stubs = {}        # PLT stub address -> modelled libc name
        self.current_argv = []      # argv for the run in progress
        self._exited = False        # did this run call exit()?
        self.footprints = FootprintTracker()
        self.global_access = GlobalAccessMap()
        # Tier 8. Evidence about global variables accumulates here all run and
        # is resolved into objects at finalize time, because an access late in
        # the trace can change an object's extent.
        self.global_table = GlobalTable(
            struct_globals=getattr(args, "struct_globals", False))
        self.global_objects = []
        # Snapshots of the data sections, one per sample, deduplicated: globals
        # rarely change, so a 10000-sample run over an unchanging 8KB region
        # stores one copy rather than 80MB of identical bytes.
        self._gsnap_pool = {}
        # Tier 10 / mechanism B: a global that HOLDS a pointer is a root for
        # dereference, exactly as a pointer argument is. 65 of the 85 globals
        # in the Kvasir suite are pointer-shaped and were printed as integers.
        # func_addr -> {addresses in the data sections it read or wrote}.
        # Kvasir cannot compute this (DWARF says a global EXISTS, not who uses
        # it) which is why its authors switch globals off wholesale on bc. We
        # observe every access, so we can attribute them.
        self.global_touch = {}
        self.global_pointer = {}      # global address -> a pointer it held
        # (func, slot) -> {instruction pc: {offsets it touched}}
        self.access_pcs = {}
        self.global_pointee_size = {}  # global address -> allocation size
        self.slot_pointer = {}      # (func_addr, raw_slot) -> a pointer it held
        self.pointee_size = {}      # (func_addr, raw_index) -> allocation size
        self.int_arg_values = {}    # func_addr -> [ {int values seen at a call} ]
        # (func_addr, raw_slot) -> [(allocation_size|None, {int args})] per call.
        # Per-call rather than aggregated: for varying_len the sizes (20, 12)
        # and lengths (5, 3) vary TOGETHER, and aggregating loses the pairing.
        self.call_records = {}
        self.insn_count = 0
        self._layout_insn_count = 0
        self.skipped_calls = 0
        # Observation only, for --dump-inferences: nothing below changes what
        # the tracer emits. Every PLT stub name (not just the modelled ones),
        # each skipped call by target, and where each skipped INDIRECT call
        # was really going - a function pointer into the program is skipped
        # like a library call, and this is how often that happens.
        self.plt_names = {}         # PLT stub address -> imported name
        self.skipped_by_target = {}  # label -> count
        self.indirect_calls = {}    # (pc, resolved target) -> count
        self.hit_insn_limit = False
        # A `ret` whose return address is not the one saved at entry: the
        # signature of a tail call or longjmp breaking ENTER/EXIT pairing.
        self.ret_mismatches = 0
        self.json_f = None
        self.dtrace = None
        self.mu = None
        self.cs = None
        self.var_names = []
        self.resolved_start_addr = None

    # ---- Filtering ----
    def _filter_functions(self, functions):
        include = set(self.args.include.split(',')) if self.args.include else None
        exclude_extra = set(self.args.exclude.split(',')) if self.args.exclude else set()
        out = {}
        for addr, name in functions.items():
            if name in exclude_extra:
                continue
            if include is not None and name not in include:
                continue
            out[addr] = name
        return out

    # ---- Setup ----
    def _setup_memory(self, stack_base=None):
        self.log.info("[+] Setting up memory map...")
        mode = UC_MODE_64 if self.is_64bit else UC_MODE_32
        self.mu = Uc(UC_ARCH_X86, mode)

        for seg in self.segments:
            page = 0x1000
            vaddr_a = (seg['vaddr'] // page) * page
            end = seg['vaddr'] + seg['memsz']
            end_a = ((end + page - 1) // page) * page
            size_a = end_a - vaddr_a
            try:
                self.mu.mem_map(vaddr_a, size_a)
                self.mu.mem_write(seg['vaddr'], seg['data'])
                self.log.verbose(f"  Mapped: 0x{vaddr_a:x} - 0x{vaddr_a + size_a:x}")
            except UcError as e:
                self.log.error(f"Mapping failed at 0x{seg['vaddr']:x}: {e}")

        # Stack
        stack_addr = self.args.stack_base if stack_base is None else stack_base
        stack_size = self.args.stack_size
        self.mu.mem_map(stack_addr, stack_size)
        if getattr(self.args, "poison_uninitialized", False):
            # Fresh pages read as zero in Unicorn, so an uninitialised local
            # looks like a real 0. Filling with a pattern makes "never written"
            # detectable, which is what Valgrind reports as nonsensical.
            self.mu.mem_write(stack_addr, bytes([POISON_BYTE]) * stack_size)
        stack_top = stack_addr + stack_size - 0x1000

        if self.is_64bit:
            self.mu.reg_write(UC_X86_REG_RSP, stack_top)
            self.mu.reg_write(UC_X86_REG_RBP, stack_top)
            # With no --argv, reproduce the pre-phase-12 registers EXACTLY.
            # Mapping the argv page and pointing rsi at it changes rsi at
            # main:::ENTER and adds a region the pointer classifier can see, so
            # doing it unconditionally moved 15 golden files. Program input is
            # opt-in like every other capability here.
            if self.current_argv:
                argc, argv_ptr = self._setup_argv()
            else:
                argc, argv_ptr = 1, stack_top - 0x100
            self.mu.reg_write(UC_X86_REG_RDI, argc)
            self.mu.reg_write(UC_X86_REG_RSI, argv_ptr)
            self.mu.reg_write(UC_X86_REG_RDX, stack_top - 0x200)
        else:
            self.mu.reg_write(UC_X86_REG_ESP, stack_top)
            self.mu.reg_write(UC_X86_REG_EBP, stack_top)

        # Live address space, for value classification. Rebuilt per layout:
        # --layouts relocates the stack, so a value that is a stack pointer in
        # one layout falls outside that range in the next. Classification must
        # use the map that was live when the sample was taken.
        self.memmap = MemoryMap()
        for seg in self.segments:
            self.memmap.add_region(seg['vaddr'], seg['memsz'], "image")
        self.memmap.add_region(stack_addr, stack_size, "stack")

        if self._globals_enabled() and not self.global_table._regions:
            # Section headers survive `strip --strip-all`, so these ranges are
            # available even though the names in them are not. Added once, not
            # per layout: --layouts relocates the stack, never the image.
            for name, addr, size in data_sections(self.args.binary):
                self.global_table.add_region(addr, size)
                self.log.verbose(f"  data section {name} "
                                 f"0x{addr:x} +{size}")
            # Symbols give exact extents, which no dynamic signal can recover:
            # an int[18] and eighteen adjacent ints produce identical access
            # evidence. Used when present, exactly as function discovery uses
            # .symtab, and --scan-prologues forces the stripped path for both.
            if not self.args.scan_prologues:
                for name, addr, size in data_symbols(self.args.binary):
                    self.global_table.add_symbol(addr, size)
                    self.log.verbose(f"  global symbol {name} "
                                     f"0x{addr:x} +{size}")

        if self._alloc_enabled():
            self._setup_arena(stack_addr, stack_size)

        cs_mode = CS_MODE_64 if self.is_64bit else CS_MODE_32
        self.cs = Cs(CS_ARCH_X86, cs_mode)
        # Operand/register detail is needed only for tier 2+ argument
        # detection. It costs ~5x disassembly throughput (640k -> 128k insn/s
        # measured), which is irrelevant at this corpus size (~650 instructions
        # per binary) but there is no reason to pay it at tiers 0-1.
        self.cs.detail = self._arity_enabled()

    def _setup_arena(self, stack_addr, stack_size):
        """Map the emulated heap and register it for pointer classification.

        The base shifts per layout exactly as the stack does, so a fixed heap
        address cannot masquerade as a property of the program.
        """
        base = self.args.heap_base + self._layout_index * LAYOUT_STRIDE
        size = self.args.heap_size

        # Overlapping a PT_LOAD segment or the stack would corrupt program
        # state in a way that looks like a program bug, not a tracer bug.
        for seg in self.segments:
            if base < seg["vaddr"] + seg["memsz"] and seg["vaddr"] < base + size:
                raise RuntimeError(
                    f"heap arena 0x{base:x}+0x{size:x} overlaps segment "
                    f"0x{seg['vaddr']:x}; move it with --heap-base")
        if base < stack_addr + stack_size and stack_addr < base + size:
            raise RuntimeError(
                f"heap arena 0x{base:x}+0x{size:x} overlaps the stack "
                f"0x{stack_addr:x}; move it with --heap-base")

        page = 0x1000
        mapped = ((size + page - 1) // page) * page
        self.mu.mem_map(base, mapped)
        if getattr(self.args, "poison_uninitialized", False):
            self.mu.mem_write(base, bytes([POISON_BYTE]) * mapped)
        self.arena = Arena(base, size)
        self.memmap.add_region(base, size, "heap")
        self.log.verbose(f"  Heap arena: 0x{base:x} - 0x{base + size:x}")

    def _input_vectors(self):
        """The argv vectors to run, one list of strings each.

        `[[]]` - a single run with no arguments - reproduces the pre-phase-12
        behaviour exactly, which is what keeps every golden file valid.
        """
        path = getattr(self.args, "argv_file", None)
        if path:
            found = []
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        found.append(line.split())
            if found:
                return found
            self.log.error(f"  [!] {path} held no usable vectors")
        one = getattr(self.args, "argv", None)
        return [one.split()] if one else [[]]

    def _setup_argv(self):
        """Lay out argv in emulated memory; return (argc, argv pointer).

        Replaces a stub that set argc=1 and pointed argv at an address nobody
        ever populated - which is why `tcas` printed its usage text and exited,
        and why four of six large programs barely executed.

        Layout is the ordinary one: NUL-terminated strings, then a
        NULL-terminated array of pointers to them, argv[0] being the program
        path. On its own page so --layouts relocation cannot collide with it.
        """
        words = [self.args.binary] + list(self.current_argv)
        self.mu.mem_map(ARGV_BASE, ARGV_SIZE)

        # Strings first, above the pointer array they will be pointed at by.
        ptr_bytes = 8 if self.is_64bit else 4
        strings_at = ARGV_BASE + (len(words) + 1) * ptr_bytes
        offsets, cursor = [], strings_at
        for w in words:
            raw = w.encode() + bytes(1)
            if cursor + len(raw) > ARGV_BASE + ARGV_SIZE:
                self.log.error("  [!] argv does not fit; truncating")
                break
            self.mu.mem_write(cursor, raw)
            offsets.append(cursor)
            cursor += len(raw)

        order = "little"
        table = b"".join(p.to_bytes(ptr_bytes, order) for p in offsets)
        table += bytes(ptr_bytes)          # the NULL that terminates argv
        self.mu.mem_write(ARGV_BASE, table)

        if self.current_argv:
            self.log.verbose(f"  argv: argc={len(offsets)} "
                             + " ".join(repr(w) for w in words[1:]))
        return len(offsets), ARGV_BASE

    def _read_cstring(self, uc, addr, limit=4096):
        """A NUL-terminated string out of emulated memory, as bytes."""
        out = bytearray()
        for i in range(limit):
            try:
                b = uc.mem_read(addr + i, 1)[0]
            except UcError:
                break
            if b == 0:
                break
            out.append(b)
        return bytes(out)

    def _handle_libc(self, uc, name, address, size):
        """Emulate a library call in place of executing it.

        Same contract as _handle_allocator: set rax, advance rip past the call,
        return True when handled.
        """
        if name in ("exit", "_exit", "abort"):
            code = uc.reg_read(UC_X86_REG_RDI) if name != "abort" else -1
            self.log.verbose(f"  {name}({code}) - stopping this run")
            self._exited = True
            uc.emu_stop()
            return True

        if name in ("atoi", "atol"):
            raw = self._read_cstring(uc, uc.reg_read(UC_X86_REG_RDI))
            text = raw.decode("latin-1").strip()
            m = re.match(r"[+-]?\d+", text)
            value = int(m.group()) if m else 0
            if name == "atoi":
                value = sign_extend(value & 0xFFFFFFFF, 32)
            uc.reg_write(UC_X86_REG_RAX, value & ((1 << 64) - 1))
            uc.reg_write(UC_X86_REG_RIP, address + size)
            self._log_event({"type": "libc", "fn": name, "pc": address,
                             "arg": text, "result": value})
            return True

        return False

    def _handle_allocator(self, uc, name, address, size):
        """Emulate an allocator call in place of executing it.

        Returns True when handled. Arguments come from the SysV registers; the
        memory effects (calloc zeroing, realloc copying) happen here because the
        Arena itself is pure.
        """
        arg0 = uc.reg_read(UC_X86_REG_RDI)
        arg1 = uc.reg_read(UC_X86_REG_RSI)
        result = 0

        if name == "malloc":
            result = self.arena.malloc(arg0)
        elif name == "calloc":
            result, nzero = self.arena.calloc(arg0, arg1)
            if result and nzero:
                uc.mem_write(result, bytes(nzero))
        elif name == "realloc":
            result, ncopy = self.arena.realloc(arg0, arg1)
            # Safe to copy after the fact: freed blocks are never reissued, so
            # the source is still intact.
            if result and ncopy:
                uc.mem_write(result, bytes(uc.mem_read(arg0, ncopy)))
        elif name == "free":
            if not self.arena.free(arg0) and arg0 != 0:
                self.log.verbose(f"  [!] free(0x{arg0:x}): not a live allocation")
        else:
            return False

        if result == 0 and name in ("malloc", "calloc", "realloc"):
            self.log.verbose(f"  [!] {name} returned NULL (arena exhausted?)")

        uc.reg_write(UC_X86_REG_RAX, result)
        uc.reg_write(UC_X86_REG_RIP, address + size)
        self._log_event({"type": "alloc", "fn": name, "pc": address,
                         "arg0": arg0, "result": result})
        return True

    # ---- Tier 2 helpers ----
    def _float_enabled(self):
        """Tier 9+: floating-point arguments and returns.

        SysV passes float and double in xmm0-xmm7, numbered independently of
        the integer registers. Without this the six-integer-register detector
        reports `float mul(float a, float b)` as taking NO arguments - measured
        at 8 functions out of 8 on Daikon's FloatTest.
        """
        return self.args.tier >= 9 and self.is_64bit

    def _globals_enabled(self):
        """Tier 8+: recover and report global variables.

        Measured on Daikon's own Kvasir suite: globals are 80.5% of everything
        the oracle says, and emitting none of them capped recall at 4%.

        `--ignore-globals` turns them off at any tier, as Kvasir's option of
        the same name does - Daikon's own `bc` run uses it. Each sample keeps a
        snapshot of the data sections until finalize, so a call-heavy program
        with large, changing globals costs memory in proportion to samples
        times data size: Stanford's Towers, 93 KB of .bss, took 2.5 GB over
        150,000 instructions with globals and 55 MB without.
        """
        return (self.args.tier >= 8 and self.is_64bit
                and not getattr(self.args, "ignore_globals", False))

    def _note_rip_targets(self, insn):
        """Record RIP-relative operand targets that land in a data section.

        At -O0 gcc addresses a global as `mov 0x2f3a(%rip),%eax`, and the
        target is computable from the instruction alone. This is the ONLY
        signal that separates two adjacent same-width globals: `globalDouble`,
        `globalLong` and `globalStr` sit at consecutive 8-byte addresses with
        no padding, and access evidence alone calls them an array of three.
        """
        try:
            operands = insn.operands
        except Exception:
            return
        for op in operands:
            if op.type != X86_OP_MEM:
                continue
            base = op.mem.base
            if base and insn.reg_name(base) == "rip":
                self.global_table.add_start(
                    insn.address + insn.size + op.mem.disp)

    def _global_root_addresses(self):
        """Addresses to probe for pointer-valued globals, known at sample time.

        Symbols when the binary is not stripped, RIP anchors otherwise. Both
        are available DURING emulation, unlike the resolved object list, which
        is only decided at finalize - so this is the capture-broadly half of
        the usual split.
        """
        if self.global_table._symbols:
            return sorted({a for a, _ in self.global_table._symbols})
        return sorted(self.global_table._starts)

    def _capture_global_pointees(self):
        """{global address: bytes behind the pointer it holds}."""
        out = {}
        for addr in self._global_root_addresses():
            try:
                raw = bytes(self.mu.mem_read(addr, 8))
            except UcError:
                continue
            ptr = int.from_bytes(raw, "little")
            if not ptr or self.memmap.classify(ptr) != POINTER:
                continue
            self.global_pointer.setdefault(addr, ptr)
            if self.arena is not None:
                size = self.arena.size_of(ptr)
                if size is not None:
                    prev = self.global_pointee_size.get(addr)
                    self.global_pointee_size[addr] = (
                        size if prev is None else min(prev, size))
            want = min(self._pointer_bound(ptr), DEREF_WINDOW)
            try:
                out[addr] = bytes(self.mu.mem_read(ptr, want))
            except UcError:
                out[addr] = None
        return out

    def _global_pointee_layout(self, addr):
        """Fields behind a pointer-valued global, or []."""
        if not getattr(self.args, "deref_globals", False):
            return []
        ptr = self.global_pointer.get(addr)
        if not ptr:
            return []
        size = self.global_pointee_size.get(addr)
        # Bounded by the allocation where one exists. Unlike a stack pointee,
        # a heap block has a known extent, so this does not repeat the
        # --infer-from-caller over-reach.
        return self.global_access.layout_at(ptr, size or DEREF_WINDOW)

    def _global_pointee_array(self, addr):
        """(element width, count) if the pointee is an array, else None.

        A pointer global has no length ARGUMENT to correlate with, which is how
        tier 7 decides this for parameters. The allocation size replaces it:
        `struct counter *counters = malloc(10 * sizeof *counters)` gives an
        exact extent, and a uniformly tiled footprint inside it yields the
        count Kvasir reports as `size(::counters[]) == 10`.
        """
        if not self._array_enabled():
            return None
        size = self.global_pointee_size.get(addr)
        if not size:
            return None
        fields = self._global_pointee_layout(addr)
        width = uniform_layout(fields)
        if width is None:
            # A partly-read array does not tile. Fall back to the widths seen:
            # if every access is the same width and divides the allocation,
            # that width is the element size.
            widths = {w for _, w in fields}
            if len(widths) != 1:
                return None
            width = widths.pop()
        if width <= 0 or size % width or size // width < 2:
            return None
        return width, size // width

    def _snapshot_globals(self):
        """Current bytes of every data section, deduplicated.

        Returns a key into the pool rather than the bytes, so N identical
        samples cost one copy. Unreadable pages yield b"" rather than raising:
        .bss may extend past what the loader actually mapped.
        """
        if not self._globals_enabled():
            return None
        parts = []
        for lo, hi in self.global_table._regions:
            try:
                parts.append((lo, bytes(self.mu.mem_read(lo, hi - lo))))
            except UcError:
                parts.append((lo, b""))
        key = tuple(parts)
        if key not in self._gsnap_pool:
            self._gsnap_pool[key] = dict(parts)
        return (key, self._capture_global_pointees())

    def _global_bytes(self, snap, address, size):
        """`size` bytes at `address` from a snapshot, or None if not covered."""
        if not snap:
            return None
        for lo, blob in self._gsnap_pool.get(snap[0], {}).items():
            off = address - lo
            if 0 <= off and off + size <= len(blob):
                return blob[off:off + size]
        return None

    def _note_global_pointer_slots(self):
        """Tell the table which slots inside each global hold pointers.

        The struct-vs-array discriminator needs this and cannot compute it:
        `globalvars` is pure and the answer depends on the live memory map.
        Read from a snapshot rather than from `self.mu`, so it reflects the
        state at a sample rather than whatever the last layout left behind.
        """
        snaps = list(self._gsnap_pool.values())
        if not snaps:
            return
        blob_by_lo = snaps[-1]
        for addr, size in set(self.global_table._symbols):
            for off in range(0, size - 7, 8):
                raw = self._global_bytes_from(blob_by_lo, addr + off, 8)
                if raw is None:
                    continue
                v = int.from_bytes(raw, "little")
                if v and self.memmap.classify(v) == POINTER:
                    self.global_table.note_pointer_slot(addr, off)

    def _global_bytes_from(self, blob_by_lo, address, size):
        """`size` bytes at `address` out of one already-resolved snapshot."""
        for lo, blob in blob_by_lo.items():
            off = address - lo
            if 0 <= off and off + size <= len(blob):
                return blob[off:off + size]
        return None

    def _global_specs(self, comp_of):
        """VarSpecs for every recovered global, in address order.

        Mirrors Kvasir's shape so the two are comparable: a scalar is a plain
        variable, an array is `g[..]` with `array 1`, and a struct-shaped
        object gets one `.offK` per recovered field.
        """
        specs = []
        for obj in self.global_objects:
            arr = self._global_pointee_array(obj.address)
            if arr:
                specs.append(VarSpec(
                    obj.name, dec_type="void*", rep_type="hashcode",
                    comparability=comp_of("global_ptr")))
                specs.append(VarSpec(
                    f"{obj.name}[..]", dec_type="int[]", rep_type="int[]",
                    comparability=comp_of("scalar"),
                    var_kind="array", enclosing_var=obj.name, array=1))
                continue
            pointee = self._global_pointee_layout(obj.address)
            if pointee:
                # A global that HOLDS a pointer: the pointer itself, the object
                # behind it, and its fields - the same shape Kvasir gives
                # `::counters`, `::counters[]`, `::counters[].a`.
                specs.append(VarSpec(
                    obj.name, dec_type="void*", rep_type="hashcode",
                    comparability=comp_of("global_ptr")))
                specs.append(VarSpec(
                    f"{obj.name}[..]", dec_type="void*[]",
                    rep_type="hashcode[]", comparability=comp_of("pointer[]"),
                    var_kind="array", enclosing_var=obj.name, array=1))
                for off, _w in pointee:
                    specs.append(VarSpec(
                        f"{obj.name}[..].off{off}", dec_type="int[]",
                        rep_type="int[]", comparability=comp_of("scalar"),
                        var_kind=f"field off{off}",
                        enclosing_var=f"{obj.name}[..]", array=1))
                continue
            if obj.is_array:
                # The base must be declared before the sequence that encloses
                # it: Daikon rejects the whole trace with "enclosing variable
                # cannot be found" otherwise. Kvasir declares the same pair,
                # the object as a hashcode and its contents as an array.
                specs.append(VarSpec(
                    obj.name, dec_type="int[]", rep_type="hashcode",
                    comparability=comp_of("global_ptr")))
                specs.append(VarSpec(
                    f"{obj.name}[..]", dec_type="int[]", rep_type="int[]",
                    comparability=comp_of("global[]"),
                    var_kind="array", enclosing_var=obj.name, array=1))
            elif len(obj.fields) > 1:
                specs.append(VarSpec(
                    obj.name, dec_type="void*", rep_type="hashcode",
                    comparability=comp_of("global_ptr")))
                for off, _w in obj.fields:
                    # `var-kind field` MUST carry the relative name; bare
                    # "field" makes Daikon reject the whole trace with
                    # "end-of-line found where relative name expected".
                    specs.append(VarSpec(
                        f"{obj.name}.off{off}", dec_type="int", rep_type="int",
                        comparability=comp_of("global"),
                        var_kind=f"field off{off}", enclosing_var=obj.name))
            else:
                specs.append(VarSpec(
                    obj.name, dec_type="int", rep_type="int",
                    comparability=comp_of("global")))
        return specs

    def _global_values(self, snap):
        """Values matching `_global_specs`, read from one snapshot."""
        out = []
        pointees = snap[1] if snap else {}
        for obj in self.global_objects:
            arr = self._global_pointee_array(obj.address)
            if arr:
                width, count = arr
                blob = pointees.get(obj.address)
                ptr = self._global_bytes(snap, obj.address, 8)
                ptr = int.from_bytes(ptr, "little") if ptr else 0
                out.append(ptr if ptr else NONSENSICAL)
                seq = (decode_sequence(blob, width, count,
                                       poisoned=self._poison_on())
                       if blob else None)
                out.append(seq if seq else NONSENSICAL)
                continue
            layout = self._global_pointee_layout(obj.address)
            if layout:
                blob = pointees.get(obj.address)
                ptr = self._global_bytes(snap, obj.address, 8)
                ptr = int.from_bytes(ptr, "little") if ptr else 0
                out.append(ptr if ptr else NONSENSICAL)
                out.append([ptr] if ptr and blob is not None else NONSENSICAL)
                for off, w in layout:
                    v = (decode_field(blob, off, w, poisoned=self._poison_on())
                         if blob else None)
                    out.append([v] if v is not None else NONSENSICAL)
                continue
            if obj.is_array:
                blob = self._global_bytes(snap, obj.address, obj.size)
                out.append(obj.address)          # the base, as a hashcode
                seq = (decode_sequence(blob, obj.width, obj.count(),
                                       poisoned=self._poison_on())
                       if blob else None)
                out.append(seq if seq else NONSENSICAL)
            elif len(obj.fields) > 1:
                blob = self._global_bytes(snap, obj.address, obj.size)
                out.append(obj.address if blob else NONSENSICAL)
                for off, w in obj.fields:
                    v = (decode_field(blob, off, w, poisoned=self._poison_on())
                         if blob else None)
                    out.append(v if v is not None else NONSENSICAL)
            else:
                w = obj.fields[0][1] if obj.fields else obj.size
                blob = self._global_bytes(snap, obj.address, w)
                v = (decode_field(blob, 0, w, poisoned=self._poison_on())
                     if blob else None)
                out.append(v if v is not None else NONSENSICAL)
        return out

    def _sse_raw_index(self, i, n_reg, n_stack):
        """Raw-vector index of SSE argument `i`.

        The SSE block sits after the stack window: [rax, 6 regs, MAX_STACK_PROBE
        stack words, xmm0..xmm7]. Computed from the FIXED probe width, not the
        function's arity, because the vector is captured before arity is known.
        """
        return 1 + len(REG_ARG_ORDER) + MAX_STACK_PROBE + i

    def _decode_float(self, bits, width):
        """Reinterpret raw register bits as a float or double.

        Daikon's `double` rep-type takes a decimal literal, so the bit pattern
        must be converted here - reporting 4614256650576692846 where the value
        is 3.14159 is the same class of error as reporting an unsigned as
        negative.
        """
        try:
            if width == 4:
                return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]
            return struct.unpack("<d", struct.pack("<Q", bits))[0]
        except (struct.error, OverflowError):
            return NONSENSICAL

    def _read_sse_values(self):
        """Low 64 bits of xmm0-xmm7, as raw bit patterns.

        Read unconditionally at tier 9 and sliced down at finalize time, the
        same capture-broadly-emit-narrowly rule the integer slots follow: a
        function's SSE arity is not known until it has executed.
        """
        out = []
        for reg in SSE_REGS:
            try:
                v = self.mu.reg_read(reg)
            except Exception:
                v = 0
            if isinstance(v, (bytes, bytearray)):
                v = int.from_bytes(bytes(v[:8]), "little")
            elif isinstance(v, (list, tuple)):
                v = int(v[0]) if v else 0
            out.append(int(v) & ((1 << 64) - 1))
        return out

    def _array_enabled(self):
        """Tier 7+: model a uniformly-tiled pointee with a correlated length
        argument as a sequence rather than a struct."""
        return self.args.tier >= 7 and self.is_64bit

    def _deref_enabled(self):
        """Tier 6+: follow pointer arguments and recover their fields."""
        return self.args.tier >= 6 and self.is_64bit

    def _alloc_enabled(self):
        """Tier 5+: model malloc/calloc/realloc/free instead of skipping them."""
        return self.args.tier >= 5 and self.is_64bit

    def _tier3_enabled(self):
        """Return value, sign correction and comparability. x86-64 only, same
        reason as tier 2: the schema is built from the SysV register order."""
        return self.args.tier >= 3 and self.is_64bit

    def _arity_enabled(self):
        """Tier 2+ on x86-64 only.

        REG_ARG_ORDER encodes the SysV x86-64 integer argument sequence. 32-bit
        cdecl passes everything on the stack, so register use-before-def has
        nothing to say there; that path keeps the legacy schema.
        """
        return self.args.tier >= 2 and self.is_64bit

    def _stack_arg_slot(self, insn):
        """Index of the stack-argument slot this instruction reads, or None.

        After the -O0 prologue (`push rbp; mov rbp, rsp`), the frame is
        [rbp]=saved rbp, [rbp+8]=return address, and stack arguments begin at
        [rbp+0x10]. An indexed access is an array walk, not an argument, so
        require a bare base+displacement form.

        Reading these off Capstone's operand detail - which tier 2 already pays
        for - avoids standing up a second mechanism on UC_HOOK_MEM_READ.
        """
        try:
            operands = insn.operands
        except (AttributeError, TypeError):
            return None
        for op in operands:
            if (op.type == X86_OP_MEM
                    and op.mem.base == X86_REG_RBP
                    and op.mem.index == 0
                    and op.mem.disp >= 0x10):
                return (op.mem.disp - 0x10) // 8
        return None

    def _note_slot_values(self, func_addr, values):
        """Remember every value each raw slot held, for type classification.

        Classified here rather than at finalize because the memory map is
        per-layout; the verdict has to be taken while that map is live.
        """
        if not self._tier3_enabled():
            return
        for i, v in enumerate(values):
            key = (func_addr, i)
            verdict = self.memmap.classify(v)
            prev = self.slot_values.get(key, NULL)
            if prev == SCALAR:
                continue          # already disqualified, permanently
            if verdict == SCALAR:
                self.slot_values[key] = SCALAR
            elif verdict == POINTER:
                self.slot_values[key] = POINTER
            # NULL is neutral: a function called once with a valid pointer and
            # once with NULL still takes a pointer. Treating NULL as
            # disqualifying cost the pointee for EVERY call to that function.

    def _watch_caller_rax(self, insn):
        """After a callee returns, does its caller consume rax?

        Reading rax before writing it means the result was used, so the function
        is not void. A write first means the value was discarded. The window is
        bounded because at -O0 the consuming instruction follows within a few
        instructions, and an unbounded watch would eventually see an unrelated
        read.
        """
        watch = self._pending_rax_watch
        if watch is None:
            return
        callee_addr, remaining = watch
        try:
            reads, writes = insn.regs_access()
        except Exception:
            return
        for r in reads:
            if canonical_reg(insn.reg_name(r)) == "rax":
                self.arity.note_caller_observation(callee_addr, True)
                # The consuming opcode reveals the result's signedness:
                # `shr` means unsigned, `sar` means signed.
                self.arity.note_return_signedness(callee_addr, insn.mnemonic)
                self._pending_rax_watch = None
                return
        for w in writes:
            if canonical_reg(insn.reg_name(w)) == "rax":
                self.arity.note_caller_observation(callee_addr, False)
                self._pending_rax_watch = None      # discarded => void
                return
        watch[1] = remaining - 1
        if watch[1] <= 0:
            self.arity.note_caller_observation(callee_addr, False)
            self._pending_rax_watch = None

    def _note_skipped_call(self, uc, insn, target, pc, next_addr):
        """Count a skipped call for --dump-inferences. Changes nothing emitted.

        A direct call is labelled by its PLT name when it has one. An indirect
        call has no target in its encoding, so the operand is read instead -
        that is the only way to tell a library call made through the GOT from
        a function pointer into the program, which is skipped all the same.
        """
        if target is None:
            resolved = self._resolve_call_target(uc, insn, next_addr)
            label = "indirect"
            if resolved is not None and resolved in self.plt_names:
                label = f"indirect:{self.plt_names[resolved]}"
            key = (pc, resolved)
            self.indirect_calls[key] = self.indirect_calls.get(key, 0) + 1
        else:
            label = self.plt_names.get(target, f"0x{target:x}")
        self.skipped_by_target[label] = self.skipped_by_target.get(label, 0) + 1

    def _resolve_call_target(self, uc, insn, next_addr):
        """Where an indirect `call` is really going, or None if unreadable.

        Reads the operand without executing anything: `call rax` is the
        register's value; `call [rbp-8]` or `call [rip+x]` is the pointer
        stored at the effective address.
        """
        try:
            op = insn.operands[0]
        except (IndexError, AttributeError):
            return None
        try:
            if op.type == X86_OP_REG:
                return uc.reg_read(self._uc_reg(insn.reg_name(op.reg)))
            if op.type == X86_OP_MEM:
                mem = op.mem
                ea = mem.disp
                if mem.base:
                    base = insn.reg_name(mem.base)
                    ea += (next_addr if base in ("rip", "eip")
                           else uc.reg_read(self._uc_reg(base)))
                if mem.index:
                    ea += uc.reg_read(
                        self._uc_reg(insn.reg_name(mem.index))) * mem.scale
                width = 8 if self.is_64bit else 4
                ea &= (1 << (8 * width)) - 1
                return int.from_bytes(bytes(uc.mem_read(ea, width)), "little")
        except (UcError, AttributeError, TypeError):
            return None
        return None

    @staticmethod
    def _uc_reg(name):
        """Unicorn's constant for a register Capstone names, e.g. 'rax'."""
        return getattr(UC_X86_CONST, "UC_X86_REG_" + name.upper())

    def _inference_report(self):
        """Every conclusion the tracer reached, for --dump-inferences.

        Built from the same state the schema is built from, after
        _finalize(), so it reports what was emitted rather than a re-derivation
        that could drift from it.
        """
        enters, exits = {}, {}
        for (_ppt, ppt_type, func_addr, *_rest) in self.pending:
            bucket = enters if ppt_type == "enter" else exits
            bucket[func_addr] = bucket.get(func_addr, 0) + 1

        funcs = []
        for addr, name in sorted(self.functions.items()):
            # Every known function is listed, run or not: one that never ran
            # is itself evidence, e.g. the target of a skipped indirect call.
            described = (self.arity.describe(addr)
                         if self._arity_enabled() else None)
            entry = {"name": name, "addr": addr,
                     "enters": enters.get(addr, 0), "exits": exits.get(addr, 0)}
            if described is not None:
                entry.update(described)
                n_reg = described["n_reg"]
                n_args = n_reg + described["n_stack"]
                entry["slot_kinds"] = [
                    self._slot_type(addr, self._arg_raw_index(i, n_reg))
                    for i in range(n_args)]
                entry["returns_value"] = self.arity.returns_value(addr)
                if self._tier3_enabled():
                    entry["return_emitted"] = self._emits_return(addr)
                    if (self._float_enabled()
                            and self.arity.return_sse_width(addr)):
                        entry["return_kind"] = "float"
                    else:
                        entry["return_kind"] = self._slot_type(addr, 0)
            funcs.append(entry)

        objects = []
        for obj in self.global_objects:
            objects.append({
                "addr": obj.address, "size": obj.size, "width": obj.width,
                "shape": ("array" if obj.is_array
                          else "scalar" if obj.is_scalar else "struct"),
                "fields": [list(f) for f in obj.fields]})

        indirect = [{"pc": pc, "target": tgt,
                     "is_function": (tgt in self.functions
                                     if tgt is not None else None),
                     "count": n}
                    for (pc, tgt), n in sorted(
                        self.indirect_calls.items(),
                        key=lambda kv: (kv[0][0], kv[0][1] or 0))]

        return {
            "version": 1,
            "binary": self.args.binary,
            "tier": self.args.tier,
            "detect_void": bool(getattr(self.args, "detect_void", False)),
            "instructions": self.insn_count,
            "hit_insn_limit": self.hit_insn_limit,
            "ret_mismatches": self.ret_mismatches,
            "samples": len(self.dtrace.data_samples),
            "skipped_calls": self.skipped_calls,
            "skipped_by_target": dict(sorted(self.skipped_by_target.items())),
            "indirect_calls": indirect,
            "functions": funcs,
            "globals": objects,
        }

    def _poison_on(self):
        return bool(getattr(self.args, "poison_uninitialized", False))

    def _pointer_bound(self, ptr):
        """How many bytes past `ptr` may belong to the same object.

        A heap pointer has an exact answer from the allocator. A stack or
        global pointer has none, so a small fixed window is used - the cost of
        over-reaching is inventing fields out of a neighbouring local.
        """
        if self.arena is not None:
            size = self.arena.size_of(ptr)
            if size is not None:
                return size
        return DEREF_WINDOW

    def _candidate_pointers(self, arg_values, include_return=False):
        """[(raw_slot_index, pointer_value)] for every slot that looks like a
        pointer RIGHT NOW.

        Deliberately independent of arity and of the accumulated slot
        classification. Both are learned from executed instructions, and at the
        moment a function is entered none of its instructions have run yet - so
        an arity-bounded loop captures nothing on the first call, and nothing
        at all for a function called once. Capture broadly here and let
        _pointee_layout decide narrowly at finalize what is worth emitting.

        Keyed by RAW slot index so it needs no arity to interpret.
        """
        if arg_values is None:
            return []
        out = []
        start = 0 if include_return else 1
        for raw_index in range(start, len(arg_values)):
            ptr = arg_values[raw_index]
            if ptr and self.memmap.classify(ptr) == POINTER:
                out.append((raw_index, ptr))
        return out

    def _hook_mem_deref(self, uc, access, addr, size, value, user_data):
        """Attribute a memory read to the argument pointer it came from.

        Fires on reads AND writes. A field that is only ever written - the
        out-parameter idiom, `void fill(pair_t *p, int v)` - leaves no read
        footprint, and a read-only hook silently recovers nothing for it.

        By VALUE, not by register: at -O0 the pointer is spilled and reloaded
        into a scratch register before use, so the argument register itself is
        never dereferenced.
        """
        if not self.call_stack:
            return
        # Recorded for EVERY access, regardless of which frame is running or
        # whether it can be attributed to an argument. This is what lets a
        # callee that never dereferences its pointer still get a layout.
        self.global_access.note(addr, size)
        if self._globals_enabled():
            self.global_table.note_access(addr, size)
            if self.global_table.in_data(addr) and self.call_stack:
                self.global_touch.setdefault(
                    self.call_stack[-1][2], set()).add(addr)

        frame = self.call_stack[-1]
        func_addr, arg_values = frame[2], frame[5]
        pc = uc.reg_read(UC_X86_REG_RIP)
        for raw_index, ptr in self._candidate_pointers(arg_values):
            delta = addr - ptr
            if 0 <= delta < self._pointer_bound(ptr):
                # Which INSTRUCTION touched which offset. `p->a; p->b` uses a
                # different instruction per field, each at a constant
                # displacement; `arr[i]` uses ONE instruction that walks many
                # offsets. That is the only dynamic signal separating
                # `struct {int a, b;}` from `int[2]`, which are otherwise
                # identical in extent, offsets and widths.
                self.access_pcs.setdefault(
                    (func_addr, raw_index), {}).setdefault(pc, set()).add(delta)
                self.footprints.note_access(func_addr, raw_index, delta, size)
                return

    def _capture_pointees(self, func_addr, arg_values, include_return=False):
        """{raw_slot_index: bytes} for every pointer-shaped slot."""
        """Snapshot the bytes behind each pointer argument.

        Captured raw and decoded at finalize, for the same reason tier 2 defers
        its schema: the field layout is not known until every invocation has
        contributed accesses.
        """
        blobs = {}
        for raw_index, ptr in self._candidate_pointers(arg_values, include_return):
            self.slot_pointer.setdefault((func_addr, raw_index), ptr)
            # Remember the allocation size so the unread tail of a heap object
            # can be inferred later; stack pointers have no such record.
            if self.arena is not None:
                size = self.arena.size_of(ptr)
                if size is not None:
                    # Keep the SMALLEST allocation this parameter ever pointed
                    # at. Footprints merge across calls, so a parameter given a
                    # 20-byte object once and a 12-byte object next must not be
                    # credited with fields that exist in only one of them.
                    key = (func_addr, raw_index)
                    prev = self.pointee_size.get(key)
                    self.pointee_size[key] = size if prev is None else min(prev, size)
            want = min(self._pointer_bound(ptr), DEREF_WINDOW)
            try:
                blobs[raw_index] = bytes(self.mu.mem_read(ptr, want))
            except UcError:
                blobs[raw_index] = None
        return blobs

    def _note_int_args(self, func_addr, arg_values):
        """Remember the non-pointer argument values seen at one call.

        An array parameter conventionally travels with its length, and that
        correlation is the only observable signal separating an array from a
        struct - the access patterns of `int p[2]` and `struct {int a, b;}` are
        identical, and gcc -O0 does not even emit a scaled-index addressing
        mode to tell them apart.
        """
        seen = set()
        for raw_index in range(1, len(arg_values)):
            v = arg_values[raw_index]
            # Plausible lengths only: positive, and not an address.
            if 0 < v < 1 << 20 and self.memmap.classify(v) != POINTER:
                seen.add(v)
        self.int_arg_values.setdefault(func_addr, []).append(seen)

        # Pair each pointer slot's allocation size with this call's integer
        # arguments, for the allocation-size array discriminator.
        for raw_index, ptr in self._candidate_pointers(arg_values):
            size = self.arena.size_of(ptr) if self.arena is not None else None
            self.call_records.setdefault((func_addr, raw_index), []).append(
                (size, seen))

    def _array_element_width(self, func_addr, arg_index, fields):
        """Element width if this pointee is an array, else None.

        Two independent discriminators. The first needs the footprint to tile
        the object uniformly; the second needs only that some integer argument
        times an observed width equals the allocation size, on every call -
        which covers a function that reads one element per call and therefore
        never tiles anything.
        """
        if not self._array_enabled():
            return None
        raw_index = self._arg_raw_index(arg_index, self.arity.arity(func_addr)[0])
        size = self.pointee_size.get((func_addr, raw_index))
        if looks_like_array(
                fields, size, self.int_arg_values.get(func_addr, []),
                tile_implies_array=getattr(
                    self.args, "tile_implies_array", False),
                pc_offsets=self.access_pcs.get((func_addr, raw_index))):
            return uniform_layout(fields)
        return array_width_from_allocation(
            fields, self.call_records.get((func_addr, raw_index), []))

    def _is_array_pointee(self, func_addr, arg_index, fields):
        return self._array_element_width(func_addr, arg_index, fields) is not None

    def _spill_slot(self, insn):
        """(arg_index, frame_offset) if this instruction spills an argument.

        Matches the -O0 prologue store `mov %edi,-0x4(%rbp)`: memory operand
        FIRST (so it is the destination - the reverse form loads from the slot
        and is not a spill), based on rbp, negative displacement, source a SysV
        argument register.
        """
        try:
            ops = insn.operands
        except (AttributeError, TypeError):
            return None
        if len(ops) != 2:
            return None
        dst, src = ops[0], ops[1]
        if dst.type != X86_OP_MEM or src.type != X86_OP_REG:
            return None
        if (dst.mem.base != X86_REG_RBP or dst.mem.index != 0
                or dst.mem.disp >= 0):
            return None
        reg = canonical_reg(insn.reg_name(src.reg))
        if reg not in REG_ARG_ORDER:
            return None
        return REG_ARG_ORDER.index(reg), dst.mem.disp

    def _sse_spill_slot(self, insn):
        """(sse_index, frame_offset) if this spills a float argument.

        `movss %xmm0,-0x4(%rbp)`: the same prologue shape as the integer spill,
        against the parallel SSE register sequence.
        """
        try:
            ops = insn.operands
        except (AttributeError, TypeError):
            return None
        if len(ops) != 2:
            return None
        dst, src = ops[0], ops[1]
        if dst.type != X86_OP_MEM or src.type != X86_OP_REG:
            return None
        if (dst.mem.base != X86_REG_RBP or dst.mem.index != 0
                or dst.mem.disp >= 0):
            return None
        reg = insn.reg_name(src.reg).lower()
        if reg not in SSE_ARG_ORDER:
            return None
        return SSE_ARG_ORDER.index(reg), dst.mem.disp

    def _read_exit_args(self, raw, func_addr, frame_base):
        """Replace clobbered register values with their spill-slot contents.

        Argument registers are caller-saved and the body reuses them freely -
        in skip_middle(a,b,c), gcc reloads `a` into edx, so at `ret` the third
        argument register holds the first argument. Re-reading registers at
        EXIT therefore reports fabricated relations such as `arg0 == arg2`,
        and no input disproves them because the clobber is deterministic.

        The spill slot still holds the parameter (and reflects assignment to
        it, which the register would not). Only register arguments need this;
        stack arguments live in the caller's frame and are still addressable.
        """
        if frame_base is None:
            return raw
        out = list(raw)
        for idx in range(len(REG_ARG_ORDER)):
            off = self.arity.spill_offset(func_addr, idx)
            if off is None:
                continue
            width = max(4, self.arity.arg_width(func_addr, idx) // 8)
            try:
                data = self.mu.mem_read(frame_base + off, width)
            except UcError:
                continue
            out[1 + idx] = int.from_bytes(bytes(data), "little")

        # xmm registers are clobbered just as badly: the body leaves the
        # RESULT in xmm0, so without this every float function reports
        # arg0 == return.
        if self._float_enabled():
            for idx in range(len(SSE_ARG_ORDER)):
                off = self.arity.sse_spill_offset(func_addr, idx)
                if off is None:
                    continue
                width = self.arity.sse_width(func_addr, idx)
                try:
                    data = self.mu.mem_read(frame_base + off, width)
                except UcError:
                    continue
                out[self._sse_raw_index(idx, 0, 0)] = int.from_bytes(
                    bytes(data), "little")
        return out

    def _note_arity(self, insn):
        """Attribute one instruction to the innermost active frame."""
        if not self.call_stack:
            return
        func_addr = self.call_stack[-1][2]
        try:
            reads, writes = insn.regs_access()
        except Exception:
            return
        spill = self._spill_slot(insn)
        if spill is not None:
            self.arity.note_spill(func_addr, spill[0], spill[1])
        if self._float_enabled():
            sse_spill = self._sse_spill_slot(insn)
            if sse_spill is not None:
                self.arity.note_sse_spill(func_addr, sse_spill[0], sse_spill[1])

        self.arity.note_instruction(
            func_addr,
            insn.mnemonic,
            [insn.reg_name(r) for r in reads],
            [insn.reg_name(w) for w in writes],
            stack_slot=self._stack_arg_slot(insn),
        )

    # ---- Register snapshots ----
    def _read_stack_args(self, rsp, count=None):
        """Read `count` words above the return address.

        Only valid at the function's first instruction (before the
        prologue runs), where rsp still points at the return address:
        arg7 is at [rsp+8], arg8 at [rsp+16], etc. Unreadable slots
        (e.g. past the mapped stack) read as 0 rather than raising.
        """
        if count is None:
            count = NUM_STACK_ARG_SLOTS
        values = []
        for i in range(count):
            try:
                word = self.mu.mem_read(rsp + 8 + i * 8, 8)
                values.append(struct.unpack('<Q', word)[0])
            except UcError:
                values.append(0)
        return values

    def _stack_probe_width(self):
        """How many stack words to capture per sample.

        Tiers 0-1 keep the fixed NUM_STACK_ARG_SLOTS window, so their bytes are
        unchanged. Tier 2 does not know a function's stack arity until it has
        executed, and the raw vector is captured before that - so probe wide and
        let the deferred schema slice it down. Cheap: a handful of extra reads
        per sample.
        """
        return NUM_STACK_ARG_SLOTS if not self._arity_enabled() else MAX_STACK_PROBE

    def _read_register_values(self):
        if self.is_64bit:
            rsp = self.mu.reg_read(UC_X86_REG_RSP)
            return [
                self.mu.reg_read(UC_X86_REG_RAX),
                self.mu.reg_read(UC_X86_REG_RDI),
                self.mu.reg_read(UC_X86_REG_RSI),
                self.mu.reg_read(UC_X86_REG_RDX),
                self.mu.reg_read(UC_X86_REG_RCX),
                self.mu.reg_read(UC_X86_REG_R8),
                self.mu.reg_read(UC_X86_REG_R9),
            ] + self._read_stack_args(rsp, self._stack_probe_width()) + (
                self._read_sse_values() if self._float_enabled() else [])
        return [
            self.mu.reg_read(UC_X86_REG_EAX),
            self.mu.reg_read(UC_X86_REG_EBX),
            self.mu.reg_read(UC_X86_REG_ECX),
            self.mu.reg_read(UC_X86_REG_EDX),
        ]

    def _dump_regs(self):
        return dict(zip(self.var_names, self._read_register_values()))

    # ---- Logging hook ----
    def _log_event(self, obj):
        if self.json_f is not None:
            self.json_f.write(json.dumps(obj) + "\n")

    # ---- Function naming ----
    def _ppt_name(self, func_name, kind):
        """Build a Daikon program-point name. kind is 'ENTER' or an exit name."""
        return f"..{func_name}():::{kind}"

    def _exit_kind(self):
        """Tier 0 emits EXIT1; tier 1+ emits EXIT0 to match Kvasir.

        At -O0 gcc routes every `return` through a single epilogue - a function
        with two return statements still has one `ret` - so one exit site per
        function is correct, and Kvasir names that site EXIT0.
        """
        return "EXIT1" if self.args.tier < 1 else "EXIT0"

    def _exit_ppt_type(self):
        """`subexit` marks an INDIVIDUAL exit site; `exit` marks an
        already-combined one.

        This one word is tier 1's actual deliverable. Declaring `exit` makes
        Daikon treat the point as pre-combined and report invariants at
        `:::EXIT1`, while Kvasir's `subexit` makes Daikon synthesize a combined
        `:::EXIT`. Until these agree, no exit-point invariant can be matched
        against the oracle, which blocks the phase 4 scorer.
        """
        return "exit" if self.args.tier < 1 else "subexit"

    def _alloc_nonce(self):
        """Tier 1+ tags each invocation so ENTER/EXIT pairing is explicit.

        Tier 0 emits no nonce and Daikon falls back to stack-discipline pairing,
        which is correct for well-nested traces (verified on recursive input)
        and safely drops unmatched entries rather than mispairing. The nonce is
        format parity with Kvasir plus immunity to cross-run pairing when
        --layouts concatenates several runs into one trace.
        """
        return None if self.args.tier < 1 else self.dtrace.next_nonce()

    # ---- Code hook ----
    def _hook_code(self, uc, address, size, user_data):
        self.insn_count += 1
        self._layout_insn_count += 1

        # Disassemble current instruction (for RET/CALL detection)
        try:
            code = uc.mem_read(address, size)
        except UcError:
            code = b""

        insn = None
        for i in self.cs.disasm(code, address):
            insn = i
            break

        # Function entry?
        if address in self.functions:
            func_name = self.functions[address]
            ppt_enter = self._ppt_name(func_name, "ENTER")

            values = self._read_register_values()
            nonce = self._alloc_nonce()
            self._note_slot_values(address, values)
            blobs = {}
            if self._deref_enabled():
                blobs = self._capture_pointees(address, values)
            if self._array_enabled():
                self._note_int_args(address, values)
            self.pending.append(
                (ppt_enter, "enter", address, values, nonce, blobs,
                 self._snapshot_globals()))

            self._log_event({
                "type": "function_enter",
                "pc": address,
                "name": func_name,
                "regs": self._dump_regs(),
            })

            # Track return address AND the entry address for EXIT pairing
            try:
                if self.is_64bit:
                    rsp = uc.reg_read(UC_X86_REG_RSP)
                    ret_addr = struct.unpack('<Q', uc.mem_read(rsp, 8))[0]
                else:
                    esp = uc.reg_read(UC_X86_REG_ESP)
                    ret_addr = struct.unpack('<I', uc.mem_read(esp, 4))[0]
            except UcError:
                ret_addr = 0

            # Where rbp will point once the standard -O0 prologue
            # (`push rbp; mov rsp,rbp`) has run. Computed here because at `ret`
            # the epilogue has already restored rbp to the caller's frame, so
            # it can no longer locate this function's spill slots. The slot
            # memory itself is still intact at that point - nothing has
            # overwritten it.
            frame_base = None
            if self._tier3_enabled():
                try:
                    frame_base = uc.reg_read(UC_X86_REG_RSP) - 8
                except UcError:
                    frame_base = None

            self.call_stack.append(
                (func_name, ret_addr, address, nonce, frame_base, values))

        # Attribute this instruction to the innermost active frame. Placed
        # AFTER the entry push so a function's first instruction counts toward
        # itself, and BEFORE the ret pop so its last one does too.
        if self._arity_enabled() and insn is not None:
            self._note_arity(insn)
        if insn is not None and self._globals_enabled():
            self._note_rip_targets(insn)

        if insn is not None and self._pending_rax_watch is not None:
            self._watch_caller_rax(insn)

        # RET = function exit
        if insn and insn.mnemonic == 'ret' and self.call_stack:
            (func_name, frame_ret_addr, entry_addr, nonce,
             frame_base, entry_values) = self.call_stack[-1]
            ppt_exit = self._ppt_name(func_name, self._exit_kind())

            # The frame's recorded return address has never been checked against
            # reality. Diagnose only - changing WHICH samples are emitted would
            # break the tier-0 golden, and there is no evidence yet that this
            # fires. Promote to control flow only if it does.
            if self.args.tier >= 1:
                try:
                    reg = UC_X86_REG_RSP if self.is_64bit else UC_X86_REG_ESP
                    sp = uc.reg_read(reg)
                    width = 8 if self.is_64bit else 4
                    fmt = '<Q' if self.is_64bit else '<I'
                    actual = struct.unpack(fmt, uc.mem_read(sp, width))[0]
                    if actual != frame_ret_addr:
                        self.ret_mismatches += 1
                        self.log.verbose(
                            f"  [!] ret mismatch in {func_name}: frame expected "
                            f"0x{frame_ret_addr:x}, stack holds 0x{actual:x}"
                        )
                except UcError:
                    pass

            values = self._read_register_values()
            if self._tier3_enabled():
                values = self._read_exit_args(values, entry_addr, frame_base)
            self._note_slot_values(entry_addr, values)
            blobs = {}
            if self._deref_enabled():
                # include_return: the return value is a real pointer here,
                # where at ENTER slot 0 is only caller residue.
                blobs = self._capture_pointees(entry_addr, values,
                                               include_return=True)
            self.pending.append(
                (ppt_exit, self._exit_ppt_type(), entry_addr, values, nonce,
                 blobs, self._snapshot_globals()))
            # A non-void callee leaves its result in rax; watch the caller's
            # next few instructions to see whether anything consumes it.
            if self._tier3_enabled():
                # Armed regardless of --detect-void: the same watch supplies
                # the signedness of the return value.
                self._pending_rax_watch = [entry_addr, 12]

            self._log_event({
                "type": "function_exit",
                "pc": address,
                "name": func_name,
                "regs": self._dump_regs(),
            })

            # Stop once the function we actually started at returns. Matching
            # on entry address covers all three start modes uniformly:
            # --start-addr, symbol-resolved, and emulation-recovered main.
            is_start_func = (entry_addr == self.resolved_start_addr)

            self.call_stack.pop()

            if is_start_func:
                self.log.info(f"\n[+] {func_name}() returned - stopping emulation")
                uc.emu_stop()
            elif self.args.stop_on_empty_stack and not self.call_stack:
                self.log.info("\n[+] Call stack empty - stopping emulation")
                uc.emu_stop()

        # CALL to unknown target → skip past it
        elif insn and insn.mnemonic == 'call' and self.args.skip_unknown_calls:
            target = None
            op = insn.op_str
            if op.startswith('0x'):
                try:
                    target = int(op, 16)
                except ValueError:
                    pass

            if (target is not None and self._alloc_enabled()
                    and target in self.alloc_stubs):
                self._handle_allocator(uc, self.alloc_stubs[target],
                                       address, size)
                return

            if target is not None and target in self.libc_stubs:
                if self._handle_libc(uc, self.libc_stubs[target],
                                     address, size):
                    return

            if target is None or target not in self.functions:
                next_addr = address + size
                # Recorded before the skip rewrites any register, so an
                # indirect call's operand still holds its real target.
                self._note_skipped_call(uc, insn, target, address, next_addr)
                if self.is_64bit:
                    uc.reg_write(UC_X86_REG_RAX, 0)
                    uc.reg_write(UC_X86_REG_RIP, next_addr)
                else:
                    uc.reg_write(UC_X86_REG_EAX, 0)
                    uc.reg_write(UC_X86_REG_EIP, next_addr)
                self.skipped_calls += 1
                self._log_event({
                    "type": "skipped_call",
                    "pc": address,
                    "target": hex(target) if target else "indirect",
                })

        # Optional verbose per-instruction trace (JSON only, expensive)
        if self.args.trace_instructions:
            self._log_event({
                "type": "insn",
                "pc": address,
                "size": size,
                "disasm": f"{insn.mnemonic} {insn.op_str}" if insn else None,
                "regs": self._dump_regs(),
            })

        if self.args.max_insns and self._layout_insn_count >= self.args.max_insns:
            self.log.info(f"\n[!] Hit instruction limit ({self.args.max_insns})")
            self.hit_insn_limit = True
            uc.emu_stop()

    # ---- Memory hooks ----
    def _hook_mem(self, uc, access, addr, size, value, user_data):
        if not self.args.trace_memory:
            return
        typ = "mem_write" if access == UC_HOOK_MEM_WRITE else "mem_read"
        evt = {"type": typ, "addr": addr, "size": size}
        if access == UC_HOOK_MEM_WRITE:
            evt["value"] = value
        self._log_event(evt)

    def _hook_mem_unmapped(self, uc, access, addr, size, value, user_data):
        page = (addr // 0x1000) * 0x1000
        try:
            uc.mem_map(page, 0x1000)
            uc.mem_write(page, b'\x00' * 0x1000)
            return True
        except UcError:
            return False

    # ---- Finalization ----
    def _emits_return(self, func_addr):
        """Void detection is opt-in; without the flag every function returns."""
        if not getattr(self.args, "detect_void", False):
            return True
        return self.arity.returns_value(func_addr)

    def _slot_type(self, func_addr, raw_index):
        """"pointer" or "scalar" for a raw slot, over every value it held."""
        return classify_slot([self.slot_values[(func_addr, raw_index)]]
                             if (func_addr, raw_index) in self.slot_values
                             else [])

    def _arg_raw_index(self, i, n_reg):
        """Raw-vector index of argument i. Layout: rax, 6 arg regs, stack."""
        return 1 + i if i < n_reg else 7 + (i - n_reg)

    def _schema_for(self, func_addr, is_exit):
        """(specs, n_reg, n_stack) for one function at the active tier."""
        if not self._arity_enabled():
            return legacy_specs(self.var_names), None, None
        n_reg, n_stack = self.arity.arity(func_addr)

        if not self._tier3_enabled():
            # Tier 2: rax retained under its own name at both ENTER and EXIT.
            specs = [VarSpec("rax")]
            specs += [VarSpec(f"arg{i}") for i in range(n_reg + n_stack)]
            return specs, n_reg, n_stack

        # Tier 3. Comparability partitions variables by inferred type: Daikon
        # only relates variables sharing a class. `return` MUST land in the same
        # class as same-typed arguments - Kvasir puts return and its int fields
        # both in class 3, and that is what produces the return-vs-field family
        # once dereference lands in tier 6.
        cls = {}
        def comp_of(kind):
            if kind not in cls:
                cls[kind] = str(len(cls) + 1)
            return cls[kind]

        specs = []
        for i in range(n_reg + n_stack):
            kind = self._slot_type(func_addr, self._arg_raw_index(i, n_reg))
            specs.append(VarSpec(
                f"arg{i}",
                dec_type="int" if kind != POINTER else "void*",
                rep_type="int" if kind != POINTER else "hashcode",
                comparability=comp_of(kind),
                # NOT `flags is_param`, despite Kvasir setting it on every
                # parameter. Measured: the flag makes Daikon emit linear
                # invariants with wrong coefficients AND suppress the correct
                # ones. On test09's skip_middle (return = 2a+1) it reports
                # `return - orig(a) - 1 == 0`, false on all six samples, while
                # the true `2 * arg0 - return + 1 == 0` disappears entirely.
                # Reproduced on a synthetic trace: the flag is the sole
                # trigger. Dropping it diverges from the oracle and agrees
                # with reality - the right trade when the consumer is a fuzzer
                # that cannot recover an invariant which was never emitted.
            ))

        # Floating-point arguments. They come after the integer ones because
        # the ABI numbers the two sequences independently and nothing in the
        # machine code records how they interleaved in the source - so for a
        # mixed list like `f(double a, int b)` the recovered ORDER is wrong
        # even though both values are right. Stated as a limit rather than
        # guessed at.
        if self._float_enabled():
            for i in range(self.arity.sse_arity(func_addr)):
                specs.append(VarSpec(
                    f"arg{n_reg + n_stack + i}",
                    dec_type="double", rep_type="double",
                    comparability=comp_of("float")))

        # Dereferenced pointees, mirroring Kvasir's shape: the pointer, a
        # one-element array standing for the object, and one variable per
        # recovered field. Field names are offsets because source names are
        # destroyed by stripping; the scorer aligns offK to DWARF fields.
        if self._deref_enabled():
            for i in range(n_reg + n_stack):
                for spec in self._pointee_specs(func_addr, i, comp_of):
                    specs.append(spec)

        # A pointer-valued return: Kvasir reports return[] and size(return[]),
        # and the argument machinery applies unchanged once slot 0 is followed.
        if (is_exit and self._deref_enabled()
                and self._emits_return(func_addr)
                and self._slot_type(func_addr, 0) == POINTER):
            ret_fields = self._return_pointee_layout(func_addr)
            if ret_fields:
                specs.append(VarSpec(
                    "return[..]", dec_type="void*[]", rep_type="hashcode[]",
                    comparability=comp_of("pointer[]"),
                    var_kind="array", enclosing_var="return", array=1))
                for off, _w in ret_fields:
                    specs.append(VarSpec(
                        f"return[..].off{off}", dec_type="int[]",
                        rep_type="int[]", comparability=comp_of("scalar"),
                        var_kind=f"field off{off}",
                        enclosing_var="return[..]", array=1))

        # rax is caller residue at ENTER - Kvasir declares no `return` there.
        if is_exit and self._emits_return(func_addr):
            sse_ret = (self.arity.return_sse_width(func_addr)
                       if self._float_enabled() else None)
            if sse_ret:
                # The result was left in xmm0, not rax: this function returns a
                # float or a double, and reading rax would report caller residue.
                specs.append(VarSpec(
                    "return", dec_type="double", rep_type="double",
                    comparability=comp_of("float")))
            else:
                kind = self._slot_type(func_addr, 0)
                specs.append(VarSpec(
                    "return",
                    dec_type="int" if kind != POINTER else "void*",
                    rep_type="int" if kind != POINTER else "hashcode",
                    comparability=comp_of(kind),
                ))

        # Globals go LAST and at every program point, matching Kvasir, which
        # reports every global at every ppt regardless of whether the function
        # touches it. Appending rather than prepending keeps the argument and
        # return positions - and therefore every lower-tier golden - unchanged.
        if self._globals_enabled():
            specs.extend(self._global_specs(comp_of))
        return specs, n_reg, n_stack

    def _pointee_layout(self, func_addr, arg_index):
        """Recovered fields for one pointer argument, or []."""
        raw_index = self._arg_raw_index(arg_index, self.arity.arity(func_addr)[0])
        if self._slot_type(func_addr, raw_index) != POINTER:
            return []
        size = self.pointee_size.get((func_addr, raw_index))

        local = self.footprints.observed(func_addr, raw_index)
        ptr = self.slot_pointer.get((func_addr, raw_index))

        # Nothing observed through this pointer inside this function: fall back
        # to what the rest of the trace did to that memory, typically the
        # caller initialising the object.
        #
        # Only with a KNOWN allocation size by default. Measured on
        # identity_ptr, whose argument is a stack `int`: with the generic
        # 64-byte window the map swallowed neighbouring locals and invented
        # three fields that do not exist. Nothing observable bounds a stack
        # object the callee never touched, so over-reaching there trades a
        # stated limit for a wrong answer - and for a consumer acting on these
        # invariants, invented fields are worse than absent ones.
        if not local:
            if size:
                return self.global_access.layout_at(ptr, size)
            if getattr(self.args, "infer_from_caller", False):
                return self.global_access.layout_at(ptr, DEREF_WINDOW)
            return []

        # Supplementing an existing footprint has the same hazard, so it is
        # gated too: `maybe` reads p->a and the caller wrote p->b, but only the
        # allocation size could prove where the object ends.
        if getattr(self.args, "infer_from_caller", False) and not size:
            merged = self.global_access.layout_at(ptr, DEREF_WINDOW)
            if merged:
                for off, w in merged:
                    self.footprints.note_access(func_addr, raw_index, off, w)

        return self.footprints.layout(
            func_addr, raw_index, object_size=size,
            infer_tail=getattr(self.args, "infer_unobserved_fields", False))

    def _return_pointee_layout(self, func_addr):
        """Recovered fields behind a pointer-valued return, or []."""
        if self._slot_type(func_addr, 0) != POINTER:
            return []
        size = self.pointee_size.get((func_addr, 0))
        if self.footprints.observed(func_addr, 0):
            return self.footprints.layout(
                func_addr, 0, object_size=size,
                infer_tail=getattr(self.args, "infer_unobserved_fields", False))
        ptr = self.slot_pointer.get((func_addr, 0))
        if size:
            return self.global_access.layout_at(ptr, size)
        if getattr(self.args, "infer_from_caller", False):
            return self.global_access.layout_at(ptr, DEREF_WINDOW)
        return []

    def _pointee_specs(self, func_addr, arg_index, comp_of):
        fields = self._pointee_layout(func_addr, arg_index)
        if not fields:
            return []
        base = f"arg{arg_index}"
        if self._is_array_pointee(func_addr, arg_index, fields):
            # The pointee IS the sequence: element type, no field variables.
            # Kvasir does the same for `int *` - `arr[..]` carries
            # [ 1 2 3 4 5 ] and has no sub-variables.
            return [VarSpec(f"{base}[..]", dec_type="int[]", rep_type="int[]",
                            comparability=comp_of("scalar"),
                            var_kind="array", enclosing_var=base, array=1)]
        out = [VarSpec(f"{base}[..]", dec_type="void*[]", rep_type="hashcode[]",
                       comparability=comp_of("pointer[]"),
                       var_kind="array", enclosing_var=base, array=1)]
        for off, width in fields:
            out.append(VarSpec(
                f"{base}[..].off{off}", dec_type="int[]", rep_type="int[]",
                comparability=comp_of("scalar"),
                var_kind=f"field off{off}",
                enclosing_var=f"{base}[..]", array=1))
        return out

    def _pointee_values(self, raw, n_reg, n_stack, func_addr, blobs):
        """Values for the pointee variables, in declaration order."""
        out = []
        for i in range(n_reg + n_stack):
            fields = self._pointee_layout(func_addr, i)
            if not fields:
                continue
            raw_index = self._arg_raw_index(i, n_reg)
            ptr = raw[raw_index]
            blob = (blobs or {}).get(raw_index)

            width = self._array_element_width(func_addr, i, fields)
            if width:
                # Count from THIS call's captured bytes, so a parameter given a
                # 5-element array on one call and a 3-element one on the next
                # yields sequences of the right length each time.
                count = (len(blob) // width) if blob else 0
                seq = (decode_sequence(blob, width, count,
                                       poisoned=self._poison_on())
                       if ptr else [])
                out.append(seq if seq else NONSENSICAL)
                continue

            # A null or unreadable pointee is `nonsensical`, not a fabricated
            # zero - Daikon must not infer facts about memory we never saw.
            out.append([ptr] if ptr and blob is not None else NONSENSICAL)
            for off, width in fields:
                v = (decode_field(blob, off, width,
                                  poisoned=self._poison_on())
                     if ptr else None)
                out.append([v] if v is not None else NONSENSICAL)
        return out

    def _filter_values(self, raw, n_reg, n_stack, func_addr=None, is_exit=False,
                       blobs=None):
        """Slice the wide raw vector down to the inferred schema.

        Raw layout is [rax, rdi, rsi, rdx, rcx, r8, r9, stack0..stackN].
        """
        if not self._tier3_enabled():
            return [raw[0]] + raw[1:1 + n_reg] + raw[7:7 + n_stack]

        # Tier 3 reorders (arguments first, `return` last) and sign-corrects.
        # An `int` occupies the low 32 bits of its register and writes to eax
        # zero-extend, so -1 arrives as 0x00000000FFFFFFFF; reported raw, Daikon
        # infers `> 0` where the truth is `< 0`.
        out = []
        for i in range(n_reg + n_stack):
            v = raw[self._arg_raw_index(i, n_reg)]
            out.append(sign_extend(v, self.arity.arg_width(func_addr, i)))
        if self._float_enabled():
            for i in range(self.arity.sse_arity(func_addr)):
                idx = self._sse_raw_index(i, n_reg, n_stack)
                bits = raw[idx] if idx < len(raw) else 0
                out.append(self._decode_float(
                    bits, self.arity.sse_width(func_addr, i)))

        if self._deref_enabled():
            out.extend(self._pointee_values(raw, n_reg, n_stack, func_addr, blobs))
        if (is_exit and self._deref_enabled()
                and self._emits_return(func_addr)
                and self._slot_type(func_addr, 0) == POINTER):
            ret_fields = self._return_pointee_layout(func_addr)
            if ret_fields:
                ptr = raw[0]
                blob = (blobs or {}).get(0)
                out.append([ptr] if ptr and blob is not None else NONSENSICAL)
                for off, w in ret_fields:
                    v = (decode_field(blob, off, w, poisoned=self._poison_on())
                     if ptr else None)
                    out.append([v] if v is not None else NONSENSICAL)

        if is_exit and self._emits_return(func_addr):
            sse_ret = (self.arity.return_sse_width(func_addr)
                       if self._float_enabled() else None)
            if sse_ret:
                idx = self._sse_raw_index(0, n_reg, n_stack)
                out.append(self._decode_float(
                    raw[idx] if idx < len(raw) else 0, sse_ret))
                return out
            width = self.arity.return_width(func_addr)
            if self.arity.return_is_unsigned(func_addr):
                # Proven unsigned by a consuming instruction, so masking to the
                # observed width is right and sign-extending would be wrong.
                out.append(raw[0] & ((1 << width) - 1) if width < 64 else raw[0])
            else:
                out.append(sign_extend(raw[0], width))
        return out

    def _finalize(self):
        """Flush buffered samples once every layout has contributed evidence.

        Arity is not known when a sample is taken - the function has not
        finished executing, and later layouts may still add evidence - so
        samples are buffered here rather than written as they happen.
        Declaration order still follows first-sample order, which is what the
        tier-0 golden pins.
        """
        # Globals are resolved ONCE, here, and the same object list is used
        # at every program point - Kvasir reports every global everywhere, and
        # a schema that varied per ppt could not be compared with it. This is
        # also the only point at which all the evidence is in.
        # Raw type evidence per global, for offline analysis of how much
        # ambiguity survives combining the available signals. Not used by the
        # tracer itself - the decision is logged separately as `global <...>`.
        for addr, size in sorted(set(self.global_table._symbols)):
            fields = self.global_table.fields_within(addr, size)
            widths = sorted({w for _, w in fields})
            ptr = sorted(self.global_table._ptr_slots.get(addr, ()))
            self.log.verbose(
                f"  globalev addr=0x{addr:x} size={size} "
                f"fields={fields} widths={widths} ptrslots={ptr}")

        for fa, hit in sorted(self.global_touch.items()):
            self.log.verbose(f"  globaltouch func=0x{fa:x} n={len(hit)} "
                             + " ".join(f"0x{a:x}" for a in sorted(hit)))

        for key, bypc in sorted(self.access_pcs.items()):
            spread = max((len(v) for v in bypc.values()), default=0)
            self.log.verbose(
                f"  accesspc func=0x{key[0]:x} slot={key[1]} "
                f"instructions={len(bypc)} max_offsets_per_insn={spread}")

        if self._globals_enabled():
            self._note_global_pointer_slots()
            self.global_objects = self.global_table.objects()
            for obj in self.global_objects:
                self.log.verbose(f"  global {obj!r}")

        schemas = {}
        for (ppt_name, ppt_type, func_addr, raw, nonce, blobs,
             gsnap) in self.pending:
            is_exit = ppt_type != "enter"
            key = (func_addr, is_exit)
            if key not in schemas:
                schemas[key] = self._schema_for(func_addr, is_exit)
            specs, n_reg, n_stack = schemas[key]
            values = (raw if n_reg is None
                      else self._filter_values(raw, n_reg, n_stack,
                                               func_addr, is_exit, blobs))
            if self._globals_enabled() and n_reg is not None:
                values = list(values) + self._global_values(gsnap)
            self.dtrace.declare(ppt_name, ppt_type, specs)
            self.dtrace.add_sample(ppt_name, values, nonce=nonce)

        if self._arity_enabled():
            for addr, name in sorted(self.functions.items()):
                if self.arity.seen(addr):
                    n_reg, n_stack = self.arity.arity(addr)
                    self.log.verbose(
                        f"  arity {name} @0x{addr:x}: "
                        f"{n_reg} reg + {n_stack} stack = {n_reg + n_stack}"
                    )

    # ---- Entry point ----
    def run(self):
        # 1. Find functions (symbol table or prologue scan)
        excluded = set() if self.args.no_default_exclude else set(DEFAULT_EXCLUDED)
        self.log.info(f"[+] Loading ELF: {self.args.binary}")
        all_funcs, self.is_64bit, self.entry_point, self.segments = \
            find_functions(
                self.args.binary,
                excluded,
                self.log,
                force_prologue_scan=self.args.scan_prologues,
            )

        self.log.info(f"  Architecture: {'x86_64' if self.is_64bit else 'x86'}")
        self.log.info(f"  Entry point: 0x{self.entry_point:x}")
        for seg in self.segments:
            self.log.verbose(
                f"  Segment: vaddr=0x{seg['vaddr']:x}, "
                f"size=0x{seg['memsz']:x}, flags={seg['flags']}"
            )

        if self.args.tier >= 5:
            try:
                stubs = resolve_plt_stubs(self.args.binary)
            except Exception as e:
                stubs = {}
                self.log.error(f"PLT resolution failed: {e}")
            self.plt_names = dict(stubs)
            self.alloc_stubs = {a: nm for a, nm in stubs.items()
                                if nm in ALLOCATORS}
            self.libc_stubs = {a: nm for a, nm in stubs.items()
                               if nm in LIBC_STUBS}
            if self.libc_stubs:
                self.log.info("  Library calls modelled: " + ", ".join(
                    f"{nm}@0x{a:x}" for a, nm in sorted(self.libc_stubs.items())))
            if self.alloc_stubs:
                pretty = ", ".join(f"{nm}@0x{a:x}"
                                   for a, nm in sorted(self.alloc_stubs.items()))
                self.log.info(f"  Allocators intercepted: {pretty}")
            else:
                self.log.info("  No allocator imports found "
                              "(statically linked, or none used)")

        # 2. Apply --include/--exclude filtering
        self.functions = self._filter_functions(all_funcs)
        if not self.functions:
            self.log.error("No traceable functions found.")
            self.log.error("Try --scan-prologues, --include, or --no-default-exclude.")
            return 1

        self.log.info(f"\n[+] Tracing {len(self.functions)} function(s):")
        for addr, name in sorted(self.functions.items())[:20]:
            self.log.info(f"    0x{addr:x}: {name}")
        if len(self.functions) > 20:
            self.log.info(f"    ... and {len(self.functions) - 20} more")

        # 3. Pick variable schema for this architecture
        self.var_names = REG_VARS_X64 if self.is_64bit else REG_VARS_X86

        # 4. Decide start address. This only depends on the binary's code
        # addresses (not on where the stack is mapped), so it's resolved
        # once and reused across every --layouts iteration below.
        start_addr = None

        if self.args.start_addr is not None:
            # Explicit address always wins.
            start_addr = self.args.start_addr
            self.log.info(
                f"\n[+] Starting emulation at 0x{start_addr:x} (--start-addr)"
            )
        else:
            # Try to resolve the start function by name (needs symbols).
            for addr, name in self.functions.items():
                if name == self.args.start_func:
                    start_addr = addr
                    self.log.info(
                        f"\n[+] Starting emulation at 0x{start_addr:x} ({name})"
                    )
                    break

            # No symbol for it. If we're after 'main' (the default), recover
            # main's address by emulating _start: on the SysV ABI it loads
            # main into RDI right before calling __libc_start_main.
            if start_addr is None and self.args.start_func == "main":
                self.log.info(
                    "\n[+] No 'main' symbol; recovering it by emulating _start..."
                )
                main_addr = discover_main_via_emulation(
                    self.segments, self.is_64bit, self.entry_point,
                    self.args.stack_base, self.args.stack_size, self.log,
                )
                if main_addr is not None:
                    start_addr = main_addr
                    self.log.info(f"[+] Recovered main at 0x{start_addr:x}")
                    # Ensure recovered main is in the traced set so its
                    # ENTER/EXIT get recorded even if prologue scan missed it.
                    if start_addr not in self.functions:
                        self.functions[start_addr] = f"sub_0x{start_addr:x}"

            # Still nothing: fall back to the entry point.
            if start_addr is None:
                self.log.info(
                    f"\n[!] Could not resolve '{self.args.start_func}'; "
                    f"starting at entry point 0x{self.entry_point:x}"
                )
                start_addr = self.entry_point

        # Remember where we actually started; the RET handler uses this to
        # decide when to stop.
        self.resolved_start_addr = start_addr

        # 5. Open output files. These are shared across every layout below,
        # so all of them merge into one Daikon trace.
        # `none` makes Daikon ignore the class numbers and compare everything.
        # Tier 3 supplies a real type partition, so the classes become live.
        self.dtrace = DaikonTraceWriter(
            self.args.output,
            var_comparability="implicit" if self._tier3_enabled() else "none")
        if self.args.json_output:
            self.json_f = open(self.args.json_output, "w", buffering=1)

        # 6. Emulate one or more independent stack layouts, merging every
        # layout's samples into the same dtrace. A single execution is
        # perfectly deterministic, so an incidental value (e.g. a leftover
        # stack address) is constant across all its samples and can look
        # "related" to real data via trivial arithmetic. Re-running with the
        # stack relocated breaks any invariant that only held at one fixed
        # address, while facts about real arguments (which don't depend on
        # where the stack sits) hold in every layout and survive the merge.
        # --layouts 1 (the default) reproduces the original single-run
        # behavior exactly.
        timeout_us = self.args.timeout * 1_000_000 if self.args.timeout else 0

        # One run per (input vector, stack layout). Both vary independent
        # things, so they multiply: `--argv-file` with 501 lines and
        # `--layouts 2` is 1002 runs. The count is logged up front because that
        # product is easy to set by accident.
        vectors = self._input_vectors()
        total = len(vectors) * self.args.layouts
        if total > 1:
            self.log.info(f"[+] Runs: {len(vectors)} input vector(s) x "
                          f"{self.args.layouts} layout(s) = {total}")

        run = -1
        for vec_index, vector in enumerate(vectors):
          for layout in range(self.args.layouts):
            run += 1
            self._layout_index = layout
            self.current_argv = vector
            self._exited = False
            stack_base = self.args.stack_base + layout * LAYOUT_STRIDE
            if total > 1 and (total <= 12 or run % 50 == 0):
                self.log.info(
                    f"[+] Run {run + 1}/{total}: vector {vec_index + 1}, "
                    f"stack_base=0x{stack_base:x}")

            self._setup_memory(stack_base)
            self.call_stack = []
            self._layout_insn_count = 0

            self.mu.hook_add(UC_HOOK_CODE, self._hook_code)
            if self.args.trace_memory:
                self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem)
            if self._deref_enabled():
                # WRITE as well as READ: an out-parameter is written and never
                # read, so a read-only hook recovers nothing for it at all.
                self.mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                                 self._hook_mem_deref)
            self.mu.hook_add(
                UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
                self._hook_mem_unmapped,
            )

            try:
                self.mu.emu_start(start_addr, start_addr + 0x1000000, timeout=timeout_us)
                self.log.info("[+] Emulation completed!")
            except UcError as e:
                self.log.error(f"Emulation stopped: {e}")

        # Every layout has now contributed arity evidence, so schemas can be
        # decided and the buffered samples flushed.
        self._finalize()
        self.dtrace.close()
        if self.json_f is not None:
            self.json_f.close()
        if getattr(self.args, "dump_inferences", None):
            with open(self.args.dump_inferences, "w") as f:
                json.dump(self._inference_report(), f, indent=1, sort_keys=True)

        # 7. Summary
        self.log.info(f"\n[+] Daikon trace:    {self.args.output}")
        if self.args.layouts > 1:
            self.log.info(f"[+] Stack layouts:   {self.args.layouts}")
        if self.args.json_output:
            self.log.info(f"[+] JSON trace:      {self.args.json_output}")
        self.log.info(f"[+] Instructions:    {self.insn_count}")
        self.log.info(f"[+] Skipped calls:   {self.skipped_calls}")
        self.log.info(f"[+] Program points:  {len(self.dtrace.ppt_specs)}")
        self.log.info(f"[+] Samples:         {len(self.dtrace.data_samples)}")
        return 0
