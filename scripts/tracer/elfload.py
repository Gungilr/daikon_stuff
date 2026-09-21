"""ELF parsing and function discovery.

Depends on pyelftools only - NOT on unicorn or capstone. That boundary is why
`discover_main_via_emulation` lives in emulate.py instead of here despite being
function-discovery logic: it builds its own Uc sandbox, and hosting it here
would drag the emulator into this module's import graph.
"""
from __future__ import print_function

import sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    print("[!] Missing dependency: pyelftools", file=sys.stderr)
    print("    Install with: pip install pyelftools", file=sys.stderr)
    sys.exit(1)


DEFAULT_EXCLUDED = {
    '_start', '_init', '_fini',
    '__libc_csu_init', '__libc_csu_fini',
    '__libc_start_main', '__libc_start_call_main',
    'frame_dummy', 'register_tm_clones', 'deregister_tm_clones',
    '_dl_relocate_static_pie', '__do_global_dtors_aux',
    '__stack_chk_fail', '__cxa_finalize',
    'call_gmon_start', '__gmon_start__',
}


def parse_symbol_functions(elf_path, excluded, log):
    """Extract function symbols from ELF symbol table.

    Returns:
        functions: dict mapping address -> function name
        is_64bit: True if x86-64
        entry_point: address of binary entry
        segments: list of PT_LOAD segments to map
    """
    functions = {}
    segments = []

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        is_64bit = (elf.elfclass == 64)
        entry_point = elf.header['e_entry']

        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_LOAD':
                segments.append({
                    'vaddr': segment['p_vaddr'],
                    'memsz': segment['p_memsz'],
                    'filesz': segment['p_filesz'],
                    'data': segment.data(),
                    'flags': segment['p_flags'],
                })

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for sym in section.iter_symbols():
                if (sym['st_info']['type'] == 'STT_FUNC'
                        and sym['st_value'] != 0
                        and sym.name
                        and sym.name not in excluded):
                    functions[sym['st_value']] = sym.name

    return functions, is_64bit, entry_point, segments


def find_functions_by_prologue(segments, is_64bit, log):
    """Heuristic function detection by scanning for common prologues.

    Detects functions in stripped binaries by looking for instruction
    patterns that typically begin a function. The function start is the
    address of the FIRST instruction, which on modern GCC is usually
    endbr64 (CET landing pad), followed by the frame setup.

    Patterns recognized (x86-64):
        endbr64                    f3 0f 1e fa
        push rbp; mov rbp, rsp     55 48 89 e5
        push rbp; sub rsp, imm8    55 48 83 ec
        sub rsp, imm8 (bare leaf)  48 83 ec

    When endbr64 is immediately followed by one of the frame-setup
    sequences, we record the endbr64 address (the true function start)
    and do NOT separately record the push that follows it.

    Returns a dict {address: f'sub_0x{addr:x}'}.
    """
    ENDBR64 = b'\xf3\x0f\x1e\xfa'

    # Frame-setup sequences that legitimately begin a function body
    FRAME_SETUPS_X64 = [
        b'\x55\x48\x89\xe5',   # push rbp; mov rbp, rsp
        b'\x55\x48\x83\xec',   # push rbp; sub rsp, imm8
        b'\x55',               # lone push rbp (followed by other setup)
    ]
    FRAME_SETUPS_X86 = [
        b'\x55\x89\xe5',       # push ebp; mov ebp, esp
        b'\x55\x83\xec',       # push ebp; sub esp, imm8
        b'\x55',               # lone push ebp
    ]

    frame_setups = FRAME_SETUPS_X64 if is_64bit else FRAME_SETUPS_X86
    functions = {}
    # Track addresses that are the "push rbp" right after an endbr64,
    # so we don't double-count them as separate functions.
    consumed_by_endbr = set()

    for seg in segments:
        if not (seg['flags'] & 0x1):  # PF_X = executable
            continue

        data = seg['data']
        vaddr = seg['vaddr']
        log.verbose(f"  Scanning 0x{vaddr:x}-0x{vaddr + len(data):x} for prologues...")

        # Pass 1: endbr64-led functions (most reliable on modern GCC)
        if is_64bit:
            start = 0
            while True:
                idx = data.find(ENDBR64, start)
                if idx < 0:
                    break
                addr = vaddr + idx
                # Check that a frame setup follows the endbr64
                after = data[idx + 4: idx + 4 + 4]
                if any(after.startswith(fs) for fs in frame_setups):
                    functions[addr] = f"sub_0x{addr:x}"
                    consumed_by_endbr.add(vaddr + idx + 4)  # the push after
                start = idx + 1

        # Pass 2: frame-setup-led functions WITHOUT a preceding endbr64
        # (covers -fcf-protection=none builds and leaf functions)
        for fs in frame_setups:
            if fs == b'\x55':
                continue  # too noisy on its own; only used as endbr follow-up
            start = 0
            while True:
                idx = data.find(fs, start)
                if idx < 0:
                    break
                addr = vaddr + idx
                # Skip if this is the push that immediately follows an endbr64
                if addr in consumed_by_endbr:
                    start = idx + 1
                    continue
                # Skip if there's an endbr64 immediately before (already counted)
                if is_64bit and idx >= 4 and data[idx - 4: idx] == ENDBR64:
                    start = idx + 1
                    continue
                if addr not in functions:
                    functions[addr] = f"sub_0x{addr:x}"
                start = idx + 1

    return functions


def find_functions(elf_path, excluded, log, force_prologue_scan=False):
    """Try symbol table first, fall back to prologue scanning."""
    sym_funcs, is_64bit, entry_point, segments = parse_symbol_functions(
        elf_path, excluded, log
    )

    if sym_funcs and not force_prologue_scan:
        log.info(f"  Found {len(sym_funcs)} function(s) via symbol table")
        return sym_funcs, is_64bit, entry_point, segments

    if force_prologue_scan:
        log.info("  Forced prologue scan (--scan-prologues)")
    else:
        log.info("  No symbol table found - scanning for function prologues...")

    prologue_funcs = find_functions_by_prologue(segments, is_64bit, log)

    # If we did a symbol-table pass, merge: symbol names take precedence
    if sym_funcs:
        for addr, name in sym_funcs.items():
            prologue_funcs[addr] = name

    log.info(f"  Found {len(prologue_funcs)} function(s) total")
    return prologue_funcs, is_64bit, entry_point, segments


# Opcode for `jmp *disp(%rip)`, the tail of every PLT stub.
_JMP_RIP = bytes((0xFF, 0x25))
_PLT_ENTRY_SIZE = 16


# Sections that hold global variables. `strip --strip-all` removes .symtab,
# so the NAMES are gone - but section headers survive, so the address RANGES
# do not. That is what makes tier-8 global recovery possible at all.
#
# .rodata is included because a string literal a global `char*` points at
# lives there, and Kvasir reports its contents.
GLOBAL_DATA_SECTIONS = (".data", ".bss", ".rodata", ".data.rel.ro")


def data_sections(elf_path):
    """[(name, addr, size)] for the sections that can hold globals.

    Empty and address-less sections are dropped: a zero-size .bss would add a
    degenerate region that every classification test then has to guard against.
    """
    out = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        for sec in elf.iter_sections():
            if sec.name not in GLOBAL_DATA_SECTIONS:
                continue
            addr, size = sec["sh_addr"], sec["sh_size"]
            if addr and size:
                out.append((sec.name, addr, size))
    return out


# Symbols that are compiler bookkeeping rather than program variables. They
# are real objects with real addresses, but no source-level name corresponds to
# them, so reporting them is pure noise.
_NOT_A_GLOBAL = ("completed.", "__", "_IO_", "stdout", "stderr", "stdin")


def data_symbols(elf_path):
    """[(name, addr, size)] for global VARIABLES from .symtab.

    The exact analogue of `parse_symbol_functions`, and it earns its place the
    same way: when the symbol table is present it gives addresses AND SIZES
    outright, which is the one thing the stripped path cannot recover. An
    `int[18]` and eighteen adjacent `int`s produce identical access evidence;
    only `st_size` separates them.

    Returns [] on a stripped binary, and the caller falls back to the
    RIP-and-access heuristic in `globalvars.py`, exactly as function discovery
    falls back to prologue scanning.
    """
    out = []
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name(".symtab")
        if symtab is None:
            return out
        for sym in symtab.iter_symbols():
            if sym["st_info"]["type"] != "STT_OBJECT":
                continue
            addr, size = sym["st_value"], sym["st_size"]
            if not addr or not size:
                continue
            name = sym.name
            if not name or name.startswith(_NOT_A_GLOBAL):
                continue
            out.append((name, addr, size))
    return sorted(out, key=lambda t: t[1])


def resolve_plt_stubs(elf_path):
    """Map PLT stub address -> imported symbol name.

    Survives `strip --strip-all`: the loader needs `.dynsym` and `.rela.plt`, so
    neither can be removed. Verified on tests/test08_stripped.exe, which yields
    malloc/free/printf at exactly the addresses the unstripped build reports.

    Two steps, neither of which assumes PLT entries are ordered to match
    relocation indices:

      1. `.rela.plt` gives GOT slot -> symbol name directly.
      2. Each PLT entry is scanned for `jmp *disp(%rip)`; its target is
         `address_of_next_instruction + disp`, which is that GOT slot.

    Reading the actual jump target rather than pairing by index is what makes
    this robust across `.plt` / `.plt.sec` layouts and linker variations.
    """
    got_to_symbol = {}
    stubs = {}

    with open(elf_path, "rb") as f:
        elf = ELFFile(f)

        for sec in elf.iter_sections():
            if isinstance(sec, RelocationSection) and sec.name == ".rela.plt":
                symtab = elf.get_section(sec["sh_link"])
                for reloc in sec.iter_relocations():
                    sym = symtab.get_symbol(reloc["r_info_sym"])
                    if sym.name:
                        got_to_symbol[reloc["r_offset"]] = sym.name

        if not got_to_symbol:
            return stubs

        # .plt.sec holds the real stubs on CET-enabled builds; .plt otherwise.
        for section_name in (".plt.sec", ".plt"):
            sec = elf.get_section_by_name(section_name)
            if sec is None:
                continue
            data = sec.data()
            base = sec["sh_addr"]
            for off in range(0, len(data), _PLT_ENTRY_SIZE):
                entry = data[off:off + _PLT_ENTRY_SIZE]
                idx = entry.find(_JMP_RIP)
                if idx < 0:
                    continue
                disp = int.from_bytes(entry[idx + 2:idx + 6], "little", signed=True)
                next_insn = base + off + idx + 6
                target = next_insn + disp
                if target in got_to_symbol:
                    stubs[base + off] = got_to_symbol[target]

    return stubs
