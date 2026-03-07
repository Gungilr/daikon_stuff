#!/usr/bin/env python3
from __future__ import print_function
import json
import struct
import sys, getopt
import pefile
from capstone import *
from unicorn import *
from unicorn.x86_const import *

upck32 = lambda x: struct.unpack('I', x)[0]
pck32 = lambda x: struct.pack('I', x)

FS_0 = 0x1000
FS_REGION_SIZE = 0x1000
PEB_ADD = 0x3000
TEB_ADD = 0x6000
LDR_ADD1 = 0x9000
LDR_ADD2 = 0xB000
LDR_ADD3 = 0xE000
LDR_ADD4 = 0xF000
PEB_LDR_ADD = 0x13000
STACK_BASE = 0x30000
STACK_LIMIT = 0x1000
TRACE_PATH = "trace.jsonl"
EXE_PATH = "test.exe"

GDT_ADDR = 0x1000
gdt_entries = [
    # Null descriptor
    0x0000000000000000,
    # Code segment
    0x00CF9A000000FFFF,
    # Data segment  
    0x00CF92000000FFFF,
    # FS segment descriptor
    0x00CF92000000FFFF,
]

# --- Helpers ---------------------------------------------------------------
def u32(x): return struct.pack("<I", x)

def init_FS():
        FS = bytearray()
        FS += pck32(0x0)            # 0x0
        FS += pck32(STACK_BASE)     # 0x4
        FS += pck32(STACK_LIMIT)    # 0x8
        FS += pck32(0x0) * 3        # 0xc,0x10,0x14
        FS += pck32(TEB_ADD)        # 0x18 <-- TEB pointer here
        FS += pck32(0x0) * 4        # 0x1C,0x20,0x24,0x28
        FS += pck32(PEB_ADD)        # 0x2C (or adjust per your needs)
        FS += pck32(0x0)
        return bytes(FS)

# --- Load PE ---------------------------------------------------------------
pe = pefile.PE(EXE_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase or 0x400000
ENTRY_POINT = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"PE image base: 0x{IMAGE_BASE:x}, entry: 0x{ENTRY_POINT:x}")

# --- Unicorn init ---------------------------------------------------------
mu = Uc(UC_ARCH_X86, UC_MODE_32)

# Optional: map a handler/trampoline area for imports
HANDLER_BASE = 0x30000000  # move higher to avoid overlap
HANDLER_SIZE = 0x00100000  # 1MB for trampolines
mu.mem_map(HANDLER_BASE, HANDLER_SIZE)

# Capstone for disassembly
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = False

LOW_MEM_BASE = 0x1000
LOW_MEM_SIZE = 0x1F000  # ~124KB to cover up to 0x20000
mu.mem_map(LOW_MEM_BASE, LOW_MEM_SIZE)
print(f"  Mapped low memory: 0x{LOW_MEM_BASE:x} - 0x{LOW_MEM_BASE+LOW_MEM_SIZE:x}")
        
# 2. Stack region (separate from low memory)
STACK_ADDR = 0x0fff0000
STACK_SIZE = 0x20000
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 4)
print(f"  Mapped stack: 0x{STACK_ADDR:x} - 0x{STACK_ADDR+STACK_SIZE:x}")

# 3. PE image region (0x400000)
# Map an address range large enough for image + some slack
IMAGE_SIZE = max(pe.OPTIONAL_HEADER.SizeOfImage, 2 * 1024 * 1024)
map_base = IMAGE_BASE
mu.mem_map(map_base, IMAGE_SIZE)

# Map and write sections
for section in pe.sections:
    va = IMAGE_BASE + section.VirtualAddress
    data = section.get_data()
    # ensure page-aligned mapping exists (already mapped above)
    mu.mem_write(va, data)
    print(f"  mapped {section.Name.decode(errors='ignore').strip()} -> 0x{va:x} ({len(data)} bytes)")

# init FS - NO MAPPING HERE, already mapped in main()
print("Writing FS structure...")
mu.mem_write(FS_0, init_FS())


# Open trace file
trace_f = open(TRACE_PATH, "w", buffering=1)

# Keep a map of import IAT VA -> (dll, name, handler_va)
import_map = {}

# --- Install IAT trampolines for imports ----------------------------------
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    idx = 0
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode(errors='ignore')
        for imp in dll.imports:
            if not imp.address:
                continue
            iat_va = imp.address  # absolute VA of IAT slot
            name = imp.name.decode(errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
            # create a small handler per import: mov eax,0 ; ret
            handler_va = HANDLER_BASE + (idx * 0x100)
            handler_bytes = b"\xB8" + struct.pack("<I", 0) + b"\xC3"  # mov eax,0 ; ret
            # write handler
            mu.mem_write(handler_va, handler_bytes)
            # write a relative JMP at the IAT slot to the handler (jmp rel32)
            # jmp instruction is E9 <rel32>
            jmp_place = iat_va
            rel32 = handler_va - (jmp_place + 5)
            jmp_instr = b"\xE9" + struct.pack("<i", rel32)
            # If IAT slot originally pointed to some memory, we overwrite it with the jmp
            # Make sure memory is mapped at that IAT VA (we mapped the image region earlier)
            mu.mem_write(jmp_place, jmp_instr)
            import_map[handler_va] = {"dll": dll_name, "name": name, "iat_va": iat_va}
            idx += 1
    print(f"Installed {len(import_map)} import trampolines (handlers start at 0x{HANDLER_BASE:x})")

# --- Hooks ---------------------------------------------------------------
MAX_INSNS = None  # set to an integer to limit trace size
insn_count = 0

def dump_regs(uc):
    regs = {
        "eip": uc.reg_read(UC_X86_REG_EIP),
        "esp": uc.reg_read(UC_X86_REG_ESP),
        "ebp": uc.reg_read(UC_X86_REG_EBP),
        "eax": uc.reg_read(UC_X86_REG_EAX),
        "ebx": uc.reg_read(UC_X86_REG_EBX),
        "ecx": uc.reg_read(UC_X86_REG_ECX),
        "edx": uc.reg_read(UC_X86_REG_EDX),
    }
    return regs

def log_event(obj):
    trace_f.write(json.dumps(obj) + "\n")

# Code hook: instruction-level trace
def hook_code(uc, address, size, user_data):
    global insn_count
    insn_count += 1
    try:
        code = uc.mem_read(address, size)
    except UcError:
        code = b""
    # disasm
    insn = None
    for i in cs.disasm(code, address):
        insn = {"mnemonic": i.mnemonic, "op_str": i.op_str, "bytes": i.bytes.hex()}
        break
    # detect import handler entry
    if address in import_map:
        info = import_map[address]
        evt = {
            "type": "import_call",
            "pc": address,
            "dll": info["dll"],
            "name": info["name"],
            "iat_va": info["iat_va"],
            "regs_before": dump_regs(uc)
        }
        log_event(evt)
        # Let handler run (it will just set eax=0 and ret), or we could simulate return manually.
    else:
        evt = {
            "type": "insn",
            "pc": address,
            "size": size,
            "disasm": f"{insn['mnemonic']} {insn['op_str']}" if insn else None,
            "bytes": insn['bytes'] if insn else None,
            "regs": dump_regs(uc),
        }
        log_event(evt)
    # optionally stop after N insns
    if MAX_INSNS and insn_count >= MAX_INSNS:
        uc.emu_stop()

# Memory hooks: read/write/invalid access
def hook_mem(uc, access, addr, size, value, user_data):
    typ = {UC_HOOK_MEM_READ: "mem_read", UC_HOOK_MEM_WRITE: "mem_write",
           UC_HOOK_MEM_READ_UNMAPPED: "mem_read_unmapped", UC_HOOK_MEM_WRITE_UNMAPPED: "mem_write_unmapped"}.get(access, f"mem_{access}")
    # For reads we can't get value directly; for writes, 'value' contains the data written
    evt = {"type": typ, "addr": addr, "size": size}
    if access == UC_HOOK_MEM_WRITE:
        evt["value"] = value  # integer
    # attempt to grab the bytes for read/write if mapped
    try:
        evt["raw"] = uc.mem_read(addr, size).hex()
    except UcError:
        evt["raw"] = None
    log_event(evt)
    log_event(dump_regs(uc))

def hook_mem_unmapped(uc, access, addr, size, value, user_data):
    print(f"[!] Unmapped memory access at 0x{addr:x} ({size} bytes)")
    return False  # returning False tells Unicorn to stop

# Add hooks
mu.hook_add(UC_HOOK_CODE, hook_code)
# Normal mapped memory reads/writes
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)

# Unmapped memory accesses (separate hook)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_unmapped)

# --- Start emulation ------------------------------------------------------
print("Starting emulation...")
try:
    print(ENTRY_POINT)
    print(str( IMAGE_BASE + IMAGE_SIZE))
    mu.emu_start(ENTRY_POINT, IMAGE_BASE + IMAGE_SIZE)
except UcError as e:
    print("Emulation stopped with Unicorn error:", e)
finally:
    trace_f.close()
    print(f"Trace written to {TRACE_PATH}")
    print(f"Executed {insn_count} instructions (approx).")