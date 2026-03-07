#!/usr/bin/env python3
from __future__ import print_function
import json
import struct
import sys
import os
import pefile
from capstone import *
from unicorn import *
from unicorn.x86_const import *

upck32 = lambda x: struct.unpack('I', x)[0]
pck32 = lambda x: struct.pack('I', x)

# Memory layout constants
TEB_BASE = 0x7000
PEB_BASE = 0x3000
PEB_LDR_BASE = 0x13000
STACK_BASE = 0x30000
STACK_LIMIT = 0x1000
TRACE_PATH = "trace.jsonl"
DAIKON_PATH = "trace.dtrace"
EXE_PATH = "test.exe"
DLL_DIR = ".\dll"

# GDT setup
GDT_ADDR = 0x5000
GDT_SIZE = 0x1000

# DLL loading base
DLL_BASE_START = 0x10000000
DLL_BASE_INCREMENT = 0x01000000

def create_segment_descriptor(base, limit, access, flags):
    """Create a proper segment descriptor for GDT."""
    descriptor = (
        (limit & 0xFFFF) |
        ((base & 0xFFFF) << 16) |
        (((base >> 16) & 0xFF) << 32) |
        ((access & 0xFF) << 40) |
        (((limit >> 16) & 0xF) << 48) |
        ((flags & 0xF) << 52) |
        (((base >> 24) & 0xFF) << 56)
    )
    return descriptor

def u32(x): return struct.pack("<I", x)

# --- Daikon Trace Writer ---
class DaikonTraceWriter:
    def __init__(self, filepath):
        self.filepath = filepath
        self.declared_ppts = {}  # ppt_name -> number of variables
        self.data_samples = []   # list of (ppt_name, values)
    
    def add_sample(self, ppt_name, var_values):
        """Add a data sample and auto-declare if needed"""
        # Auto-declare based on number of values
        if ppt_name not in self.declared_ppts:
            num_vars = len(var_values)
            self.declared_ppts[ppt_name] = num_vars
        
        self.data_samples.append((ppt_name, var_values))
    
    def close(self):
        """Write everything to file: declarations first, then data"""
        with open(self.filepath, 'w') as f:
            # Write header
            f.write("decl-version 2.0\n")
            f.write("var-comparability none\n\n")
            
            # Write all declarations
            for ppt_name, num_vars in self.declared_ppts.items():
                f.write(f"ppt {ppt_name}\n")
                f.write("ppt-type enter\n")
                
                # Generate placeholder variable names: var0, var1, var2, ...
                for i in range(num_vars):
                    f.write(f"variable var{i}\n")
                    f.write("  var-kind variable\n")
                    f.write("  dec-type int\n")
                    f.write("  rep-type int\n")
                    f.write("  comparability 22\n")
                
                f.write("\n")
            
            # Write all data samples
            for ppt_name, var_values in self.data_samples:
                f.write(f"{ppt_name}\n")
                
                # Write variable_name, value pairs
                for i, value in enumerate(var_values):
                    f.write(f"var{i}\n")
                    f.write(f"{value}\n")
                
                f.write("\n")

# --- Load PE ---------------------------------------------------------------
pe = pefile.PE(EXE_PATH)
IMAGE_BASE = pe.OPTIONAL_HEADER.ImageBase or 0x400000
ENTRY_POINT = IMAGE_BASE + pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f"PE image base: 0x{IMAGE_BASE:x}, entry: 0x{ENTRY_POINT:x}")

# --- Unicorn init ---------------------------------------------------------
mu = Uc(UC_ARCH_X86, UC_MODE_32)

print("\n[+] Setting up memory map...")

# 0. Map null page
NULL_PAGE_ADDR = 0x0000
NULL_PAGE_SIZE = 0x1000
mu.mem_map(NULL_PAGE_ADDR, NULL_PAGE_SIZE)
mu.mem_write(NULL_PAGE_ADDR, b'\x00' * NULL_PAGE_SIZE)
print(f"  Mapped null page: 0x{NULL_PAGE_ADDR:x} - 0x{NULL_PAGE_SIZE:x}")

# 1. Low memory region
LOW_MEM_BASE = 0x1000
LOW_MEM_SIZE = 0x1F000
mu.mem_map(LOW_MEM_BASE, LOW_MEM_SIZE)
print(f"  Mapped low memory: 0x{LOW_MEM_BASE:x} - 0x{LOW_MEM_BASE+LOW_MEM_SIZE:x}")

# 2. Stack region
STACK_ADDR = 0x0fff0000
STACK_SIZE = 0x20000
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.reg_write(UC_X86_REG_ESP, STACK_ADDR + STACK_SIZE - 4)
print(f"  Mapped stack: 0x{STACK_ADDR:x} - 0x{STACK_ADDR+STACK_SIZE:x}")

# 3. Handler/trampoline area for imports
HANDLER_BASE = 0x30000000
HANDLER_SIZE = 0x00100000
mu.mem_map(HANDLER_BASE, HANDLER_SIZE)
print(f"  Mapped handler area: 0x{HANDLER_BASE:x} - 0x{HANDLER_BASE+HANDLER_SIZE:x}")

# 4. PE image region
IMAGE_SIZE = max(pe.OPTIONAL_HEADER.SizeOfImage, 2 * 1024 * 1024)
map_base = IMAGE_BASE
mu.mem_map(map_base, IMAGE_SIZE)
print(f"  Mapped PE image: 0x{map_base:x} - 0x{map_base+IMAGE_SIZE:x}")

# Map and write PE sections
for section in pe.sections:
    va = IMAGE_BASE + section.VirtualAddress
    data = section.get_data()
    mu.mem_write(va, data)
    print(f"    Section {section.Name.decode(errors='ignore').strip()} -> 0x{va:x} ({len(data)} bytes)")

# --- Setup GDT ---
print("\n[+] Setting up GDT...")

gdt_entries = [
    0x0000000000000000,
    create_segment_descriptor(0, 0xFFFFF, 0x9A, 0xC),
    create_segment_descriptor(0, 0xFFFFF, 0x92, 0xC),
    create_segment_descriptor(TEB_BASE, 0xFFFFF, 0x92, 0xC),
]

for i, entry in enumerate(gdt_entries):
    mu.mem_write(GDT_ADDR + i * 8, entry.to_bytes(8, 'little'))
    base = (entry >> 16) & 0xFFFF | ((entry >> 32) & 0xFF) << 16 | ((entry >> 56) & 0xFF) << 24
    limit = (entry & 0xFFFF) | ((entry >> 48) & 0xF) << 16
    access = (entry >> 40) & 0xFF
    flags = (entry >> 52) & 0xF
    print(f"  GDT[{i}] (selector 0x{i*8:02x}): 0x{entry:016x}")
    if i > 0:
        print(f"    Base=0x{base:08x}, Limit=0x{limit:05x}, Access=0x{access:02x}, Flags=0x{flags:01x}")

gdtr_limit = len(gdt_entries) * 8 - 1
mu.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, gdtr_limit, 0))
print(f"  GDTR set: base=0x{GDT_ADDR:x}, limit=0x{gdtr_limit:x}")

# --- Initialize TEB/PEB ---
print(f"\n[+] Initializing TEB at 0x{TEB_BASE:x}...")
teb = bytearray(0x1000)
struct.pack_into('<I', teb, 0x18, TEB_BASE)
struct.pack_into('<I', teb, 0x30, PEB_BASE)
struct.pack_into('<I', teb, 0x04, STACK_ADDR + STACK_SIZE)
struct.pack_into('<I', teb, 0x08, STACK_ADDR)
mu.mem_write(TEB_BASE, bytes(teb))

print(f"[+] Initializing PEB at 0x{PEB_BASE:x}...")
peb = bytearray(0x1000)
struct.pack_into('<I', peb, 0x08, IMAGE_BASE)
struct.pack_into('<I', peb, 0x0C, PEB_LDR_BASE)
struct.pack_into('<I', peb, 0x10, 0)
struct.pack_into('<B', peb, 0x02, 0)
mu.mem_write(PEB_BASE, bytes(peb))

print(f"[+] Initializing PEB_LDR_DATA at 0x{PEB_LDR_BASE:x}...")
ldr = bytearray(0x1000)
for offset in [0x0C, 0x14, 0x1C]:
    struct.pack_into('<I', ldr, offset, PEB_LDR_BASE + offset)
    struct.pack_into('<I', ldr, offset + 4, PEB_LDR_BASE + offset)
mu.mem_write(PEB_LDR_BASE, bytes(ldr))

# Set segment registers
FS_SELECTOR = 0x18
mu.reg_write(UC_X86_REG_FS, FS_SELECTOR)
mu.reg_write(UC_X86_REG_DS, 0x10)
mu.reg_write(UC_X86_REG_ES, 0x10)
mu.reg_write(UC_X86_REG_SS, 0x10)

print("\n[+] Memory map complete!")

# --- Load DLLs ---
loaded_dlls = {}
dll_load_base = DLL_BASE_START

def load_dll(dll_name):
    """Load a DLL into memory and return its base address and exports."""
    global dll_load_base
    
    dll_path = None
    for name_variant in [dll_name, dll_name.lower(), dll_name.upper()]:
        test_path = os.path.join(DLL_DIR, name_variant)
        if os.path.exists(test_path):
            dll_path = test_path
            break
    
    if not dll_path:
        print(f"  [!] DLL not found: {dll_name}")
        return None
    
    try:
        dll_pe = pefile.PE(dll_path)
    except Exception as e:
        print(f"  [!] Failed to parse {dll_name}: {e}")
        return None
    
    dll_size = max(dll_pe.OPTIONAL_HEADER.SizeOfImage, 1 * 1024 * 1024)
    page_size = 0x1000
    dll_size = ((dll_size + page_size - 1) // page_size) * page_size
    
    dll_base = dll_load_base
    dll_load_base += DLL_BASE_INCREMENT
    
    try:
        mu.mem_map(dll_base, dll_size)
        print(f"  [+] Loaded {dll_name} at 0x{dll_base:x} (size: 0x{dll_size:x})")
    except UcError as e:
        print(f"  [!] Failed to map memory for {dll_name}: {e}")
        return None
    
    for section in dll_pe.sections:
        va = dll_base + section.VirtualAddress
        data = section.get_data()
        try:
            mu.mem_write(va, data)
        except UcError as e:
            print(f"      [!] Failed to write section {section.Name}: {e}")
    
    exports = {}
    if hasattr(dll_pe, 'DIRECTORY_ENTRY_EXPORT'):
        export_count = 0
        for exp in dll_pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                func_name = exp.name.decode('utf-8', errors='ignore')
                func_rva = exp.address
                func_va = dll_base + func_rva
                exports[func_name] = func_va
                export_count += 1
                if export_count <= 5:
                    print(f"      Export: {func_name} -> 0x{func_va:x}")
        if export_count > 5:
            print(f"      ... and {export_count - 5} more exports")
    
    loaded_dlls[dll_name.lower()] = {
        'base': dll_base,
        'size': dll_size,
        'exports': exports,
        'pe': dll_pe
    }
    
    return dll_base

print("\n[+] Loading DLLs...")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode(errors='ignore')
        if dll_name.lower() not in loaded_dlls:
            load_dll(dll_name)

# --- Resolve imports ---
print("\n[+] Resolving imports...")
import_map = {}

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode(errors='ignore')
        dll_info = loaded_dlls.get(dll_name.lower())
        
        for imp in dll.imports:
            if not imp.address:
                continue
            
            iat_va = imp.address
            func_name = imp.name.decode(errors='ignore') if imp.name else f"ordinal_{imp.ordinal}"
            
            func_va = None
            if dll_info and func_name in dll_info['exports']:
                func_va = dll_info['exports'][func_name]
                print(f"  Resolved {dll_name}!{func_name} -> 0x{func_va:x}")
                
                mu.mem_write(iat_va, struct.pack('<I', func_va))
                import_map[func_va] = {"dll": dll_name, "name": func_name, "iat_va": iat_va}
            else:
                handler_va = HANDLER_BASE + len(import_map) * 0x100
                handler_bytes = b"\xB8" + struct.pack("<I", 0) + b"\xC3"
                mu.mem_write(handler_va, handler_bytes)
                mu.mem_write(iat_va, struct.pack('<I', handler_va))
                import_map[handler_va] = {"dll": dll_name, "name": func_name, "iat_va": iat_va}
                print(f"  Stubbed {dll_name}!{func_name} -> 0x{handler_va:x}")

print(f"\n[+] Resolved/stubbed {len(import_map)} imports")

# --- Initialize trace writers ---
MAX_INSNS = 100000
insn_count = 0

cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = False

# Both trace files
trace_f = open(TRACE_PATH, "w", buffering=1)
dtrace = DaikonTraceWriter(DAIKON_PATH)

def dump_regs(uc):
    return {
        "eip": uc.reg_read(UC_X86_REG_EIP),
        "esp": uc.reg_read(UC_X86_REG_ESP),
        "ebp": uc.reg_read(UC_X86_REG_EBP),
        "eax": uc.reg_read(UC_X86_REG_EAX),
        "ebx": uc.reg_read(UC_X86_REG_EBX),
        "ecx": uc.reg_read(UC_X86_REG_ECX),
        "edx": uc.reg_read(UC_X86_REG_EDX),
    }

def log_event(obj):
    trace_f.write(json.dumps(obj) + "\n")

def hook_code(uc, address, size, user_data):
    global insn_count
    insn_count += 1
    try:
        code = uc.mem_read(address, size)
    except UcError:
        code = b""
    
    insn = None
    for i in cs.disasm(code, address):
        insn = {"mnemonic": i.mnemonic, "op_str": i.op_str, "bytes": i.bytes.hex()}
        break
    
    if address in import_map:
        info = import_map[address]
        
        # Write to JSON
        evt = {
            "type": "import_call",
            "pc": address,
            "dll": info["dll"],
            "name": info["name"],
            "iat_va": info["iat_va"],
            "regs_before": dump_regs(uc)
        }
        log_event(evt)
        
        # Write to Daikon - just pass values, names auto-generated
        func_name = f"{info['dll']}::{info['name']}"
        ppt_enter = f"{func_name}:::ENTER"
        
        # Just pass the register values - placeholder names generated automatically
        reg_values = [
            uc.reg_read(UC_X86_REG_EAX),
            uc.reg_read(UC_X86_REG_EBX),
            uc.reg_read(UC_X86_REG_ECX),
            uc.reg_read(UC_X86_REG_EDX),
            uc.reg_read(UC_X86_REG_ESP),
            uc.reg_read(UC_X86_REG_EBP),
        ]
        dtrace.add_sample(ppt_enter, reg_values)
        
    else:
        # Regular instruction - only JSON
        evt = {
            "type": "insn",
            "pc": address,
            "size": size,
            "disasm": f"{insn['mnemonic']} {insn['op_str']}" if insn else None,
            "bytes": insn['bytes'] if insn else None,
            "regs": dump_regs(uc),
        }
        log_event(evt)
    
    if MAX_INSNS and insn_count >= MAX_INSNS or uc.reg_read(UC_X86_REG_EIP) == 0:
        uc.emu_stop()

def hook_mem(uc, access, addr, size, value, user_data):
    typ = {UC_HOOK_MEM_READ: "mem_read", UC_HOOK_MEM_WRITE: "mem_write"}.get(access, f"mem_{access}")
    evt = {"type": typ, "addr": addr, "size": size}
    if access == UC_HOOK_MEM_WRITE:
        evt["value"] = value
    try:
        evt["raw"] = uc.mem_read(addr, size).hex()
    except UcError:
        evt["raw"] = None
    log_event(evt)

def hook_mem_unmapped(uc, access, addr, size, value, user_data):
    access_type = {
        UC_HOOK_MEM_READ_UNMAPPED: "READ",
        UC_HOOK_MEM_WRITE_UNMAPPED: "WRITE",
        UC_HOOK_MEM_FETCH_UNMAPPED: "FETCH"
    }.get(access, f"UNKNOWN({access})")
    
    print(f"\n[!] Unmapped memory {access_type} at 0x{addr:x} ({size} bytes)")
    
    eip = uc.reg_read(UC_X86_REG_EIP)
    esp = uc.reg_read(UC_X86_REG_ESP)
    print(f"    Current EIP: 0x{eip:x}, ESP: 0x{esp:x}")
    
    try:
        code = uc.mem_read(eip, 15)
        for i in cs.disasm(code, eip):
            print(f"    Instruction: 0x{i.address:x}: {i.mnemonic} {i.op_str}")
            break
    except:
        pass
    
    if access in [UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED]:
        page_addr = (addr // 0x1000) * 0x1000
        try:
            uc.mem_map(page_addr, 0x1000)
            uc.mem_write(page_addr, b'\x00' * 0x1000)
            print(f"    [+] Mapped page at 0x{page_addr:x}, continuing")
            return True
        except Exception as e:
            print(f"    [!] Failed to map: {e}")
    
    log_event({"type": "unmapped_access", "addr": addr, "size": size, "access": access_type, "eip": eip})
    return False

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, hook_mem)
mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_unmapped)

# --- Start emulation ---
print("\n[+] Starting emulation...")
print(f"  Entry point: 0x{ENTRY_POINT:x}")

try:
    mu.emu_start(ENTRY_POINT, IMAGE_BASE + IMAGE_SIZE)
    print("\n[+] Emulation completed successfully!")
except UcError as e:
    print(f"\n[!] Emulation stopped: {e}")
    try:
        final_eip = mu.reg_read(UC_X86_REG_EIP)
        print(f"  Final EIP: 0x{final_eip:x}")
    except:
        pass
finally:
    trace_f.close()
    dtrace.close()
    print(f"\n[+] JSON trace written to {TRACE_PATH}")
    print(f"[+] Daikon trace written to {DAIKON_PATH}")
    print(f"[+] Executed {insn_count} instructions")