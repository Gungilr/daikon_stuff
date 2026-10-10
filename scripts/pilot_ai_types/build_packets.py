"""Blind pilot for AI type recovery on globals.

For each small C test in Daikon's kvasir suite:
  - compile -O0 -gdwarf-3 -no-pie, keep a debug copy and a stripped copy
  - ground truth (from DWARF, debug copy) -> truth.json      (NOT read until scoring)
  - evidence (from STRIPPED copy only)    -> packets/<id>.txt

The global's extent comes from .symtab of the debug copy, matching the tracer's
tier-8 "symbol size known" path (the 72-globals measurement in FORMAL-METHODS.md
used the same assumption). Packets are anonymised: id = g<N>, no names.
"""
import json, os, re, subprocess, sys, random
from elftools.elf.elffile import ELFFile

SUITE = sys.argv[1]
OUT = sys.argv[2]
DIRS = ["ArrayTest", "ArraysInStructTest", "CoercePointerTest", "ConstMergeTest",
        "ConstantTest", "FloatTest", "GlobalTest", "IntTest", "MultiDimArrayTest",
        "NestedStructTest", "NestedStructVarList", "PointerTest",
        "SelectGlobalsTest", "SimpleDisambigStructTest", "StaticArraysTest",
        "StructPtrTest", "TrivialTest", "TypedefTest", "TypesTest", "UnionComp",
        "crazy-test-1", "partial-init", "small-test", "static-struct",
        "string-arrays", "two-statics", "pointer-levels", "local-ptr",
        "function-pointer", "md5", "tcas"]


def die_type_class(die, cu, depth=0):
    """Strip typedef/const/volatile and classify."""
    if depth > 3:
        return "other", "..."
    seen = 0
    while die is not None and seen < 20:
        seen += 1
        tag = die.tag
        if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"):
            if "DW_AT_type" not in die.attributes:
                return "void", "void"
            die = die.get_DIE_from_attribute("DW_AT_type")
            continue
        if tag == "DW_TAG_base_type":
            name = die.attributes["DW_AT_name"].value.decode()
            return "scalar", name
        if tag == "DW_TAG_pointer_type":
            if "DW_AT_type" in die.attributes:
                _, inner = die_type_class(die.get_DIE_from_attribute("DW_AT_type"), cu, depth + 1)
            else:
                inner = "void"
            return "pointer", inner + "*"
        if tag == "DW_TAG_enumeration_type":
            return "scalar", "enum"
        if tag == "DW_TAG_array_type":
            _, inner = die_type_class(die.get_DIE_from_attribute("DW_AT_type"), cu, depth + 1)
            return "array", inner + "[]"
        if tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
            members = []
            for ch in die.iter_children():
                if ch.tag == "DW_TAG_member" and "DW_AT_type" in ch.attributes:
                    k, d = die_type_class(ch.get_DIE_from_attribute("DW_AT_type"), cu, depth + 1)
                    members.append(d)
            return ("struct" if tag == "DW_TAG_structure_type" else "union"), "{" + ", ".join(members) + "}"
        return "other", tag
    return "other", "?"


def dwarf_globals(path):
    out = {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_variable" or "DW_AT_location" not in die.attributes:
                    continue
                loc = die.attributes["DW_AT_location"].value
                if not isinstance(loc, list) or not loc or loc[0] != 0x03:  # DW_OP_addr
                    continue
                addr = int.from_bytes(bytes(loc[1:9]), "little")
                k, d = die_type_class(die.get_DIE_from_attribute("DW_AT_type"), cu)
                name = die.attributes.get("DW_AT_name")
                out[addr] = (name.value.decode() if name else "?", k, d)
    return out


def symtab_objects(path):
    res = {}
    with open(path, "rb") as f:
        elf = ELFFile(f)
        st = elf.get_section_by_name(".symtab")
        secs = {s.name: (s["sh_addr"], s["sh_size"], s) for s in elf.iter_sections()}
        for s in st.iter_symbols():
            if s["st_info"]["type"] == "STT_OBJECT" and s["st_size"] > 0:
                res[s["st_value"]] = s["st_size"]
        data = {}
        for nm in (".data", ".rodata"):
            if nm in secs:
                a, sz, sec = secs[nm]
                data[nm] = (a, sec.data())
        bss = secs.get(".bss", (0, 0, None))[:2]
    return res, data, bss


def rodata_string(v, data):
    if ".rodata" not in data:
        return None
    a, blob = data[".rodata"]
    if not (a <= v < a + len(blob)):
        return None
    end = blob.find(b"\0", v - a)
    raw = blob[v - a:end]
    if 1 <= len(raw) <= 80 and all(32 <= c < 127 or c in (9, 10) for c in raw):
        return raw.decode().replace("\n", "\\n")
    return None


def init_bytes(addr, size, data, bss):
    for nm, (a, blob) in data.items():
        if a <= addr < a + len(blob):
            return nm, blob[addr - a: addr - a + size]
    if bss[0] <= addr < bss[0] + bss[1]:
        return ".bss", bytes(size)
    return "?", b""


def main():
    os.makedirs(os.path.join(OUT, "packets"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "bin"), exist_ok=True)
    truth, gid = {}, 0
    entries = []
    for d in DIRS:
        src_dir = os.path.join(SUITE, d)
        if not os.path.isdir(src_dir):
            continue
        srcs = [os.path.join(src_dir, f) for f in sorted(os.listdir(src_dir)) if f.endswith(".c")]
        if not srcs:
            continue
        dbg = os.path.join(OUT, "bin", d + ".dbg")
        strp = os.path.join(OUT, "bin", d + ".strip")
        r = subprocess.run(["gcc", "-O0", "-gdwarf-3", "-no-pie", "-fno-pie", "-w", "-o", dbg] + srcs + ["-lm"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print("build failed", d, r.stderr[:200], file=sys.stderr)
            continue
        subprocess.run(["strip", "--strip-all", "-o", strp, dbg], check=True)
        dg = dwarf_globals(dbg)
        syms, data, bss = symtab_objects(dbg)
        dis = subprocess.run(["objdump", "-d", "--no-show-raw-insn", "-M", "intel", strp],
                             capture_output=True, text=True).stdout.splitlines()
        for addr, (name, kind, desc) in sorted(dg.items()):
            size = syms.get(addr)
            if not size or name.startswith("__") or name in ("stdin", "stdout", "stderr", "completed.0"):
                continue
            sec, ib = init_bytes(addr, size, data, bss)
            # lines that reference any address inside [addr, addr+size): merge
            # +-3 line windows into one deduplicated listing, annotate .rodata strings
            keep, nref = set(), 0
            for i, line in enumerate(dis):
                for m in re.finditer(r"(?:# |\b0x)([0-9a-f]{6,})", line):
                    v = int(m.group(1), 16)
                    if addr <= v < addr + size:
                        nref += 1
                        keep.update(range(max(0, i - 3), min(len(dis), i + 4)))
                        break
            lines, prev = [], None
            for i in sorted(keep)[:90]:
                if prev is not None and i != prev + 1:
                    lines.append("  ...")
                ln = dis[i]
                for m in re.finditer(r"0x([0-9a-f]{6})\b", ln):
                    st = rodata_string(int(m.group(1), 16), data)
                    if st:
                        ln += f'   ; "{st}"'
                        break
                if addr <= max([int(x, 16) for x in re.findall(r"(?:# |\b0x)([0-9a-f]{6,})", ln)] or [0]) < addr + size:
                    ln = ln + "   <== g"
                lines.append("  " + ln.strip())
                prev = i
            refs_txt = "\n".join(lines) if lines else "  (no instruction references this address range)"
            gid += 1
            key = f"g{gid:03d}"
            truth[key] = {"binary": d, "name": name, "kind": kind, "type": desc,
                          "addr": hex(addr), "size": size}
            pkt = (f"global {key} at {hex(addr)}, extent {size} bytes, section {sec}\n"
                   f"initial bytes: {ib.hex(' ') if ib else '(none)'}\n"
                   f"instructions touching it ({nref}), with context:\n"
                   + refs_txt + "\n")
            with open(os.path.join(OUT, "packets", key + ".txt"), "w") as f:
                f.write(pkt)
            entries.append(key)
    with open(os.path.join(OUT, "truth.json"), "w") as f:
        json.dump(truth, f, indent=1)
    print(len(entries), "globals packeted")


if __name__ == "__main__":
    main()
