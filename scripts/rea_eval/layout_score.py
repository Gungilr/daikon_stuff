"""Score tier-10 recovered types against DWARF (phase 11, steps 2-3).

For each debug binary: run the tracer at tier 10 with --dump-layouts (the
tracer reads no DWARF), then compare every typed site it can tie to a DWARF
type - a parameter's pointee (function address + register slot) or a global
(address) - with that type's flattened layout.

Metrics
  layout   predicted fields {(offset, width)} vs DWARF leaf fields
           {(offset, size)}: precision, recall, F1; "invented" = a predicted
           field DWARF does not have at that offset and width
  kind     for matched fields: pointer / float / integer right, and
           signedness right when the tracer stated one; abstentions apart
  shape    struct / array / scalar right

Usage:
    python3 scripts/rea_eval/layout_score.py BIN [BIN ...]
"""
import collections
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elftools.elf.elffile import ELFFile  # noqa: E402
from ground_truth import _strip, _ref, _attr, _name, _location_addr  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SHIM = os.path.join(REPO, "scripts", "unicorn_dwarf.py")


def kind_of(die):
    d = _strip(die)
    if d is None:
        return "void", 0, None
    t = d.tag
    size = _attr(d, "DW_AT_byte_size")
    if t == "DW_TAG_base_type":
        enc = _attr(d, "DW_AT_encoding")
        if enc == 4:
            return "float", size, None
        return "int", size, enc in (5, 6)
    if t == "DW_TAG_pointer_type":
        return "pointer", 8, None
    if t == "DW_TAG_enumeration_type":
        return "int", size, None
    if t in ("DW_TAG_structure_type", "DW_TAG_union_type"):
        return ("union" if t == "DW_TAG_union_type" else "struct"), size, None
    if t == "DW_TAG_array_type":
        return "array", size, None
    return "other", size, None


def flatten(sdie, base=0, depth=0):
    """[(offset, size, kind, signed)] leaf members; an array member is one
    field of its element size (the tracer models it as an array field)."""
    out = []
    if depth > 6:
        return out
    for m in sdie.iter_children():
        if m.tag != "DW_TAG_member":
            continue
        off = _attr(m, "DW_AT_data_member_location", 0)
        off = off if isinstance(off, int) else 0
        t = _strip(_ref(m))
        k, size, signed = kind_of(_ref(m))
        if k in ("struct",) and t is not None:
            out.extend(flatten(t, base + off, depth + 1))
        elif k == "array" and t is not None:
            e = _strip(_ref(t))
            ek, es, esg = kind_of(_ref(t))
            if ek == "struct" and e is not None:
                out.extend(flatten(e, base + off, depth + 1))   # first element
            else:
                out.append((base + off, es, ek, esg))
        else:
            out.append((base + off, size, k, signed))
    return out


def truth_layout(die):
    """(shape, fields, stride) for a pointee or global type DIE."""
    d = _strip(die)
    k, size, signed = kind_of(die)
    if k in ("struct", "union"):
        return ("union" if k == "union" else "struct"), flatten(d), None
    if k == "array":
        e = _strip(_ref(d))
        ek, es, esg = kind_of(_ref(d))
        if ek == "struct" and e is not None:
            return "array_of_struct", flatten(e), es
        return "array", [(0, es, ek, esg)], es
    return "scalar", [(0, size, k, signed)], None


def dwarf_index(path):
    """{func_addr: [param type DIEs in order]}, {global_addr: type DIE}."""
    funcs, globs = {}, {}
    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    low = _attr(die, "DW_AT_low_pc")
                    if isinstance(low, int):
                        funcs[low] = [_ref(c) for c in die.iter_children()
                                      if c.tag == "DW_TAG_formal_parameter"]
                elif die.tag == "DW_TAG_variable":
                    a = _location_addr(die)
                    if a is not None and "DW_AT_type" in die.attributes:
                        globs[a] = _ref(die)
    return funcs, globs


def run_tracer(binary, out_json):
    with tempfile.TemporaryDirectory() as d:
        subprocess.run([sys.executable, SHIM, binary, "-o", os.path.join(d, "t.dtrace"),
                        "--start-func", "main", "--tier", "10", "--dump-layouts", out_json],
                       capture_output=True, text=True, timeout=600)


def predicted(t):
    if t is None:
        return None, [], None
    if t["shape"] == "array":
        fs = t["fields"]
        if len(fs) >= 1 and (len(fs) > 1 or fs[0]["width"] != t["stride"]
                             or fs[0]["kind"] == "struct"):
            return "array_of_struct", fs, t["stride"]
        return "array", fs, t["stride"]
    return t["shape"], t["fields"], t["stride"]


def score(binaries):
    C = collections.Counter()
    examples = collections.defaultdict(list)
    for b in binaries:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
            jp = tf.name
        run_tracer(b, jp)
        try:
            dump = json.load(open(jp))
        except Exception:
            C["tracer_failed"] += 1
            continue
        finally:
            os.unlink(jp)
        funcs, globs = dwarf_index(b)
        pairs = []                     # (label, site string, truth DIE)
        for faddr, slots in dump.get("roots", {}).items():
            params = funcs.get(int(faddr, 16), [])
            int_params = [p for p in params if kind_of(p)[0] != "float"]
            for raw, site in slots.items():
                raw = int(raw)
                if raw == 0 or raw > len(int_params):
                    continue
                p = _strip(int_params[raw - 1])
                if p is None or p.tag != "DW_TAG_pointer_type":
                    continue
                pairs.append((f"{os.path.basename(b)} {faddr} arg{raw - 1}", site, _ref(p)))
        for site in dump.get("types", {}):
            if site.startswith("global:"):
                addr = int(site.split(":")[1], 16)
                if addr in globs:
                    pairs.append((f"{os.path.basename(b)} global {hex(addr)}", site, globs[addr]))
        seen = set()
        for label, site, tdie in pairs:
            if (b, site) in seen:
                continue
            seen.add((b, site))
            t = dump["types"].get(site)
            if t is None:
                C["untyped"] += 1
                continue
            tshape, tfields, tstride = truth_layout(tdie)
            pshape, pfields, pstride = predicted(t)
            if tshape == "union":
                C["truth_union"] += 1
                C["union_abstained" if all(f["kind"] == "abstain" for f in pfields) else
                  "union_typed"] += 1
                continue
            C["sites"] += 1
            C[f"shape:{tshape}->{pshape}"] += 1
            C["shape_ok"] += (tshape == pshape)
            if pshape == "array" and tshape == "array":
                C["array_width_ok"] += (pfields and pfields[0]["width"] == tfields[0][1])
                C["array_sites"] += 1
                continue
            truth = {(o, s): (k, sg) for o, s, k, sg in tfields}
            pred = [(f["off"], f["width"], f["kind"], f["signed"]) for f in pfields
                    if f["kind"] != "array_field"]
            for f in pfields:
                if f["kind"] == "array_field":
                    pred.append((f["off"], f["width"], "array_field", f["signed"]))
            for o, w, k, sg in pred:
                C["pred_fields"] += 1
                if k == "abstain":
                    C["abstain_fields"] += 1
                if (o, w) in truth or (k == "array_field" and any(to == o for to, _ in truth)):
                    C["field_tp"] += 1
                    tk, tsg = truth.get((o, w), (None, None))
                    if k in ("abstain", "array_field") or tk is None:
                        continue
                    C["kind_checked"] += 1
                    pk = "pointer" if k == "pointer" else ("float" if k == "float" else "int")
                    ok = pk == tk
                    C["kind_ok"] += ok
                    if not ok and len(examples["kind"]) < 8:
                        examples["kind"].append((label, o, w, k, tk))
                    if ok and pk == "int" and sg is not None and tsg is not None:
                        C["sign_checked"] += 1
                        C["sign_ok"] += (sg == tsg)
                else:
                    C["field_fp"] += 1
                    if len(examples["invented"]) < 10:
                        examples["invented"].append((label, o, w, k))
            C["truth_fields"] += len(truth)
    return C, examples


def pct(a, b):
    return f"{100.0 * a / b:5.1f}%" if b else "  n/a"


def main(argv):
    C, ex = score(argv[1:])
    P = C["field_tp"] / C["pred_fields"] if C["pred_fields"] else 0
    R = C["field_tp"] / C["truth_fields"] if C["truth_fields"] else 0
    F = 2 * P * R / (P + R) if P + R else 0
    print(f"typed sites tied to DWARF: {C['sites']}   (untyped: {C['untyped']}, "
          f"unions: {C['truth_union']} - abstained {C['union_abstained']})")
    print(f"shape right: {pct(C['shape_ok'], C['sites'])}   "
          + ", ".join(f"{k[6:]} {v}" for k, v in sorted(C.items()) if k.startswith("shape:")))
    print(f"scalar arrays: element width right {pct(C['array_width_ok'], C['array_sites'])}"
          f" of {C['array_sites']}")
    print(f"LAYOUT fields: precision {pct(C['field_tp'], C['pred_fields'])}  "
          f"recall {pct(C['field_tp'], C['truth_fields'])}  F1 {100 * F:5.1f}%   "
          f"invented {pct(C['field_fp'], C['pred_fields'])} ({C['field_fp']} of {C['pred_fields']})")
    print(f"KIND (matched fields): right {pct(C['kind_ok'], C['kind_checked'])} of "
          f"{C['kind_checked']}   wrong {pct(C['kind_checked'] - C['kind_ok'], C['kind_checked'])}"
          f"   signedness right {pct(C['sign_ok'], C['sign_checked'])} of {C['sign_checked']}"
          f"   abstained {C['abstain_fields']}")
    for k, v in ex.items():
        for e in v:
            print(f"   [{k}] {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
