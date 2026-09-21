#!/usr/bin/env python3
"""Score tracer invariants against Kvasir's, the project's actual metric.

Counts cannot answer "how close are we" - test09 once showed 8 against 8 and
agreed on only 7 of them. This compares CONTENT.

Three problems have to be solved before two reports can be compared at all:

  1. NAMES. Stripping destroys them, so the tracer emits `arg0`, `arg0[].off4`.
     DWARF is read HERE, at scoring time only, to map those onto Kvasir's `p`,
     `p[].b`. This is the one place DWARF is allowed; feeding it back into the
     tracer would invalidate the whole experiment.

  2. FORM. Daikon prints the same fact many ways depending on which variable it
     anchors to: `a - c + 1 == 0` and `c - a - 1 == 0` are one invariant. Linear
     relations are parsed and put in a canonical form rather than string-matched.

  3. ORACLE DEFECTS. Kvasir sets `flags is_param`, which makes Daikon drop
     non-unit coefficients and suppress correct invariants outright. Some of
     what it reports is false on its own samples. Those are counted separately
     rather than held against the tracer - see --show-oracle-bugs.

Usage:
    score_invariants.py --kvasir invariants/test08.kvasir.txt \\
                        --tracer invariants/test08.tracer.t7.txt \\
                        --binary tests/test08.exe
"""
from __future__ import print_function

import argparse
import math
import os
import re
import sys

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("[!] needs pyelftools", file=sys.stderr)
    sys.exit(1)


# --- report parsing ---------------------------------------------------------

_NOISE = re.compile(
    r"^(=+|Daikon version.*|Exiting Daikon.*|Reading .*|Processing .*|\[\d{4}-.*)$")


def parse_report(path):
    """{ppt_name: [invariant, ...]} from a Daikon text report.

    Carriage returns are stripped and leading whitespace removed first: Daikon's
    progress output overwrites with CRs and can leave padding on an invariant
    line, which silently corrupts naive line filters.
    """
    out, ppt = {}, None
    with open(path, errors="replace") as f:
        for raw in f:
            line = raw.replace("\r", "").strip()
            if not line or _NOISE.match(line):
                continue
            if ":::" in line:
                ppt = line
                out.setdefault(ppt, [])
            elif ppt is not None:
                out[ppt].append(line)
    return out


# --- DWARF: the only place debug info is read -------------------------------

def dwarf_globals(elf_path):
    """{address: name} for file-scope variables, from DWARF.

    Tier 8 names a global by its address - `g_0x404018` - because stripping
    destroys the name and an address is the only identity left. This maps them
    back onto Kvasir's `::globalInt`, at scoring time only, exactly as
    parameter names are mapped.
    """
    out = {}
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return out
        for cu in elf.get_dwarf_info().iter_CUs():
            for die in cu.get_top_DIE().iter_children():
                if die.tag != "DW_TAG_variable":
                    continue
                nm = die.attributes.get("DW_AT_name")
                loc = die.attributes.get("DW_AT_location")
                if not nm or not loc or not isinstance(loc.value, list):
                    continue
                # DW_OP_addr (0x03) is what marks a static storage location;
                # a local's location is a frame-base offset and must not match.
                if not loc.value or loc.value[0] != 0x03:
                    continue
                addr = int.from_bytes(bytes(loc.value[1:9]), "little")
                out[addr] = nm.value.decode()
    return out


def dwarf_names(elf_path):
    """(params, fields): {func: [param names]}, {func: {offset: field name}}."""
    params, fields = {}, {}
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            return params, fields
        dw = elf.get_dwarf_info()
        for cu in dw.iter_CUs():
            dies = {d.offset: d for d in cu.iter_DIEs()}
            for die in cu.iter_DIEs():
                if die.tag != "DW_TAG_subprogram":
                    continue
                name = die.attributes.get("DW_AT_name")
                if not name:
                    continue
                fname = name.value.decode()
                plist, fmap = [], {}
                for child in die.iter_children():
                    if child.tag != "DW_TAG_formal_parameter":
                        continue
                    pn = child.attributes.get("DW_AT_name")
                    plist.append(pn.value.decode() if pn else f"arg{len(plist)}")
                    # Follow parameter -> pointer -> struct to name its members.
                    t = child.attributes.get("DW_AT_type")
                    seen = set()
                    while t is not None and t.value not in seen:
                        seen.add(t.value)
                        td = dies.get(t.value + cu.cu_offset) or dies.get(t.value)
                        if td is None:
                            break
                        if td.tag == "DW_TAG_structure_type":
                            for m in td.iter_children():
                                if m.tag == "DW_TAG_member":
                                    mn = m.attributes.get("DW_AT_name")
                                    off = m.attributes.get(
                                        "DW_AT_data_member_location")
                                    if mn and off is not None:
                                        fmap[off.value] = mn.value.decode()
                            break
                        t = td.attributes.get("DW_AT_type")
                if plist:
                    params[fname] = plist
                if fmap:
                    fields[fname] = fmap
    return params, fields


def global_rename_map(globals_by_addr):
    """`g_0x404018` -> `::globalInt`, longest key first."""
    m = {}
    for addr, name in globals_by_addr.items():
        m[f"g_0x{addr:x}"] = f"::{name}"
    return m


def rename_map(func, params, fields):
    """Tracer variable name -> Kvasir variable name, longest key first."""
    m = {}
    plist = params.get(func, [])
    fmap = fields.get(func, {})
    for i, pname in enumerate(plist):
        for off, fname in fmap.items():
            m[f"arg{i}[].off{off}"] = f"{pname}[].{fname}"
        m[f"arg{i}[]"] = f"{pname}[]"
        m[f"arg{i}"] = pname
    return dict(sorted(m.items(), key=lambda kv: -len(kv[0])))


def apply_renames(inv, mapping):
    """Rewrite tracer names to Kvasir names, innermost occurrences included.

    The lookbehind deliberately does NOT exclude `[`. Daikon derives indexed
    elements, and the index is a variable in its own right: we emit
    `arr[arg1-1]` where Kvasir emits `arr[n-1]`. Blocking a match after `[`
    left the subscript un-renamed and scored four true facts on test13 as
    simultaneous misses and false positives.
    """
    for src, dst in mapping.items():
        inv = re.sub(r"(?<![\w\].])" + re.escape(src) + r"(?![\w])",
                     dst, inv)
    return inv


# --- canonical form ---------------------------------------------------------

# Daikon prints large values two ways depending on the variable's declared
# type: `2.147483648E9` from our int trace, `-2.14748e+09` from Kvasir's. Both
# spellings must parse as numbers, or the `e` is read as a variable name and
# the whole invariant falls through uncanonicalized - which scored the one
# signedness fact phase 8 recovered as a miss AND a false positive.
_NUM = r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?"
# The (?<![\d.]) stops the `E9` of `2.147483648E9` being read as a variable
# name, which used to abort the term scan and leave the invariant uncanonical.
_DOUBLE_SIGN = re.compile(r"(?<![eE])[+-][+-]")


def fold_signs(s):
    """`a+-b` -> `a-b`, `a--b` -> `a+b`, on a whitespace-free expression.

    Daikon writes a negative coefficient as `+ -1*x` and a negative constant
    subtraction as `- -2147483648`. Both parsers here scan signs positionally,
    so a doubled sign must be collapsed first. Getting this wrong is not a
    cosmetic matter: `return - orig(x) - -2147483648 == 0` was silently read
    as `... - 2147483648`, which flipped a FALSE oracle fact into a true one
    and cost the tracer a point of recall for being right about it.

    The lookbehind spares an exponent's sign, which always follows an `e`.
    """
    for _ in range(4):
        folded = _DOUBLE_SIGN.sub(lambda m: "+" if m.group() in ("--", "++")
                                  else "-", s)
        if folded == s:
            return s
        s = folded
    return s
_TERM = re.compile(r"([+-]?)\s*(?:(" + _NUM + r")\s*\*\s*)?(?<![\d.])"
                   r"([A-Za-z_][\w().\[\]]*)")
_CONST = re.compile(r"([+-])(" + _NUM + r")(?![\w*])")


def canonical(inv):
    """Canonicalize an invariant so equivalent spellings compare equal.

    Two normalizations, then the input unchanged if neither applies.

    `a - c + 1 == 0` and `c - a - 1 == 0` are the same fact. Daikon's choice of
    anchor variable is arbitrary, so both are reduced to one normal form:
    coefficients divided by their gcd, sign fixed so the alphabetically first
    variable is positive, terms sorted.
    """
    # Comparisons are directional but not canonical: `return >= orig(b)` and
    # `b <= return` are one fact, and Daikon picks a side arbitrarily. Rewrite
    # every > and >= into < and <= with the operands swapped, so both spellings
    # land on the same string.
    flip = {" >= ": " <= ", " > ": " < "}
    for src, dst in flip.items():
        if src in inv:
            head, _, tail = inv.partition(src)
            suffix = ""
            for mark in (" (elementwise)",):
                if tail.endswith(mark):
                    tail, suffix = tail[: -len(mark)], mark
            inv = f"{tail.strip()}{dst}{head.strip()}{suffix}"
            break

    # Equality is symmetric, and Daikon's operand order is arbitrary:
    # `p == return` and `return == p` are one fact. Sort the two sides when
    # neither is an arithmetic expression.
    if " == " in inv and not inv.rstrip().endswith("== 0"):
        lhs, _, rhs = inv.partition(" == ")
        if not re.search(r"[-+*]", lhs + rhs):
            lo, hi = sorted((lhs.strip(), rhs.strip()))
            return f"{lo} == {hi}"

    s = fold_signs(inv.replace(" ", ""))
    if not s.endswith("==0") or "==" not in s:
        return inv
    body = s[:-3]
    if not re.fullmatch(r"[-+0-9.eE*\w().\[\]]+", body):
        return inv

    coeffs, const, pos = {}, 0.0, 0
    for m in _TERM.finditer(body):
        if m.start() != pos:
            return inv                      # unparsed gap: leave it alone
        sign = -1.0 if m.group(1) == "-" else 1.0
        c = float(m.group(2)) if m.group(2) else 1.0
        coeffs[m.group(3)] = coeffs.get(m.group(3), 0.0) + sign * c
        pos = m.end()
    for m in re.finditer(_CONST, body):
        if m.start() >= pos:
            const += (-1.0 if m.group(1) == "-" else 1.0) * float(m.group(2))
            pos = m.end()
    if pos != len(body) or not coeffs:
        return inv

    vals = [v for v in coeffs.values() if v] + ([const] if const else [])
    if not vals:
        return inv
    g = 0.0
    for v in vals:
        g = math.gcd(int(abs(v)), int(g)) if float(v).is_integer() else 1
    scale = float(g) if g else 1.0
    first = sorted(k for k, v in coeffs.items() if v)
    if not first:
        return inv
    if coeffs[first[0]] < 0:
        scale = -scale
    terms = [f"{coeffs[k] / scale:g}*{k}" for k in sorted(coeffs) if coeffs[k]]
    c = const / scale
    return " + ".join(terms) + (f" + {c:g}" if c else "") + " == 0"



def unchanged_vars(*invariant_lists):
    """Variables asserted equal to their entry value, from either side.

    An unmodified parameter makes `f(v)` and `f(orig(v))` the same fact, and
    Daikon's choice between them is arbitrary. test03 is the clean example:

        kvasir:  orig(num) - return + 1 == 0
        tracer:  num - return + 1 == 0    AND    num == orig(num)

    Those are one invariant, and exact set matching scored it as a miss AND a
    false positive - penalising the tracer twice for agreeing. Collecting the
    equality from either report is sound because it is an observed fact about
    the same execution, not an assumption.
    """
    out = set()
    marker = " == orig("
    for lst in invariant_lists:
        for inv in lst:
            text = inv.strip()
            # Matched without a regex backreference (escapes do not survive
            # this repo's patch pipeline): "X == orig(X)" holds when the two
            # names are literally the same token.
            if marker not in text or not text.endswith(")"):
                continue
            lhs, _, rhs = text.partition(marker)
            if lhs and lhs == rhs[:-1]:
                out.add(lhs)
                # A sequence that does not change cannot change length, so
                # size(S) is unchanged too. Daikon reports the size relation
                # over orig() on one side and the current value on the other,
                # and without this every `orig(size(p[]))` fact reads as a miss.
                if lhs.endswith("[]"):
                    out.add(f"size({lhs})")
    return out


def drop_orig(inv, unchanged):
    """Rewrite orig(v) -> v for provably unmodified v; drop tautologies."""
    for v in unchanged:
        inv = re.sub(r"orig\(" + re.escape(v) + r"\)", v, inv)
    lhs, eq, rhs = inv.partition(" == ")
    if eq and lhs.strip() == rhs.strip():
        return None                       # v == v carries no information
    return inv



# --- oracle validation -----------------------------------------------------

def parse_dtrace(path):
    """{ppt: [{var: value}]} with orig(v) resolved through the nonce.

    Used to check the ORACLE against its own data. Kvasir sets `flags
    is_param`, which makes Daikon drop non-unit coefficients, so some of what
    it reports is false on the very samples it was given. Scoring the tracer
    against those costs it recall for being right.
    """
    samples, entries = {}, {}
    ppt = nonce = None
    cur = {}
    with open(path, errors="replace") as f:
        lines = f.read().replace(chr(13), '').split(chr(10))
    i = 0
    while i < len(lines):
        line = lines[i]
        if ":::" in line and not line.startswith(" "):
            if ppt and cur:
                samples.setdefault(ppt, []).append((nonce, cur))
            ppt, cur, nonce = line, {}, None
            i += 1
            if i < len(lines) and lines[i] == "this_invocation_nonce":
                nonce = lines[i + 1]; i += 2
            continue
        if ppt and line and i + 1 < len(lines):
            val = lines[i + 1]
            try:
                cur[line] = int(val)
            except ValueError:
                pass
            i += 3 if (i + 2 < len(lines) and lines[i + 2] in ("0", "1", "2")) else 2
            continue
        i += 1
    if ppt and cur:
        samples.setdefault(ppt, []).append((nonce, cur))

    for p, lst in samples.items():
        if p.endswith(":::ENTER"):
            for nc, vals in lst:
                entries[(p[:-len(":::ENTER")], nc)] = vals
    out = {}
    for p, lst in samples.items():
        base = p.split(":::")[0]
        rows = []
        for nc, vals in lst:
            merged = dict(vals)
            for k, v in entries.get((base, nc), {}).items():
                merged[f"orig({k})"] = v
            rows.append(merged)
        out[p] = rows
    return out


def invariant_holds(inv, rows):
    """True/False for a linear equality over known variables; None if unsure."""
    s = fold_signs(inv.replace(" ", ""))
    if not s.endswith("==0"):
        return None
    body = s[:-3]
    coeffs, const, pos = {}, 0.0, 0
    for m in _TERM.finditer(body):
        if m.start() != pos:
            return None
        sign = -1.0 if m.group(1) == "-" else 1.0
        c = float(m.group(2)) if m.group(2) else 1.0
        coeffs[m.group(3)] = coeffs.get(m.group(3), 0.0) + sign * c
        pos = m.end()
    for m in re.finditer(_CONST, body):
        if m.start() >= pos:
            const += (-1.0 if m.group(1) == "-" else 1.0) * float(m.group(2))
            pos = m.end()
    if pos != len(body) or not coeffs or not rows:
        return None
    checked = 0
    for row in rows:
        if not all(v in row for v in coeffs):
            continue
        checked += 1
        if abs(sum(c * row[v] for v, c in coeffs.items()) + const) > 1e-6:
            return False
    return True if checked else None


def false_oracle_facts(kvasir_report, kvasir_dtrace):
    """[(ppt, invariant)] that Kvasir reports and its own samples contradict."""
    rows_by_ppt = parse_dtrace(kvasir_dtrace)
    bad = []
    for ppt, invs in parse_report(kvasir_report).items():
        rows = rows_by_ppt.get(ppt) or rows_by_ppt.get(ppt.replace(":::EXIT", ":::EXIT0"))
        if not rows:
            continue
        for inv in invs:
            if invariant_holds(inv, rows) is False:
                bad.append((ppt, inv))
    return bad


# --- scoring ----------------------------------------------------------------

_FILE_SCOPED = re.compile(r"^.*/[^/]*\.(?:c|cc|cpp|cxx)\.")


def norm_ppt(name):
    """Align the two tools' spellings of the same program point.

    Two differences, both cosmetic and both fatal to a set comparison:

      * Daikon prints EXIT0 as EXIT once the exits are combined.
      * Kvasir qualifies a `static` function with its source path -
        `/abs/path/TypedefTest.c.createCopy()` where we emit `..createCopy()`.
        Eight program points in Daikon's own Kvasir suite are named this way,
        and without stripping the prefix every fact at them scored as a miss
        AND a false positive, because the function name never reached the
        DWARF rename map.
    """
    return _FILE_SCOPED.sub("..", name).replace(":::EXIT0", ":::EXIT")


def score(kvasir_path, tracer_path, binary):
    params, fields = dwarf_names(binary)
    gmap = global_rename_map(dwarf_globals(binary))
    kv = {norm_ppt(k): v for k, v in parse_report(kvasir_path).items()}
    tr = {norm_ppt(k): v for k, v in parse_report(tracer_path).items()}

    rows, tot_m, tot_k, tot_t = [], 0, 0, 0
    for ppt in sorted(set(kv) | set(tr)):
        func = re.sub(r"^\.\.|\(\).*$", "", ppt)
        mapping = rename_map(func, params, fields)
        # Globals are renamed at every program point, since tier 8 reports them
        # everywhere Kvasir does. Merged AFTER the parameter map so the
        # longest-key-first ordering still holds across both.
        mapping = dict(sorted({**mapping, **gmap}.items(),
                              key=lambda kv: -len(kv[0])))
        k_raw = kv.get(ppt, [])
        t_raw = [apply_renames(i, mapping) for i in tr.get(ppt, [])]
        unchanged = unchanged_vars(k_raw, t_raw)
        k_set = {canonical(x) for x in
                 (drop_orig(i, unchanged) for i in k_raw) if x}
        t_set = {canonical(x) for x in
                 (drop_orig(i, unchanged) for i in t_raw) if x}
        matched = k_set & t_set
        rows.append({
            "ppt": ppt, "kvasir": len(k_set), "tracer": len(t_set),
            "matched": len(matched),
            "missed": sorted(k_set - t_set), "extra": sorted(t_set - k_set),
        })
        tot_m += len(matched); tot_k += len(k_set); tot_t += len(t_set)

    recall = tot_m / tot_k if tot_k else 0.0
    precision = tot_m / tot_t if tot_t else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return rows, {"matched": tot_m, "kvasir": tot_k, "tracer": tot_t,
                  "precision": precision, "recall": recall, "f1": f1}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--kvasir", required=True)
    p.add_argument("--tracer", required=True)
    p.add_argument("--binary", required=True,
                   help="the -g build, read ONLY to align names")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="list missed and extra invariants per program point")
    a = p.parse_args(argv)

    for f in (a.kvasir, a.tracer, a.binary):
        if not os.path.isfile(f):
            print(f"[!] not found: {f}", file=sys.stderr)
            return 1

    rows, tot = score(a.kvasir, a.tracer, a.binary)
    print(f"{'program point':<42} {'kv':>4} {'tr':>4} {'match':>6} {'recall':>7}")
    for r in rows:
        rec = r["matched"] / r["kvasir"] if r["kvasir"] else float("nan")
        print(f"{r['ppt']:<42} {r['kvasir']:>4} {r['tracer']:>4} "
              f"{r['matched']:>6} {rec:>7.0%}")
        if a.verbose:
            for m in r["missed"]:
                print(f"      MISSED  {m}")
            for e in r["extra"]:
                print(f"      extra   {e}")
    print(f"\n  matched {tot['matched']}/{tot['kvasir']} oracle facts   "
          f"precision {tot['precision']:.0%}   recall {tot['recall']:.0%}   "
          f"F1 {tot['f1']:.0%}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
