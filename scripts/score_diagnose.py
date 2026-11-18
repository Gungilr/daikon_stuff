"""Diagnose WHY facts fail to match in score_invariants.py (a scoring audit).

For every missed oracle fact and every extra tracer fact, after the scorer's own
renaming and normalisation, assign one cause:

  missed:
    var-absent      a variable it mentions is not declared at that program point
                    in our trace at all (nothing we print could match)
    form            our trace has a fact over the same variables that differs only in
                    spelling: number formatting (floats), `1*x`, `x == [v]` vs
                    `x elements == v`, ... (heuristic: same variable set + same
                    shape after number/format stripping)
    other           variables present, no same-variable fact - a genuine miss or a
                    different Daikon choice (suppression, equality-set leader)
  extra:
    var-unknown     mentions a variable Kvasir does not declare there (our g_0x...,
                    offK fields with no DWARF name, ...)
    form            the mirror of missed/form
    other

Usage:
    python3 scripts/score_diagnose.py --bins DIR --kv-inv DIR --tr-inv DIR --traces DIR --kv-traces DIR
        [--suffix .t10] [--examples N]
"""
import argparse
import collections
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import score_invariants as S  # noqa: E402

TOK = re.compile(r"(?:::)?[A-Za-z_][\w]*(?:\[[^\]]*\])?(?:(?:\.|->)[A-Za-z_]\w*(?:\[[^\]]*\])?)*")
KEYWORDS = {"orig", "size", "elements", "one", "of", "has", "only", "value", "null", "contains",
            "no", "nulls", "and", "length", "in", "sorted", "by", "is", "a", "subsequence",
            "elementwise", "pointer", "lexically", "true", "false", "mod", "nonsensical",
            "printable", "L", "E", "inf", "NaN", "not", "Infinity"}


def decl_vars(dtrace):
    """{ppt: set(variable names)} from a .dtrace/.decls header."""
    out = collections.defaultdict(set)
    ppt = None
    for line in open(dtrace, errors="replace"):
        line = line.rstrip("\n")
        if line.startswith("ppt "):
            ppt = S.norm_ppt(line[4:])
        elif line.startswith("  variable ") or line.startswith("variable "):
            if ppt:
                out[ppt].add(line.split(None, 1)[1])
        elif not line.strip():
            ppt = None
    return out


def vars_of(inv):
    names = set()
    for m in TOK.finditer(inv):
        t = m.group(0)
        if t in KEYWORDS or re.fullmatch(r"\d.*", t):
            continue
        names.add(t)
    return names


def shape(inv):
    s = re.sub(r"\[[^\]]*\]", "[]", inv)
    s = re.sub(r"-?\d+(\.\d+)?([eE][-+]?\d+)?L?", "N", s)
    s = re.sub(r"\b1\*", "", s)
    s = re.sub(r'"[^"]*"', "S", s)
    s = s.replace(" elements", "").replace("orig(", "(")
    return re.sub(r"\s+", " ", s).strip()


def kv_name(v):
    """Kvasir's array/field spelling, for presence checks: `p[..]` -> `p[]`."""
    return v.replace("[..]", "[]")


def strip_brackets(v):
    return re.sub(r"\[[^\]]*\]", "[]", v)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--bins", required=True)
    p.add_argument("--kv-inv", required=True)
    p.add_argument("--tr-inv", required=True)
    p.add_argument("--traces", required=True, help="dir with our <name>.tracer.t10<suffix>.dtrace")
    p.add_argument("--kv-traces", required=True, help="dir with <name>.kvasir.decls")
    p.add_argument("--suffix", default="")
    p.add_argument("--examples", type=int, default=3)
    a = p.parse_args(argv)
    C = collections.Counter()
    E = collections.defaultdict(list)
    per_bin = collections.defaultdict(collections.Counter)
    for f in sorted(os.listdir(a.bins)):
        if not f.endswith(".exe"):
            continue
        name = f[:-4]
        kv = os.path.join(a.kv_inv, f"{name}.kvasir.txt")
        tr = os.path.join(a.tr_inv, f"{name}.tracer.t10{a.suffix}.txt")
        dt = os.path.join(a.traces, f"{name}.tracer.t10{a.suffix}.dtrace")
        kd = os.path.join(a.kv_traces, f"{name}.kvasir.decls")
        if not all(os.path.exists(x) for x in (kv, tr, dt, kd)):
            continue
        binary = os.path.join(a.bins, f)
        params, fields = S.dwarf_names(binary)
        gmap = S.global_rename_map(S.dwarf_globals(binary))
        deep_funcs, deep_globs = S.dwarf_deep_names(binary)
        gmap = {**deep_globs, **gmap}
        ours = decl_vars(dt)
        theirs = decl_vars(kd)
        rows, _ = S.score(kv, tr, binary)
        for r in rows:
            ppt = r["ppt"]
            func = re.sub(r"^\.\.|\(\).*$", "", ppt)
            mapping = {**deep_funcs.get(func, {}), **S.rename_map(func, params, fields)}
            mapping = dict(sorted({**mapping, **gmap}.items(), key=lambda kv: -len(kv[0])))
            mine = {strip_brackets(kv_name(S.apply_renames(v, mapping))) for v in ours.get(ppt, ())}
            mine |= {strip_brackets(kv_name(S.apply_renames(v, mapping)))
                     for v in ours.get(ppt.replace(":::EXIT", ":::EXIT0"), ())}
            kvv = {strip_brackets(kv_name(v)) for v in theirs.get(ppt, ())}
            kvv |= {strip_brackets(kv_name(v)) for v in theirs.get(ppt.replace(":::EXIT", ":::EXIT0"), ())}
            ex_shapes = collections.defaultdict(list)
            for x in r["extra"]:
                ex_shapes[(frozenset(map(strip_brackets, vars_of(x))), shape(x))].append(x)
            mi_shapes = collections.defaultdict(list)
            for x in r["missed"]:
                mi_shapes[(frozenset(map(strip_brackets, vars_of(x))), shape(x))].append(x)
            for x in r["missed"]:
                vs = {strip_brackets(v) for v in vars_of(x)}
                key = (frozenset(vs), shape(x))
                if any(v not in mine for v in vs):
                    c = "missed: var-absent"
                elif key in ex_shapes:
                    c = "missed: form"
                else:
                    c = "missed: other"
                g = "global" if any(v.startswith("::") for v in vs) else "local"
                C[c] += 1
                C[f"{c} ({g})"] += 1
                per_bin[name][c] += 1
                if len(E[c]) < a.examples * 3 and (len(E[c]) < a.examples or g == "local"):
                    partner = ex_shapes.get(key, [""])[0] if c == "missed: form" else ""
                    E[c].append(f"{name} {ppt}: {x!r}" + (f"   ~ ours {partner!r}" if partner else ""))
            for x in r["extra"]:
                vs = {strip_brackets(v) for v in vars_of(x)}
                key = (frozenset(vs), shape(x))
                if any(v not in kvv for v in vs):
                    c = "extra: var-unknown"
                elif key in mi_shapes:
                    c = "extra: form"
                else:
                    c = "extra: other"
                C[c] += 1
                per_bin[name][c] += 1
                if len(E[c]) < a.examples:
                    E[c].append(f"{name} {ppt}: {x!r}")
            C["matched"] += r["matched"]
    tot_m = sum(v for k, v in C.items() if k.startswith("missed:") and "(" not in k)
    tot_e = sum(v for k, v in C.items() if k.startswith("extra:") and "(" not in k)
    print(f"matched {C['matched']}   missed {tot_m}   extra {tot_e}\n")
    for k in sorted(C):
        if k == "matched":
            continue
        base = tot_m if k.startswith("missed") else tot_e
        print(f"{C[k]:6d}  {100 * C[k] / base:5.1f}%  {k}")
    for k, v in E.items():
        print(f"\n{k}:")
        for x in v:
            print("   " + x[:230])
    return 0


if __name__ == "__main__":
    sys.exit(main())
