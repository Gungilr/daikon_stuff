#!/usr/bin/env python3
"""How many of our unmatched facts could Kvasir never have printed?

Kvasir runs DynComp by default (daikon/doc/daikon.texinfo, "DynComp dynamic
comparability analysis for C/C++"), and test.sh hands Kvasir's `.decls` to
Daikon. Daikon only relates two variables whose comparability classes match
(VarComparabilityImplicit.comparable), so a fact over two scalars that DynComp
put in different classes is one the ORACLE CANNOT PRODUCE. Every such fact in
our report is a guaranteed false positive, and an emulator-side DynComp would
remove it.

This measures how many there are, to decide whether building that is worth it.

Each fact the tracer emitted and Kvasir did not is put in one class:

  unary       one variable; comparability does not apply
  sequence    every term but at most one scalar is a sequence or a size().
              Kvasir writes array comparabilities with no index part, Daikon
              parses them as dimensionless, and elementType() of a
              dimensionless comparability is `unknown` - comparable to
              everything. So sequence terms never block a pairing here.
  unresolved  a scalar name Kvasir did not declare at that program point
              (typically an unmapped `.offK` field of ours)
  same        all scalars in one class - Kvasir COULD have printed it
  cross       two scalars in different classes - Kvasir could NOT have

The same classifier is applied to MATCHED facts as a check on itself: Kvasir
printed every one of those, so none can be `cross`. A non-zero count there means
the classifier, not the tracer, is wrong.

Usage:
    measure_comparability.py DIR

DIR holds, per program NAME: NAME.kvasir.txt and NAME.tracer.txt (Daikon text
reports), NAME.kvasir.decls (Kvasir's declarations, with DynComp classes), and
NAME.exe (the -g build, read only to align names - as in score_invariants.py).
"""
from __future__ import print_function

import argparse
import glob
import os
import re
import sys

from score_invariants import (apply_renames, canonical, drop_orig, dwarf_globals,
                              dwarf_names, global_rename_map, norm_ppt,
                              parse_report, rename_map, score, unchanged_vars)

CLASSES = ("unary", "sequence", "unresolved", "same", "cross")

# A Daikon variable path: optional `::`, a name, then any mix of `[..]`
# subscripts and `.field` / `->field` steps. The lookbehind stops a match
# starting inside a number (`2.147483648E9`) or mid-path; the lookahead stops
# function-like wrappers (`orig(`, `size(`) being read as variables.
_NAME = re.compile(r"(?<![\w.:>-])((?:::)?[A-Za-z_]\w*(?:\[[^\]]*\])?"
                   r"(?:(?:\.|->)[A-Za-z_]\w*(?:\[[^\]]*\])?)*)(?!\w|\()")
_QUOTED = re.compile(r'"[^"]*"')
# Words Daikon uses in its printed invariants that the name pattern would
# otherwise take for variables.
_KEYWORDS = frozenset(
    "elements one of has only value values null sorted by is a subsequence "
    "reverse contains no duplicates in lexically pointed to are the and or "
    "true false".split())


def parse_decls(path):
    """{program point: {variable: comparability string}} from a .decls file.

    Program points go through the scorer's norm_ppt, so `:::EXIT0` lines up with
    the report's `:::EXIT`. Declarations spell a sequence `a[..]`; reports
    spell it `a[]`, so declarations are rewritten to the report spelling.
    """
    out, ppt, var = {}, None, None
    with open(path, errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            text = line.strip()
            if line.startswith("ppt "):
                ppt = norm_ppt(line[4:].strip())
                out.setdefault(ppt, {})
                var = None
            elif text.startswith("variable ") and ppt is not None:
                var = text[len("variable "):].replace("[..]", "[]")
            elif text.startswith("comparability ") and ppt is not None and var:
                out[ppt][var] = text.split()[1]
    return out


def variables(fact):
    """{variable name: appears directly inside size(...)} for one fact."""
    fact = _QUOTED.sub('""', fact)
    names = {}
    for m in _NAME.finditer(fact):
        name = m.group(1)
        if name in _KEYWORDS:
            continue
        before = fact[:m.start()]
        names.setdefault(name, before.endswith("size(")
                         or before.endswith("size(orig("))
    return names


def classify(fact, comps):
    """One of CLASSES for `fact`, given Kvasir's {variable: comparability}."""
    names = variables(fact)
    if len(names) <= 1:
        return "unary"
    bases, unresolved, scalars = set(), False, 0
    for name, in_size in names.items():
        if in_size or "[" in name:
            continue                    # sequence or size term: see docstring
        if name not in comps:
            unresolved = True
            continue
        comp = comps[name]
        if "[" in comp:
            unresolved = True           # an indexed comparability; not modelled
            continue
        scalars += 1
        base = int(comp)
        if base >= 0:                   # negative means comparable to all
            bases.add(base)
    if len(bases) >= 2:
        return "cross"
    if unresolved:
        return "unresolved"
    return "same" if scalars >= 2 else "sequence"


def fact_sets(kvasir_report, tracer_report, binary):
    """{ppt: (kvasir facts, tracer facts)}, normalised exactly as score() does.

    Duplicates the loop in score_invariants.score(), which returns counts and
    the unmatched lists but not the matched set. measure() checks the totals
    against score() for every program, so the two cannot drift silently.
    """
    params, fields = dwarf_names(binary)
    gmap = global_rename_map(dwarf_globals(binary))
    kv = {norm_ppt(k): v for k, v in parse_report(kvasir_report).items()}
    tr = {norm_ppt(k): v for k, v in parse_report(tracer_report).items()}
    out = {}
    for ppt in sorted(set(kv) | set(tr)):
        func = re.sub(r"^\.\.|\(\).*$", "", ppt)
        mapping = rename_map(func, params, fields)
        mapping = dict(sorted({**mapping, **gmap}.items(),
                              key=lambda kv_: -len(kv_[0])))
        k_raw = kv.get(ppt, [])
        t_raw = [apply_renames(i, mapping) for i in tr.get(ppt, [])]
        unchanged = unchanged_vars(k_raw, t_raw)
        k_set = {canonical(x) for x in (drop_orig(i, unchanged) for i in k_raw) if x}
        t_set = {canonical(x) for x in (drop_orig(i, unchanged) for i in t_raw) if x}
        out[ppt] = (k_set, t_set)
    return out


def measure(directory):
    """Per-program and total counts. Raises if fact_sets() drifts from score()."""
    programs, extra, matched = [], dict.fromkeys(CLASSES, 0), dict.fromkeys(CLASSES, 0)
    totals = {"matched": 0, "kvasir": 0, "tracer": 0}
    for kv_path in sorted(glob.glob(os.path.join(directory, "*.kvasir.txt"))):
        name = os.path.basename(kv_path)[:-len(".kvasir.txt")]
        tr_path = os.path.join(directory, name + ".tracer.txt")
        exe = os.path.join(directory, name + ".exe")
        decls = os.path.join(directory, name + ".kvasir.decls")
        if not all(os.path.isfile(p) for p in (tr_path, exe, decls)):
            continue
        comps_by_ppt = parse_decls(decls)
        sets = fact_sets(kv_path, tr_path, exe)
        n_m = n_k = n_t = cross = 0
        for ppt, (k_set, t_set) in sets.items():
            comps = comps_by_ppt.get(ppt, {})
            for fact in k_set & t_set:
                matched[classify(fact, comps)] += 1
            for fact in t_set - k_set:
                kind = classify(fact, comps)
                extra[kind] += 1
                cross += kind == "cross"
            n_m += len(k_set & t_set)
            n_k += len(k_set)
            n_t += len(t_set)
        _, ref = score(kv_path, tr_path, exe)
        if (n_m, n_k, n_t) != (ref["matched"], ref["kvasir"], ref["tracer"]):
            raise RuntimeError(f"{name}: fact_sets() disagrees with score(): "
                               f"{(n_m, n_k, n_t)} vs "
                               f"{(ref['matched'], ref['kvasir'], ref['tracer'])}")
        programs.append({"name": name, "matched": n_m, "kvasir": n_k,
                         "tracer": n_t, "cross": cross})
        totals["matched"] += n_m
        totals["kvasir"] += n_k
        totals["tracer"] += n_t
    return programs, totals, extra, matched


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("directory")
    a = p.parse_args(argv)
    if not os.path.isdir(a.directory):
        print(f"[!] not a directory: {a.directory}", file=sys.stderr)
        return 1

    programs, totals, extra, matched = measure(a.directory)
    if not programs:
        print("[!] no program has all four artefacts", file=sys.stderr)
        return 1

    print(f"programs with all four artefacts: {len(programs)}")
    print(f"matched {totals['matched']}  oracle {totals['kvasir']}  "
          f"emitted {totals['tracer']}\n")
    print(f"{'class':<11} {'unmatched':>9} {'matched':>8}")
    for c in CLASSES:
        print(f"{c:<11} {extra[c]:>9} {matched[c]:>8}")
    print(f"{'total':<11} {sum(extra.values()):>9} {sum(matched.values()):>8}")

    m, t = totals["matched"], totals["tracer"]
    now = m / t if t else 0.0
    best = m / (t - extra["cross"]) if t > extra["cross"] else 0.0
    bound = (m / (t - extra["cross"] - extra["unresolved"])
             if t > extra["cross"] + extra["unresolved"] else 0.0)
    print(f"\nprecision now                              {now:6.1%}")
    print(f"... with every cross-class fact removed    {best:6.1%}")
    print(f"... and every unresolved one too (bound)   {bound:6.1%}")
    if matched["cross"]:
        print(f"\n[!] {matched['cross']} MATCHED facts classified cross-class: "
              "the classifier is wrong, not the tracer", file=sys.stderr)
        return 2

    print("\nprograms with cross-class facts:")
    for r in sorted(programs, key=lambda r: -r["cross"]):
        if r["cross"]:
            print(f"  {r['name']:<28} {r['cross']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
