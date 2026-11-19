"""Splitting conditions for Daikon, from what the fuzzer refuted.

A relation the corpus shows to be sometimes true and sometimes false at a
program point (exactly the relations the loop's fuzzing refuted) is a natural
case split: Daikon, given it in a .spinfo file, reports conditional invariants
such as `(x < y) ==> (return == 1)` - the facts that describe a branch, which
the unconditional grammar cannot state.

Conditions per program point (all must mix true and false over the corpus):
    x < y, x == y      for pairs of scalar variables (orig() excluded)
    x == c             for c in a variable's values when it takes <= 3 values
    return == c        at EXIT points whose return takes <= 3 values
"""
import collections
import itertools

MAX_PER_PPT = 40


def conditions(rows_by_ppt):
    """{ppt: [java condition]} from {ppt: [row]} of a corpus trace."""
    out = {}
    for ppt, rows in rows_by_ppt.items():
        if not rows or ":::" not in ppt:
            continue
        names = sorted(v for v in rows[0] if not v.startswith("orig(")
                       and all(isinstance(r.get(v), int) for r in rows))
        conds = []
        vals = {v: {r[v] for r in rows} for v in names}
        for v in names:
            if 1 < len(vals[v]) <= 3:
                for c in sorted(vals[v]):
                    conds.append(f"{v} == {c}")
        for a, b in itertools.combinations(names, 2):
            if a == "return" or b == "return":
                continue
            lt = {r[a] < r[b] for r in rows}
            eq = {r[a] == r[b] for r in rows}
            if len(lt) == 2:
                conds.append(f"{a} < {b}")
            if len(eq) == 2:
                conds.append(f"{a} == {b}")
        if conds:
            out[ppt] = conds[:MAX_PER_PPT]
    return out


def write_spinfo(conds, path):
    with open(path, "w") as fh:
        for ppt, cs in sorted(conds.items()):
            fh.write(f"PPT_NAME {ppt}\n")
            for c in cs:
                fh.write(c + "\n")
            fh.write("\n")
    return path
