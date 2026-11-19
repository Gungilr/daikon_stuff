"""Daikon invariants as executable checks, for the fuzz loop.

Parses Daikon's text report (score_invariants.parse_report) and compiles the
invariant forms that matter for scalar program points into predicates over one
sample (a {variable: int} row from score_invariants.parse_dtrace, with orig()
already resolved):

    x == c   x != c   x < c   x <= c   x > c   x >= c      (and c on the left)
    x one of { c1, c2, ... }
    x == y   x != y   x < y   x <= y   x > y   x >= y
    a*x + b*y + ... + c == 0                                 (linear equalities)
    (A) ==> (B)   (A) <==> (B)       with A and B any form above (conditional
                                     invariants, which Daikon reports when given
                                     splitting conditions)

Anything else (sequences, implications, modulus, ...) is left uncompiled and
counted; the loop never guesses at a form it cannot evaluate. A predicate
returns None when a variable it needs is missing from the row.
"""
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import score_invariants as S  # noqa: E402

VAR = r"(?:orig\()?(?:::)?[A-Za-z_][\w]*\)?"
NUM = r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?L?"
OPS = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b, "<": lambda a, b: a < b,
       "<=": lambda a, b: a <= b, ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
FLIP = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "!=": "!="}


def _num(s):
    s = s.rstrip("L")
    return float(s) if any(c in s for c in ".eE") else int(s)


class Inv:
    """One compiled invariant: `kind`, the variables, constants, and `holds(row)`."""
    __slots__ = ("ppt", "text", "kind", "vars", "consts", "op", "fn")

    def __init__(self, ppt, text, kind, vars_, consts, op, fn):
        self.ppt, self.text, self.kind = ppt, text, kind
        self.vars, self.consts, self.op, self.fn = vars_, consts, op, fn

    @property
    def key(self):
        return (self.ppt, self.text)

    def holds(self, row):
        if any(v not in row for v in self.vars):
            return None
        try:
            return bool(self.fn(row))
        except (TypeError, ZeroDivisionError):
            return None

    def __repr__(self):
        return f"Inv({self.ppt} | {self.text})"


def compile_inv(ppt, text):
    t = text.strip()
    m = re.fullmatch(r"\((.+)\)\s+(==>|<==>)\s+\((.+)\)", t)
    if m:
        # Conditional invariants (from a splitter): both sides must compile.
        a, b = compile_inv(ppt, m.group(1)), compile_inv(ppt, m.group(3))
        if a is None or b is None:
            return None
        both = a.vars + tuple(v for v in b.vars if v not in a.vars)
        if m.group(2) == "==>":
            fn = lambda r: (not a.fn(r)) or b.fn(r)
        else:
            fn = lambda r: a.fn(r) == b.fn(r)
        return Inv(ppt, t, "implies", both, (), m.group(2), fn)
    m = re.fullmatch(rf"({VAR}) one of \{{ ({NUM}(?:, {NUM})*) \}}", t)
    if m:
        v = m.group(1)
        vals = {_num(x) for x in m.group(2).split(", ")}
        return Inv(ppt, t, "oneof", (v,), tuple(sorted(vals)), None, lambda r: r[v] in vals)
    m = re.fullmatch(rf"({VAR}) (==|!=|<=|>=|<|>) ({NUM})", t)
    if m:
        v, op, c = m.group(1), m.group(2), _num(m.group(3))
        f = OPS[op]
        return Inv(ppt, t, "const", (v,), (c,), op, lambda r: f(r[v], c))
    m = re.fullmatch(rf"({NUM}) (==|!=|<=|>=|<|>) ({VAR})", t)
    if m:
        c, op, v = _num(m.group(1)), FLIP[m.group(2)], m.group(3)
        f = OPS[op]
        return Inv(ppt, t, "const", (v,), (c,), op, lambda r: f(r[v], c))
    m = re.fullmatch(rf"({VAR}) (==|!=|<=|>=|<|>) ({VAR})", t)
    if m:
        a, op, b = m.group(1), m.group(2), m.group(3)
        f = OPS[op]
        return Inv(ppt, t, "rel", (a, b), (), op, lambda r: f(r[a], r[b]))
    lin = _linear(t)
    if lin is not None:
        coeffs, const = lin
        vs = tuple(coeffs)
        return Inv(ppt, t, "linear", vs, (const,), "==",
                   lambda r: abs(sum(c * r[v] for v, c in coeffs.items()) + const) < 1e-6)
    return None


def _linear(t):
    s = S.fold_signs(t.replace(" ", ""))
    if not s.endswith("==0") or "[" in s:
        return None
    body = s[:-3]
    coeffs, const, pos = {}, 0.0, 0
    for m in S._TERM.finditer(body):
        if m.start() != pos:
            return None
        sign = -1.0 if m.group(1) == "-" else 1.0
        c = float(m.group(2)) if m.group(2) else 1.0
        coeffs[m.group(3)] = coeffs.get(m.group(3), 0.0) + sign * c
        pos = m.end()
    for m in re.finditer(S._CONST, body):
        if m.start() >= pos:
            const += (-1.0 if m.group(1) == "-" else 1.0) * float(m.group(2))
            pos = m.end()
    if pos != len(body) or not coeffs:
        return None
    return coeffs, const


def load(report_path):
    """([Inv], n_uncompiled) from a Daikon text report."""
    invs, skipped = [], 0
    for ppt, texts in S.parse_report(report_path).items():
        p = S.norm_ppt(ppt)
        for t in texts:
            c = compile_inv(p, t)
            if c is None:
                skipped += 1
            else:
                invs.append(c)
    return invs, skipped


def rows_by_ppt(dtrace_path):
    """{normalised ppt: [row]} - samples only (declaration blocks dropped)."""
    out = {}
    for ppt, rows in S.parse_dtrace(dtrace_path).items():
        if ppt.startswith("ppt "):
            continue
        out.setdefault(S.norm_ppt(ppt), []).extend(rows)
    return out


def violations(invs, rows):
    """[Inv] that some sample in rows contradicts."""
    bad = []
    for inv in invs:
        for r in rows.get(inv.ppt, ()):
            if inv.holds(r) is False:
                bad.append(inv)
                break
    return bad
