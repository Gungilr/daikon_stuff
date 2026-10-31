"""Daikon's text output, compiled into checks the fuzzer can run per sample.

Each supported invariant becomes a function from a trace row to
(holds, distance):

    holds     whether the invariant is true of this sample
    distance  how far the sample is from VIOLATING it; 0 iff it does

Distance is the classic search-based-testing "branch distance" (Korel, Tracey),
applied to the invariant instead of a branch. It is what turns Daikon's output
into guidance: an input that brings `return >= 0` from distance 40 to 3 is
progress even though it refutes nothing, so the fuzzer keeps it and mutates it
further. That is the half of the loop where Daikon steers the fuzzer.

The fuzzer's verdict is advisory. Refutation is decided by re-running Daikon on
the grown corpus: an invariant is refuted when Daikon stops reporting it. So an
unsupported form costs guidance, never correctness, and compile() returns None
for anything it does not understand rather than guessing.

Pure: no subprocesses, no third-party imports.
"""
import math
import re

from .dtrace import parse_value

_NOISE = re.compile(
    r"^(=+|Daikon version.*|Exiting Daikon.*|Reading .*|Processing .*"
    r"|No return from procedure.*|Picked up JAVA_TOOL_OPTIONS.*|\[\d{4}-.*)$")


def parse_report(text):
    """{ppt: [invariant text]} from a Daikon text report."""
    out, ppt = {}, None
    for raw in text.split("\n"):
        line = raw.replace("\r", "").strip()
        if not line or _NOISE.match(line):
            continue
        if ":::" in line and " " not in line.split(":::", 1)[0]:
            ppt = line
            out.setdefault(ppt, [])
        elif ppt is not None:
            out[ppt].append(line)
    return out


def report_ppts_for(sample_ppt):
    """Report program points whose invariants apply to a sample.

    Kvasir writes `f():::EXIT0`; Daikon reports both the numbered exit and the
    combined `f():::EXIT`. Conditional points (`;condition=...`) are skipped:
    deciding which samples they cover means re-implementing Daikon's splitter.
    """
    out = [sample_ppt]
    m = re.match(r"^(.*:::EXIT)\d+$", sample_ppt)
    if m:
        out.append(m.group(1))
    return out


# --- tokenizer --------------------------------------------------------------

_TOKEN = re.compile(r"""\s*(?:
    (?P<num>0x[0-9a-fA-F]+|\d+\.\d*(?:[eE][-+]?\d+)?|\d+(?:[eE][-+]?\d+)?)
  | (?P<str>"(?:[^"\\]|\\.)*")
  | (?P<name>(?:::)?[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*|\[[^\[\]]*\])*)
  | (?P<op>==|!=|<=|>=|<|>|\+|-|\*|/|%|\(|\)|,)
)""", re.X)


def _tokenize(s):
    toks, pos = [], 0
    s = s.rstrip()
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m or m.end() == pos:
            return None
        kind = m.lastgroup
        toks.append((kind, m.group(kind)))
        pos = m.end()
    return toks


class _Unsupported(Exception):
    pass


class _Missing(Exception):
    """A variable the row does not have (or has as nonsensical)."""


def _resolve(name, row):
    """Value of a Daikon variable name in a trace row."""
    if name == "null":
        return 0
    if name in ("true", "false"):
        return 1 if name == "true" else 0
    key = name.replace("[]", "[..]")
    if key in row:
        v = row[key]
        if v is None:
            raise _Missing(name)
        return v
    # Element access: `buf[3]`, and Daikon's variable-index forms `buf[n-1]`,
    # `buf[return]`, which index the `buf[..]` sequence by another variable.
    m = re.match(r"^(.*)\[([^\[\]]+)\]$", key)
    if m and m.group(2) != ".." and m.group(1) + "[..]" in row:
        seq = row[m.group(1) + "[..]"]
        try:
            idx = _compile_expr(m.group(2))(row)
        except _Unsupported:
            raise _Missing(name)
        if (isinstance(seq, list) and isinstance(idx, int) and 0 <= idx < len(seq)
                and seq[idx] is not None):
            return seq[idx]
    raise _Missing(name)


def _resolver(name):
    """_resolve(name, row) as a closure, with the name's parsing done once.

    The string rewrite, the regex and (for `buf[return-1]`) the index
    expression's parse used to run on every check: a third of the loop's
    Python time on tcas.
    """
    if name == "null":
        return lambda r: 0
    if name in ("true", "false"):
        c = 1 if name == "true" else 0
        return lambda r: c
    key = name.replace("[]", "[..]")
    m = re.match(r"^(.*)\[([^\[\]]+)\]$", key)
    seq_key = idx = None
    if m and m.group(2) != "..":
        seq_key = m.group(1) + "[..]"
        try:
            idx = _compile_expr(m.group(2))
        except _Unsupported:
            idx = None

    def f(row):
        if key in row:
            v = row[key]
            if v is None:
                raise _Missing(name)
            return v
        if seq_key is not None and seq_key in row:
            seq = row[seq_key]
            if idx is None:
                raise _Missing(name)
            i = idx(row)
            if (isinstance(seq, list) and isinstance(i, int) and 0 <= i < len(seq)
                    and seq[i] is not None):
                return seq[i]
        raise _Missing(name)
    return f


# --- expressions ------------------------------------------------------------
#
# A tiny recursive-descent parser producing closures over a row. Arithmetic
# only; anything else raises _Unsupported at compile time.

class _Parser(object):
    def __init__(self, toks):
        self.toks, self.i = toks, 0

    def peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else (None, None)

    def take(self, value=None):
        tok = self.peek()
        if tok[0] is None or (value is not None and tok[1] != value):
            raise _Unsupported("expected %r, got %r" % (value, tok))
        self.i += 1
        return tok

    def done(self):
        return self.i >= len(self.toks)

    def expr(self):
        f = self.term()
        while self.peek()[1] in ("+", "-"):
            op = self.take()[1]
            g = self.term()
            f = (lambda a, b: lambda r: a(r) + b(r))(f, g) if op == "+" else \
                (lambda a, b: lambda r: a(r) - b(r))(f, g)
        return f

    def term(self):
        f = self.unary()
        while self.peek()[1] in ("*", "/", "%"):
            op = self.take()[1]
            g = self.unary()
            if op == "*":
                f = (lambda a, b: lambda r: a(r) * b(r))(f, g)
            elif op == "/":
                f = (lambda a, b: lambda r: _cdiv(a(r), b(r)))(f, g)
            else:
                f = (lambda a, b: lambda r: _cmod(a(r), b(r)))(f, g)
        return f

    def unary(self):
        if self.peek()[1] == "-":
            self.take()
            f = self.unary()
            return lambda r: -f(r)
        return self.atom()

    def atom(self):
        kind, val = self.peek()
        if kind == "num":
            self.take()
            n = int(val, 0) if re.match(r"^(0x[0-9a-fA-F]+|\d+)$", val) else float(val)
            return lambda r: n
        if kind == "str":
            self.take()
            s = val[1:-1]
            return lambda r: s
        if val == "(":
            self.take("(")
            f = self.expr()
            self.take(")")
            return f
        if kind == "name":
            self.take()
            if val in ("orig", "size") and self.peek()[1] == "(":
                self.take("(")
                inner = self.var_name()
                self.take(")")
                if val == "orig":
                    return _resolver("orig(%s)" % inner)
                get = _resolver(inner)
                return lambda r: _size(get(r))
            return _resolver(val)
        raise _Unsupported("unexpected token %r" % (val,))

    def var_name(self):
        """A bare or orig()-wrapped name, as text (for size(orig(x[])))."""
        kind, val = self.take()
        if kind != "name":
            raise _Unsupported(val)
        if val == "orig" and self.peek()[1] == "(":
            self.take("(")
            inner = self.var_name()
            self.take(")")
            return "orig(%s)" % inner
        return val


def _cdiv(a, b):
    if b == 0:
        raise _Missing("division by zero")
    if isinstance(a, int) and isinstance(b, int):
        q = abs(a) // abs(b)
        return q if (a >= 0) == (b >= 0) else -q
    return a / b


def _cmod(a, b):
    if b == 0:
        raise _Missing("mod by zero")
    return a - b * _cdiv(a, b)


def _size(v):
    if not isinstance(v, list):
        raise _Missing("size of non-sequence")
    return len(v)


def _compile_expr(text):
    toks = _tokenize(text)
    if not toks:
        raise _Unsupported(text)
    p = _Parser(toks)
    f = p.expr()
    if not p.done():
        raise _Unsupported(text)
    return f


# --- comparison semantics ---------------------------------------------------
#
# For `L op R`, with d = L - R, two distances:
#   to_false: smallest change in d that makes the comparison false
#   to_true:  smallest change in d that makes it true
# Integers move in steps of 1, so `d <= 0` needs d >= 1 to fail.

def _cmp(op, a, b):
    """(holds, to_false, to_true)."""
    if isinstance(a, (list, str)) or isinstance(b, (list, str)):
        if op not in ("==", "!="):
            raise _Missing("ordered comparison of non-numbers")
        eq = a == b
        holds = eq if op == "==" else not eq
        return holds, (1 if holds else 0), (0 if holds else 1)
    d = a - b
    if op == "==":
        return d == 0, (1 if d == 0 else 0), abs(d)
    if op == "!=":
        return d != 0, abs(d), (1 if d == 0 else 0)
    if op == "<=":
        return d <= 0, max(0, 1 - d), max(0, d)
    if op == "<":
        return d < 0, max(0, -d), max(0, d + 1)
    if op == ">=":
        return d >= 0, max(0, d + 1), max(0, -d)
    if op == ">":
        return d > 0, max(0, d), max(0, 1 - d)
    raise _Unsupported(op)


_CMP_OPS = ("==", "!=", "<=", ">=", "<", ">")


def _split_comparison(text):
    """(lhs, op, rhs) at the single top-level comparison, or None."""
    toks = _tokenize(text)
    if not toks:
        return None
    depth, at = 0, []
    for i, (kind, val) in enumerate(toks):
        if val == "(":
            depth += 1
        elif val == ")":
            depth -= 1
        elif kind == "op" and val in _CMP_OPS and depth == 0:
            at.append(i)
    if len(at) != 1:
        return None

    def join(ts):
        return " ".join(v for _, v in ts)
    i = at[0]
    return join(toks[:i]), toks[i][1], join(toks[i + 1:])


# --- predicates -------------------------------------------------------------
#
# A predicate maps a row to (holds, to_false, to_true). Invariant.check()
# exposes (holds, to_false) - "distance" everywhere else means to_false.

def _pred_comparison(lhs, op, rhs):
    f, g = _compile_expr(lhs), _compile_expr(rhs)
    return lambda r: _cmp(op, f(r), g(r))


def _pred_one_of(lhs, items):
    f = _compile_expr(lhs)
    vals = [parse_value(x.strip()) for x in items.split(",") if x.strip()]
    if not vals or any(v is None for v in vals):
        raise _Unsupported("one of")

    def p(r):
        v = f(r)
        holds = v in vals
        if holds:
            return True, 1, 0
        if isinstance(v, (int, float)):
            nums = [x for x in vals if isinstance(x, (int, float))]
            return False, 0, min(abs(v - x) for x in nums) if nums else 1
        return False, 0, 1
    return p


def _pred_mod(lhs, op, rem, mod):
    f = _compile_expr(lhs)
    rem, mod = int(rem), int(mod)

    def p(r):
        v = f(r)
        if not isinstance(v, int):
            raise _Missing("mod of non-integer")
        hit = v % mod == rem          # Python's % is non-negative, like Daikon's
        holds = hit if op == "==" else not hit
        return holds, (1 if holds else 0), (0 if holds else 1)
    return p


def _pred_in(lhs, seq):
    f, g = _compile_expr(lhs), _compile_expr(seq)

    def p(r):
        s = g(r)
        if not isinstance(s, list):
            raise _Missing("in non-sequence")
        holds = f(r) in s
        return holds, (1 if holds else 0), (0 if holds else 1)
    return p


class _Elem(object):
    """The row plus `__elem__`, without copying the row for every element."""
    __slots__ = ("row", "v")

    def __init__(self, row, v):
        self.row, self.v = row, v

    def __contains__(self, key):
        return key == "__elem__" or key in self.row

    def __getitem__(self, key):
        return self.v if key == "__elem__" else self.row[key]


def _pred_elements(seq, rest):
    """`A[] elements <pred>`: the predicate holds of every element."""
    g = _compile_expr(seq)
    elem = _compile_predicate("__elem__ " + rest)

    def p(r):
        s = g(r)
        if not isinstance(s, list):
            raise _Missing("elements of non-sequence")
        holds, to_false = True, None
        for v in s:
            if v is None:
                continue
            h, tf, _ = elem(_Elem(r, v))
            holds = holds and h
            to_false = tf if to_false is None else min(to_false, tf)
        if to_false is None:
            to_false = 1               # an element must appear first
        return holds, (0 if not holds else to_false), (0 if holds else 1)
    return p


def _pred_implies(a, b):
    pa, pb = _compile_predicate(a), _compile_predicate(b)

    def p(r):
        ha, _, ta = pa(r)
        hb, fb, _ = pb(r)
        holds = (not ha) or hb
        # Violation needs the antecedent TRUE and the consequent FALSE.
        to_false = 0 if not holds else ta + fb
        return holds, to_false, (0 if holds else 1)
    return p


def _strip_parens(s):
    s = s.strip()
    if s.startswith("(") and s.endswith(")"):
        depth = 0
        for i, c in enumerate(s):
            depth += c == "("
            depth -= c == ")"
            if depth == 0 and i < len(s) - 1:
                return s
        return s[1:-1].strip()
    return s


def _compile_predicate(text):
    text = text.strip()
    if "==>" in text:
        parts = text.split("==>")
        if len(parts) != 2:
            raise _Unsupported(text)
        return _pred_implies(_strip_parens(parts[0]), _strip_parens(parts[1]))
    m = re.match(r"^(.+?) elements (.+)$", text)
    if m:
        return _pred_elements(m.group(1), m.group(2))
    m = re.match(r"^(.+?) one of \{(.*)\}$", text)
    if m:
        return _pred_one_of(m.group(1), m.group(2))
    m = re.match(r"^(.+?) (==|!=) (-?\d+)\s+\(mod (\d+)\)$", text)
    if m:
        return _pred_mod(*m.groups())
    m = re.match(r"^(\S+) in (\S+)$", text)
    if m:
        return _pred_in(m.group(1), m.group(2))
    if re.search(r"has only one value|sorted by|no duplicates|is a pointer"
                 r"|subsequence|is reverse of|lexically|\bpower of\b|\bbits\b",
                 text):
        raise _Unsupported(text)
    parts = _split_comparison(text)
    if parts is None:
        raise _Unsupported(text)
    return _pred_comparison(*parts)


class _Recorder(object):
    """A read-only view of a row that notes which variables were looked at."""
    __slots__ = ("row", "seen")

    def __init__(self, row):
        self.row, self.seen = row, set()

    def __contains__(self, key):
        self.seen.add(key)
        return key in self.row

    def __getitem__(self, key):
        self.seen.add(key)
        return self.row[key]


_ABSENT = object()
_MEMO_MAX = 4096


def _memo_part(v):
    # Arrays are compared by identity: dtrace.rows() hands out one shared
    # list per distinct raw value, so a 360-entry global table is one object
    # for every call that saw it unchanged. Scalars compare by value.
    return id(v) if isinstance(v, list) else v


class Invariant(object):
    __slots__ = ("ppt", "text", "_pred", "_names", "_memo")

    def __init__(self, ppt, text, pred):
        self.ppt, self.text, self._pred = ppt, text, pred
        self._names = ()
        self._memo = {}

    @property
    def key(self):
        return (self.ppt, self.text)

    def check(self, row):
        """(holds, distance) on one row, or None if it cannot be evaluated.

        Memoized on the values of the variables the predicate reads: print_tokens
        has "elements" invariants over 360-entry global tables that are the
        same on every call, and re-scanning them was 97% of the loop's time.
        Exact, not approximate: a hit means every variable this invariant has
        ever read has the same value as in an earlier evaluation.
        """
        vals = tuple(row.get(n, _ABSENT) for n in self._names)
        key = tuple(_memo_part(v) for v in vals)
        hit = self._memo.get(key)
        if hit is not None:
            return hit[1]
        rec = _Recorder(row)
        res = self._check(rec)
        if not rec.seen.issubset(self._names):
            # Read something new (an implication's consequent, say): widen
            # the key and forget entries keyed on the narrower one.
            self._names = tuple(sorted(set(self._names) | rec.seen))
            self._memo = {}
            vals = tuple(row.get(n, _ABSENT) for n in self._names)
            key = tuple(_memo_part(v) for v in vals)
        if len(self._memo) >= _MEMO_MAX:
            self._memo = {}
        # Keep vals alive with the entry so no id() in the key is reused.
        self._memo[key] = (vals, res)
        return res

    def _check(self, row):
        try:
            holds, to_false, _ = self._pred(row)
        except (_Missing, TypeError, ValueError, ZeroDivisionError, OverflowError):
            return None
        if isinstance(to_false, float) and (math.isnan(to_false) or math.isinf(to_false)):
            return None
        return bool(holds), (0 if not holds else to_false)

    def __repr__(self):
        return "Invariant(%r, %r)" % (self.ppt, self.text)


def compile_invariant(ppt, text):
    """An Invariant, or None if the form is not supported."""
    try:
        return Invariant(ppt, text, _compile_predicate(text))
    except _Unsupported:
        return None
    except RecursionError:
        return None


def compile_report(report):
    """({ppt: [Invariant]}, [unsupported (ppt, text)])."""
    out, unsupported = {}, []
    for ppt, invs in report.items():
        if ";condition=" in ppt:
            continue
        for text in invs:
            inv = compile_invariant(ppt, text)
            if inv is None:
                unsupported.append((ppt, text))
            else:
                out.setdefault(ppt, []).append(inv)
    return out, unsupported
