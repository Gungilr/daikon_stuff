"""Rule-directed mutation: write a live rule's boundary into the input.

Guidance alone only *scores* inputs: one that lands closer to breaking a rule
is kept, but the bytes still change at random. A rule says more than that.
`alt <= 1000` names the value that matters (1000, then 1001), and `x < y`
names it relative to another variable. This module turns a rule plus one
traced row into concrete children:

1. Read the rule's variable from the row (its value v in this input).
2. Find v in the input bytes, in the encodings the targets use: a
   little-endian 32/16/8-bit integer, or decimal text.
3. Replace it, in the same encoding, with values on and across the
   boundary (c-1, c, c+1 for `x op c`; y-1, y, y+1 for `x op y`).

It is input-to-state correspondence in the style of REDQUEEN, driven by the
rules instead of by comparison operands. When v does not appear in the input
(the variable is computed, not copied), there is no child.

Pure: no subprocesses.
"""
import re
import struct

from . import invariants
from .dtrace import parse_value

_SIMPLE = re.compile(r"^(?:::)?[A-Za-z_]\w*$")
_INT32 = (-(1 << 31), (1 << 32) - 1)


def _rule_parts(text, cache={}):
    """[(var, other)]: variables a rule bounds and what bounds them.

    `other` is a constant (int) or another variable's name (str). None if
    the rule is not a comparison of plain variables and constants."""
    if text in cache:
        return cache[text]
    out = None
    m = re.match(r"^(\S+) one of \{(.*)\}$", text)
    if m and _SIMPLE.match(m.group(1)):
        vals = [parse_value(x.strip()) for x in m.group(2).split(",")]
        ints = [v for v in vals if isinstance(v, int) and not isinstance(v, bool)]
        if ints:
            # Outside the observed set, and the set's own edges.
            out = [(m.group(1), min(ints)), (m.group(1), max(ints))]
    elif not re.search(r"==>| elements | in |\(mod|one of", text):
        parts = invariants._split_comparison(text)
        if parts is not None:
            lhs, _, rhs = parts
            out = []
            for a, b in ((lhs, rhs), (rhs, lhs)):
                if not _SIMPLE.match(a):
                    continue
                c = parse_value(b)
                if isinstance(c, int) and not isinstance(c, bool):
                    out.append((a, c))
                elif _SIMPLE.match(b):
                    out.append((a, b))
            out = out or None
    cache[text] = out
    return out


def _encodings(v):
    """[(bytes, encoder)] for an integer value, most specific first."""
    out = []
    if _INT32[0] <= v <= _INT32[1]:
        fmt = "<i" if v < 0 else "<I"
        out.append((struct.pack(fmt, v), lambda t: struct.pack("<I", t & 0xffffffff)))
    if -32768 <= v <= 65535 and not -128 <= v <= 255:
        out.append((struct.pack("<h" if v < 0 else "<H", v),
                    lambda t: struct.pack("<H", t & 0xffff)))
    out.append((str(v).encode(), lambda t: str(t).encode()))
    if -128 <= v <= 255:
        out.append((bytes([v & 0xff]), lambda t: bytes([t & 0xff])))
    return out


def _occurrences(data, pat, text):
    """Offsets of pat in data; for decimal text, only whole numbers."""
    out, i = [], data.find(pat)
    while i >= 0:
        if not text or ((i == 0 or not chr(data[i - 1]).isdigit() and data[i - 1] != ord("-"))
                        and (i + len(pat) == len(data) or not chr(data[i + len(pat)]).isdigit())):
            out.append(i)
        i = data.find(pat, i + 1)
    return out


def children(data, rule_text, row, rng, limit=4):
    """Up to `limit` inputs that put one of the rule's variables on or across
    its boundary, or [] if the rule or the input gives no handle."""
    parts = _rule_parts(rule_text)
    if not parts:
        return []
    var, other = rng.choice(parts)
    v = row.get(var)
    if isinstance(other, str):
        c = row.get(other)
    else:
        c = other
    if not isinstance(v, int) or isinstance(v, bool) or not isinstance(c, int) \
            or isinstance(c, bool):
        return []
    targets = [t for t in (c - 1, c, c + 1) if t != v]
    if not targets:
        return []
    out = []
    for pat, enc in _encodings(v):
        is_text = pat == str(v).encode()
        offs = _occurrences(data, pat, is_text)
        if not offs:
            continue
        # A value as common as 0 or 1 is everywhere; any one spot will do.
        off = rng.choice(offs)
        for t in targets:
            new = enc(t)
            if not is_text and len(new) != len(pat):
                continue
            child = data[:off] + new + data[off + len(pat):]
            if child != data:
                out.append(child)
        if out:
            break
    rng.shuffle(out)
    return out[:limit]
