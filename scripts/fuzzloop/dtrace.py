"""Kvasir trace handling: parse, split by input, filter, renumber, re-emit.

The harness runs many inputs per process, and calls fuzz_input_begin(id)
before each one. Kvasir traces that call like any other, so its ENTER sample
is a marker: every sample after it, up to the next marker, belongs to input
`id`. Splitting on it is what lets one Valgrind start-up serve a batch while
the corpus is still kept, and re-traced, per input.

Pure: no subprocesses, no third-party imports.
"""
import re

MARKER_FUNC = "fuzz_input_begin"
MARKER_VAR = "fuzz_id"

# Harness and fuzz.h functions. They are traced because Kvasir traces every
# function with debug info, but their invariants describe the harness, not
# the program, so they never reach Daikon.
DEFAULT_OMIT = re.compile(
    r"(^|\.)(main|read_file|fuzz_target|fuzz_input_begin|fuzz_cursor_make"
    r"|fuzz_take_\w+)\(\)")

_HEADER_KEYS = ("input-language", "decl-version", "var-comparability")


class Sample(object):
    """One ENTER or EXIT record, values kept as the raw strings Kvasir wrote
    so re-emission is byte-faithful."""
    __slots__ = ("ppt", "nonce", "vars")

    def __init__(self, ppt, nonce, vars_):
        self.ppt = ppt
        self.nonce = nonce
        self.vars = vars_          # [(name, raw_value, modbit)]

    def get(self, name):
        for n, v, _ in self.vars:
            if n == name:
                return v
        return None

    def __repr__(self):
        return "Sample(%r, %r, %d vars)" % (self.ppt, self.nonce, len(self.vars))


def func_of(ppt):
    """`..abs_diff():::EXIT0` -> `..abs_diff()`."""
    return ppt.split(":::", 1)[0]


def is_marker(ppt):
    return func_of(ppt).endswith(MARKER_FUNC + "()")


# --- decls ------------------------------------------------------------------

def parse_decls(text):
    """(header_lines, {ppt: [block lines]}), in file order."""
    header, blocks = [], {}
    cur = None
    for line in text.replace("\r", "").split("\n"):
        if line.startswith("ppt "):
            cur = line[4:]
            blocks[cur] = [line]
        elif not line.strip():
            cur = None
        elif cur is not None:
            blocks[cur].append(line)
        elif line.split(" ", 1)[0] in _HEADER_KEYS:
            header.append(line)
    return header, blocks


def strip_is_param(block):
    """Drop `flags is_param` from a decl block.

    With is_param set, Daikon drops non-unit coefficients and reports
    invariants that are false on its own samples (docs/plans/README.md,
    "Correctness issues", item 1). A fuzzer would then spend its budget
    "refuting" facts that were never true, so the loop strips it by default.
    """
    out = []
    for line in block:
        s = line.strip()
        if s.startswith("flags "):
            flags = [f for f in s.split()[1:] if f != "is_param"]
            if not flags:
                continue
            line = line[:len(line) - len(line.lstrip())] + "flags " + " ".join(flags)
        out.append(line)
    return out


def render_decls(header, blocks, keep=lambda ppt: True, is_param=False):
    parts = ["\n".join(header), ""]
    for ppt, block in blocks.items():
        if not keep(ppt):
            continue
        parts.append("\n".join(block if is_param else strip_is_param(block)))
        parts.append("")
    return "\n".join(parts) + "\n"


# --- dtrace -----------------------------------------------------------------

def parse_dtrace(text):
    """[Sample], skipping any header or embedded decl blocks."""
    lines = text.replace("\r", "").split("\n")
    out, i, n = [], 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if line.startswith("ppt ") or line.split(" ", 1)[0] in _HEADER_KEYS:
            # A decl block or header line: skip to the next blank line.
            while i < n and lines[i].strip():
                i += 1
            continue
        if ":::" not in line:
            i += 1
            continue
        ppt, i = line, i + 1
        nonce = None
        if i < n and lines[i] == "this_invocation_nonce":
            nonce = int(lines[i + 1])
            i += 2
        vars_ = []
        while i < n and lines[i].strip():
            name = lines[i]
            value = lines[i + 1] if i + 1 < n else ""
            mod = lines[i + 2] if i + 2 < n else "1"
            vars_.append((name, value, mod))
            i += 3
        out.append(Sample(ppt, nonce, vars_))
    return out


def split_by_input(samples):
    """{input_id: [Sample]} using the fuzz_input_begin markers.

    Samples before the first marker (main, read_file) belong to no input and
    are dropped. Marker samples themselves are dropped too.
    """
    out, cur = {}, None
    for s in samples:
        if is_marker(s.ppt):
            if s.ppt.endswith(":::ENTER"):
                raw = s.get(MARKER_VAR)
                cur = int(raw) if raw is not None else None
                if cur is not None:
                    out.setdefault(cur, [])
            continue
        if cur is not None:
            out[cur].append(s)
    return out


def keep_ppt(ppt, omit=DEFAULT_OMIT):
    return not omit.search(func_of(ppt))


def render_samples(samples, nonce_base):
    """(text, next_nonce_base) with nonces renumbered from nonce_base.

    The corpus mixes inputs traced by different Kvasir runs, whose nonces all
    start from zero. Daikon pairs ENTER with EXIT by nonce, so collisions
    across runs would pair samples from different calls.
    """
    remap = {}
    parts = []
    for s in samples:
        if s.nonce is None:
            nonce_line = []
        else:
            if s.nonce not in remap:
                remap[s.nonce] = nonce_base + len(remap)
            nonce_line = ["this_invocation_nonce", str(remap[s.nonce])]
        body = [s.ppt] + nonce_line
        for name, value, mod in s.vars:
            body.extend((name, value, mod))
        parts.append("\n".join(body) + "\n")
    return "\n".join(parts) + ("\n" if parts else ""), nonce_base + len(remap)


# --- values -----------------------------------------------------------------

_ARRAY_TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\S+')


def parse_value(raw):
    """int / float / str / list, or None for nonsensical and unparseable."""
    raw = raw.strip()
    if raw in ("nonsensical", ""):
        return None
    if raw.startswith("[") and raw.endswith("]"):
        items = [parse_value(t) for t in _ARRAY_TOKEN.findall(raw[1:-1])]
        return items
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1]
    if raw == "null":
        return 0
    try:
        return int(raw, 0)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        return None


def rows(samples):
    """[(ppt, {var: value})] with `orig(v)` filled in for EXIT samples.

    Assumes the samples come from ONE run (or were renumbered together), so
    nonces are unique.
    """
    entries = {}
    out = []
    for s in samples:
        vals = {}
        for name, raw, mod in s.vars:
            # modbit 2 means "missing" (no value this time); treat as absent.
            if mod == "2":
                continue
            vals[name] = parse_value(raw)
        if s.ppt.endswith(":::ENTER"):
            entries[(func_of(s.ppt), s.nonce)] = vals
        else:
            for k, v in entries.get((func_of(s.ppt), s.nonce), {}).items():
                vals["orig(%s)" % k] = v
        out.append((s.ppt, vals))
    return out
