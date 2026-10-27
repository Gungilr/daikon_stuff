"""The bug checker: sanitizer reports, attributed to the input that caused them.

Daikon can only flag a property it has already proposed. In the single-seed
run it never proposed `abs_diff: return >= 0`, so the 5 inputs that overflowed
abs_diff were never reported. The checker is an oracle that needs no
invariant: a third build of the target with AddressSanitizer and
UndefinedBehaviorSanitizer, run on every input.

That build must NOT use -fwrapv. With -fwrapv, gcc silently drops the
signed-integer-overflow check (verified with gcc 13.3: the overflow prints a
wrong answer and exits 0). The traced and coverage builds keep -fwrapv so
that Kvasir records the wrapped value deterministically.

The harness (built with -DFUZZ_SAN) writes `@@FUZZ-INPUT <id>` to stderr
before each record, so every report that follows belongs to that input.
UBSan reports are recoverable, so one input can trigger several and the batch
keeps going. An ASan report aborts the process, and the runner restarts
after the culprit.

Pure: no subprocesses, no third-party imports.
"""
import re

INPUT_MARKER = "@@FUZZ-INPUT "

# UBSan:  file.c:12:9: runtime error: signed integer overflow: 9 - -2147483648 ...
_UBSAN = re.compile(r"^(?P<loc>[^\s:][^:]*:\d+:\d+): runtime error: (?P<msg>.*)$")
# ASan:   ==123==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
_ASAN = re.compile(r"==\d+==ERROR: AddressSanitizer: (?P<kind>[\w-]+)(?P<rest>.*)$")
# ASan stack frame:  #0 0x55... in parse_digits /path/buffer.c:38
_FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (?P<func>\S+) (?P<loc>\S+:\d+(?::\d+)?)")
# SEGV etc. without ASan's report (e.g. stack exhaustion)
_SIGNAL = re.compile(r"==\d+==ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer): "
                     r"(?P<kind>SEGV|stack-overflow|ABRT|FPE)")


def ubsan_kind(msg):
    """A short class name for a UBSan message: the text before the first
    colon, e.g. "signed integer overflow", "division by zero"."""
    head = msg.split(":", 1)[0].strip()
    return head if head else msg[:40]


class Bug(object):
    __slots__ = ("kind", "location", "message", "function", "sanitizer")

    def __init__(self, sanitizer, kind, location, message, function=None):
        self.sanitizer, self.kind = sanitizer, kind
        self.location, self.message, self.function = location, message, function

    @property
    def key(self):
        """Deduplication key. The same check at the same source location is
        one bug, however many inputs reach it."""
        return (self.kind, self.location)

    def as_dict(self):
        return {"sanitizer": self.sanitizer, "kind": self.kind,
                "location": self.location, "function": self.function,
                "message": self.message}

    def __repr__(self):
        return "Bug(%s at %s)" % (self.kind, self.location)


def parse_stderr(text, own_sources=()):
    """(bugs_by_input, last_input_started).

    bugs_by_input maps the input id (as numbered within this run) to a list of
    Bug. `own_sources` are basenames of files in the target. An ASan report
    is located at its first stack frame inside one of them, not inside libc.
    """
    bugs, cur = {}, None
    lines = text.replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith(INPUT_MARKER):
            try:
                cur = int(line[len(INPUT_MARKER):].strip())
            except ValueError:
                pass
            i += 1
            continue
        if line.startswith("@@FUZZ-DIED "):
            # The forked child for this input was killed by a signal and no
            # sanitizer report preceded it (ASan exits normally after one).
            # SIGFPE (8) is skipped: UBSan's integer-divide-by-zero check always
            # reports before the trap, so an unreported SIGFPE is only a repeat
            # of a location this process already printed.
            parts = line.split()
            if len(parts) >= 3 and parts[2] != "8" and not bugs.get(int(parts[1])):
                bugs.setdefault(int(parts[1]), []).append(Bug(
                    "signal", "signal %s" % parts[2], "?",
                    "killed by signal %s" % parts[2]))
            i += 1
            continue
        if line.startswith("@@BUG ") and cur is not None:
            # Ground-truth marker from a -DFUZZ_ORACLE build (benchmarking only).
            parts = line.split()
            bugs.setdefault(cur, []).append(Bug(
                "oracle", parts[1], parts[1], "planted bug triggered",
                parts[2] if len(parts) > 2 else None))
            i += 1
            continue
        m = _UBSAN.match(line)
        if m and cur is not None:
            msg = m.group("msg")
            bugs.setdefault(cur, []).append(
                Bug("ubsan", ubsan_kind(msg), _short(m.group("loc")), msg))
            i += 1
            continue
        m = _ASAN.search(line) or _SIGNAL.search(line)
        if m and cur is not None:
            kind = m.group("kind")
            loc, func = None, None
            # The access type is on the next line, and the frames follow it.
            for j in range(i + 1, min(i + 40, len(lines))):
                f = _FRAME.match(lines[j])
                if not f:
                    continue
                path = f.group("loc")
                if loc is None:
                    loc, func = _short(path), f.group("func")
                if not own_sources or path.rsplit("/", 1)[-1].split(":")[0] in own_sources:
                    loc, func = _short(path), f.group("func")
                    break
            detail = lines[i + 1].strip() if i + 1 < len(lines) else ""
            bugs.setdefault(cur, []).append(
                Bug("asan", kind, loc or "?", (kind + " " + detail).strip(), func))
        i += 1
    return bugs, cur


def _short(path):
    """`/abs/path/fuzz/targets/arith.c:20:23` -> `arith.c:20:23`."""
    return path.rsplit("/", 1)[-1]
