"""ENTER/EXIT nonce pairing under nesting, driven without an emulator.

Models what Tracer._hook_code does with call_stack: allocate a nonce at ENTER,
carry it on the frame, reuse it verbatim at the matching EXIT.
"""
from tracer.writer import DaikonTraceWriter, legacy_specs

VARS = ["rax", "rdi"]


class FakeTracer:
    """The nonce half of Tracer, with the emulator removed."""

    def __init__(self, writer):
        self.w = writer
        self.call_stack = []

    def enter(self, func, values):
        ppt = f"..{func}():::ENTER"
        self.w.declare(ppt, "enter", legacy_specs(VARS))
        nonce = self.w.next_nonce()
        self.w.add_sample(ppt, values, nonce=nonce)
        self.call_stack.append((func, nonce))
        return nonce

    def exit(self, values):
        func, nonce = self.call_stack.pop()
        ppt = f"..{func}():::EXIT0"
        self.w.declare(ppt, "subexit", legacy_specs(VARS))
        self.w.add_sample(ppt, values, nonce=nonce)
        return nonce


def _nonces(text, ppt):
    """Extract nonces from every sample of one ppt, in file order."""
    out = []
    for chunk in text.split(f"\n{ppt}\n")[1:]:
        lines = chunk.splitlines()
        if lines and lines[0] == "this_invocation_nonce":
            out.append(int(lines[1]))
    return out


def test_simple_call_pairs_enter_and_exit(tmp_path):
    path = tmp_path / "t.dtrace"
    t = FakeTracer(DaikonTraceWriter(str(path)))
    n = t.enter("f", [0, 5])
    assert t.exit([5, 5]) == n
    t.w.close()
    text = path.read_text()
    assert _nonces(text, "..f():::ENTER") == _nonces(text, "..f():::EXIT0")


def test_recursion_pairs_lifo(tmp_path):
    """fact(5): five nested frames, then five returns.

    The innermost EXIT must carry the OUTERMOST-last nonce (4), not the first.
    """
    path = tmp_path / "t.dtrace"
    t = FakeTracer(DaikonTraceWriter(str(path)))
    entered = [t.enter("fact", [0, n]) for n in (5, 4, 3, 2, 1)]
    exited = [t.exit([r, 0]) for r in (1, 2, 6, 24, 120)]
    t.w.close()

    assert entered == [0, 1, 2, 3, 4]
    assert exited == [4, 3, 2, 1, 0], "pairing is not LIFO"

    text = path.read_text()
    assert _nonces(text, "..fact():::ENTER") == [0, 1, 2, 3, 4]
    assert _nonces(text, "..fact():::EXIT0") == [4, 3, 2, 1, 0]


def test_mutual_recursion_keeps_frames_distinct(tmp_path):
    path = tmp_path / "t.dtrace"
    t = FakeTracer(DaikonTraceWriter(str(path)))
    a1 = t.enter("a", [0, 1])
    b1 = t.enter("b", [0, 2])
    a2 = t.enter("a", [0, 3])
    assert t.exit([0, 0]) == a2
    assert t.exit([0, 0]) == b1
    assert t.exit([0, 0]) == a1
    t.w.close()
    assert len({a1, b1, a2}) == 3


def test_nonces_unique_across_simulated_layouts(tmp_path):
    """--layouts N concatenates N runs into ONE trace.

    A per-run counter would reissue ids and let a run-2 EXIT pair with a run-1
    ENTER. The counter lives on the writer, which outlives the layout loop.
    """
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    for _ in range(3):                      # three layouts
        t = FakeTracer(w)                   # fresh call stack, shared writer
        t.enter("f", [0, 1])
        t.exit([1, 1])
    w.close()
    text = path.read_text()
    all_nonces = (_nonces(text, "..f():::ENTER") + _nonces(text, "..f():::EXIT0"))
    assert len(all_nonces) == 6
    assert len(set(all_nonces)) == 3, "nonces collided across layouts"


def test_dangling_enter_consumes_no_exit_nonce(tmp_path):
    """Truncated runs leave unmatched ENTERs.

    Daikon reports and drops them ("Unmatched entries are ignored!"); the
    writer's job is only to not reuse the id.
    """
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    t = FakeTracer(w)
    t.enter("f", [0, 1])
    t.enter("f", [0, 2])
    t.exit([1, 1])                 # only the inner frame returns
    w.close()
    text = path.read_text()
    assert _nonces(text, "..f():::ENTER") == [0, 1]
    assert _nonces(text, "..f():::EXIT0") == [1]
