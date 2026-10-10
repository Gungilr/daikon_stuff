"""--dump-inferences end to end, and the two flaws it was built to measure.

The dump records what the tracer concluded, for auditing against debug info
(scripts/audit_heuristics.py). It must never change the trace itself.

The last two tests compile tiny programs that reproduce flaws found by reading
the code (docs/HEURISTICS.md, H16 and H38). They pin the CURRENT, WRONG
behaviour on purpose, as test_unsigned_is_knowingly_wrong once did: when either
starts failing, the flaw has been fixed and the test should be inverted.
"""
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("unicorn")

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIM = REPO / "scripts" / "unicorn_dwarf.py"

pytestmark = pytest.mark.e2e


def _trace(binary, out, *extra):
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(out),
         "--start-func", "main", "--tier", "9", "--detect-void", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_bytes()


def _fixture(name):
    binary = REPO / "tests" / f"{name}.exe"
    if not binary.exists():
        pytest.skip(f"{binary} not built - run `make tests`")
    return binary


def _compile(tmp_path, source):
    if shutil.which("gcc") is None:
        pytest.skip("gcc not on PATH")
    src = tmp_path / "prog.c"
    src.write_text(source)
    exe = tmp_path / "prog.exe"
    subprocess.run(["gcc", "-g", "-O0", "-no-pie", "-fno-stack-protector",
                    "-o", str(exe), str(src)], check=True, timeout=120)
    return exe


def _dump(binary, tmp_path):
    out = tmp_path / "t.dtrace"
    report = tmp_path / "t.json"
    _trace(binary, out, "--dump-inferences", str(report))
    return json.loads(report.read_text())


def _by_name(report):
    return {f["name"]: f for f in report["functions"]}


def test_dump_leaves_the_trace_byte_identical(tmp_path):
    binary = _fixture("test12")
    plain = _trace(binary, tmp_path / "a.dtrace")
    dumped = _trace(binary, tmp_path / "b.dtrace",
                    "--dump-inferences", str(tmp_path / "b.json"))
    assert plain == dumped


def test_dump_reports_the_signedness_the_trace_uses(tmp_path):
    """test12: big_unsigned's caller shifts the result with `shr`, negate's
    consumer is signed. The dump must say what the emitted values show."""
    funcs = _by_name(_dump(_fixture("test12"), tmp_path))
    assert funcs["big_unsigned"]["ret_unsigned"] is True
    assert funcs["negate"]["ret_unsigned"] is False
    assert funcs["negate"]["return_kind"] == "scalar"


def test_float_return_rule_misfires_on_an_int_function(tmp_path):
    """H16, known wrong. Any SSE write to xmm0 marks the function as returning
    a double, and nothing clears it when the result is then converted to an
    int in eax. `half` is right; `truncate_twice` is declared to return a
    double read from xmm0. When this fails, H16 is fixed: invert it."""
    exe = _compile(tmp_path, """
        int truncate_twice(double x) { return (int)(x * 2.0); }
        double half(double x) { return x / 2.0; }
        int main(void) {
            int s = 0;
            for (int i = 0; i < 3; i++) s += truncate_twice(i + 0.25) + (int)half(i);
            return s & 1;
        }
    """)
    funcs = _by_name(_dump(exe, tmp_path))
    assert funcs["half"]["return_kind"] == "float"
    assert funcs["truncate_twice"]["return_kind"] == "float"   # WRONG: an int


def test_function_pointer_call_into_the_program_is_skipped(tmp_path):
    """H38, known wrong. `call rax` has no target in its encoding, so it is
    treated like a library call and skipped: `twice` never runs. The dump
    resolves the operand, which is how the corpus audit counts this. When
    `twice` starts being entered, H38 is fixed: invert it."""
    exe = _compile(tmp_path, """
        static int twice(int x) { return 2 * x; }
        int apply(int (*f)(int), int v) { return f(v); }
        int main(void) { return apply(twice, 21) == 42 ? 0 : 1; }
    """)
    report = _dump(exe, tmp_path)
    funcs = _by_name(report)
    into_program = [c for c in report["indirect_calls"] if c["is_function"]]
    assert [c["target"] for c in into_program] == [funcs["twice"]["addr"]]
    assert funcs["twice"]["enters"] == 0                       # WRONG: it ran
    assert funcs["apply"]["enters"] == 1


def test_ignore_globals_drops_every_global(tmp_path):
    """--ignore-globals mirrors Kvasir's option: no global is declared even at
    tier 9, and nothing else changes - the argument and return survive."""
    exe = _compile(tmp_path, """
        int counter = 5;
        int bump(int x) { counter += x; return counter; }
        int main(void) { return bump(1) == 6 ? 0 : 1; }
    """)
    with_globals = _trace(exe, tmp_path / "a.dtrace").decode()
    without = _trace(exe, tmp_path / "b.dtrace", "--ignore-globals").decode()
    assert "g_0x" in with_globals
    assert "g_0x" not in without
    assert "variable arg0\n" in without and "variable return\n" in without
