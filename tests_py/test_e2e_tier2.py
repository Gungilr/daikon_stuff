"""Tier 2 end-to-end: arity detection against real binaries."""
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("unicorn")

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIM = REPO / "scripts" / "unicorn_dwarf.py"
GOLDEN_T0 = REPO / "tests_py" / "golden" / "test08.tier0.dtrace"
GOLDEN_T1 = REPO / "tests_py" / "golden" / "test08.tier1.dtrace"
DAIKON = REPO / "daikon"

pytestmark = pytest.mark.e2e


def _trace(name, out, *extra):
    binary = REPO / "tests" / f"{name}.exe"
    if not binary.exists():
        pytest.skip(f"{binary} not built - run `make tests`")
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(out),
         "--start-func", "main", "-v", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_text(), proc.stdout + proc.stderr


def _arities(log):
    """Parse the verbose `arity NAME @0xADDR: R reg + S stack = N` lines."""
    return {m[0]: int(m[1]) for m in
            re.findall(r"arity (\w+) @0x[0-9a-f]+: \d+ reg \+ \d+ stack = (\d+)", log)}


def _n_vars(dtrace, ppt):
    block = dtrace.split(f"ppt {ppt}\n")[1].split("\n\n")[0]
    return block.count("variable ")


def _daikon(dtrace, tmp_path):
    if shutil.which("java") is None:
        pytest.skip("java not on PATH")
    if not (DAIKON / "java" / "daikon" / "Daikon.class").exists():
        pytest.skip("daikon not built")
    proc = subprocess.run(
        ["java", "-cp", f"{DAIKON}/java:{DAIKON}/java/lib/*", "daikon.Daikon",
         "-o", str(tmp_path / "o.inv.gz"), str(dtrace)],
        cwd=str(REPO), capture_output=True, text=True, timeout=600,
    )
    return proc.stdout + proc.stderr


def _count_invariants(report):
    return len([
        ln for ln in report.splitlines()
        if ln and ":::" not in ln
        and not ln.startswith(("=", "Daikon", "Exiting", "Reading",
                               "Processing", "[", " "))
    ])


# ---- lower tiers must not move ---------------------------------------------

def test_tier0_golden_unchanged(tmp_path):
    """The deferred-schema refactor touched the sample path for every tier."""
    text, _ = _trace("test08", tmp_path / "t0.dtrace")
    assert text == GOLDEN_T0.read_text()


def test_tier1_golden_unchanged(tmp_path):
    text, _ = _trace("test08", tmp_path / "t1.dtrace", "--tier", "1")
    assert text == GOLDEN_T1.read_text()


# ---- arity ------------------------------------------------------------------

def test_pointer_argument_functions(tmp_path):
    _, log = _trace("test08", tmp_path / "t2.dtrace", "--tier", "2")
    a = _arities(log)
    assert a["stack_read"] == 1
    assert a["heap_read"] == 1
    assert a["main"] == 0


def test_register_and_stack_arguments(tmp_path):
    """stack8's 7th argument is dead AND on the stack, so it is never spilled.

    Only contiguity recovers it - a set-union rule would report 7.
    """
    _, log = _trace("test07", tmp_path / "t2.dtrace", "--tier", "2")
    a = _arities(log)
    assert a["reg6"] == 6
    assert a["stack8"] == 8


def test_dead_parameters_recovered_at_O0(tmp_path):
    """gcc -O0 spills every parameter regardless of use.

    At -O1 `pick_first` would report 1 against Kvasir's 2; this corpus is -O0,
    which flatters the heuristic.
    """
    _, log = _trace("test09", tmp_path / "t2.dtrace", "--tier", "2")
    a = _arities(log)
    assert a["pick_first"] == 2
    assert a["skip_middle"] == 3
    assert a["trailing_dead"] == 2


def test_twelve_arguments_exceeds_the_old_fixed_window(tmp_path):
    """6 register + 6 stack, from a single read of the 12th argument."""
    _, log = _trace("test10", tmp_path / "t2.dtrace", "--tier", "2")
    a = _arities(log)
    assert a["twelve"] == 12
    assert a["nullary"] == 0


# ---- emitted schema ---------------------------------------------------------

def test_variable_count_collapses(tmp_path):
    dtrace, _ = _trace("test08", tmp_path / "t2.dtrace", "--tier", "2")
    assert _n_vars(dtrace, "..stack_read():::ENTER") == 2      # rax + arg0
    for gone in ("variable rsi", "variable rcx", "variable r8",
                 "variable r9", "variable stack0"):
        assert gone not in dtrace


def test_twelve_declares_all_twelve_args(tmp_path):
    dtrace, _ = _trace("test10", tmp_path / "t2.dtrace", "--tier", "2")
    block = dtrace.split("ppt ..twelve():::ENTER\n")[1].split("\n\n")[0]
    for i in range(12):
        assert f"variable arg{i}\n" in block
    assert "variable arg12\n" not in block


def test_nullary_declares_no_argument_variables(tmp_path):
    """Arity 0 must yield a valid ppt, not a crash or a dropped point.

    rax is still present at tier 2; tier 3 promotes it to `return` and leaves
    ENTER genuinely empty, as Kvasir's main(void) is.
    """
    dtrace, _ = _trace("test10", tmp_path / "t2.dtrace", "--tier", "2")
    block = dtrace.split("ppt ..nullary():::ENTER\n")[1].split("\n\n")[0]
    assert "variable arg0" not in block
    assert "variable rax" in block


# ---- the measured outcome ---------------------------------------------------

def test_invariant_count_falls_sharply(tmp_path):
    """The headline number: 179 at tiers 0-1, ~17 here.

    Asserted as a direction and a loose bound so the test does not become a
    maintenance burden every time Daikon's inference changes.
    """
    t1 = tmp_path / "t1.dtrace"
    t2 = tmp_path / "t2.dtrace"
    _trace("test08", t1, "--tier", "1")
    _trace("test08", t2, "--tier", "2")
    n1 = _count_invariants(_daikon(t1, tmp_path))
    n2 = _count_invariants(_daikon(t2, tmp_path))
    assert n1 > 100, f"tier 1 baseline moved unexpectedly ({n1})"
    assert n2 < n1 / 3, f"expected a sharp drop, got {n1} -> {n2}"


def test_accidental_pointee_recovery_is_destroyed(tmp_path):
    """Tier 2 removes real information along with the noise.

    At tier 0/1 the tracer encoded stack_read's true relation twice by accident:
    `4.29...E9 * rax - 2 * stack0 + ... == 0` (the caller's struct, captured
    because the fixed stack window overlapped main's frame) and
    `rax - 2 * rdx - 1 == 0` (p->a left in a scratch register). Neither slot is
    an argument, so tier 2 correctly drops both - and the semantic facts go with
    them.

    This pins the finding rather than guarding against regression: recall is
    expected to FALL at tier 2 and not recover until dereference lands in
    tier 6. If this test starts failing, tier 2 has stopped pruning
    non-arguments.
    """
    t1 = tmp_path / "t1.dtrace"
    t2 = tmp_path / "t2.dtrace"
    _trace("test08", t1, "--tier", "1")
    _trace("test08", t2, "--tier", "2")
    r1 = _daikon(t1, tmp_path)
    r2 = _daikon(t2, tmp_path)

    exit1 = r1.split("..stack_read():::EXIT")[1].split("=====")[0]
    exit2 = r2.split("..stack_read():::EXIT")[1].split("=====")[0]
    assert "rax - 2 * rdx - 1 == 0" in exit1, "tier-1 baseline finding vanished"
    assert "rdx" not in exit2
    assert "stack0" not in exit2
