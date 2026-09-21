"""Tier 7 end-to-end: array pointees."""
import pathlib
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("unicorn")

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIM = REPO / "scripts" / "unicorn_dwarf.py"
GOLDEN = REPO / "tests_py" / "golden"
DAIKON = REPO / "daikon"

pytestmark = pytest.mark.e2e


def _trace(name, out, *extra):
    binary = REPO / "tests" / f"{name}.exe"
    if not binary.exists():
        pytest.skip(f"{binary} not built - run `make tests`")
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(out),
         "--start-func", "main", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_text()


def _decl(dtrace, ppt):
    return dtrace.split(f"ppt {ppt}\n")[1].split("\n\n")[0]


def _values(dtrace, ppt, var):
    out, lines = [], dtrace.splitlines()
    for i, line in enumerate(lines):
        if line == ppt:
            for j in range(i + 1, min(i + 60, len(lines))):
                if lines[j] == var:
                    out.append(lines[j + 1]); break
                if lines[j] == "":
                    break
    return out


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
    return (proc.stdout + proc.stderr).replace("\r", "")


# ---- lower tiers frozen ----------------------------------------------------

@pytest.mark.parametrize("tier", [0, 1, 2, 3, 5, 6])
def test_lower_tier_goldens_unchanged(tmp_path, tier):
    text = _trace("test08", tmp_path / f"t{tier}.dtrace", "--tier", str(tier))
    assert text == (GOLDEN / f"test08.tier{tier}.dtrace").read_text()


def test_structs_are_untouched_by_tier7(tmp_path):
    """test08 has only struct pointees, so tier 7 must change nothing.

    A discriminator that fired here would cost the off0/off4 relations that
    tier 6 worked to recover.
    """
    t6 = _trace("test08", tmp_path / "a.dtrace", "--tier", "6")
    t7 = _trace("test08", tmp_path / "b.dtrace", "--tier", "7")
    assert t6 == t7


# ---- the array model -------------------------------------------------------

def test_array_pointee_is_a_sequence(tmp_path):
    """Kvasir emits `arr[..]` as int[] carrying every element, with no field
    sub-variables; the two forms are alternatives, not complements."""
    d = _trace("test13", tmp_path / "t7.dtrace", "--tier", "7")
    block = _decl(d, "..sum_array():::ENTER")
    assert "rep-type int[]" in block
    assert "hashcode[]" not in block
    assert "off0" not in block


def test_array_values_carry_every_element(tmp_path):
    d = _trace("test13", tmp_path / "t7.dtrace", "--tier", "7")
    vals = _values(d, "..sum_array():::ENTER", "arg0[..]")
    assert vals and vals[0] == "[ 1 2 3 4 5 ]"


def test_struct_with_an_unrelated_int_stays_a_struct(tmp_path):
    """two_fields(p, 99) is the trap: a two-element pointee whose function also
    takes an int. Only a value equal to the element count should trigger the
    array model, and 99 never does."""
    d = _trace("test13", tmp_path / "t7.dtrace", "--tier", "7")
    block = _decl(d, "..two_fields():::ENTER")
    assert "variable arg0[..].off0" in block
    assert "variable arg0[..].off4" in block


def test_tier6_models_the_array_as_a_struct(tmp_path):
    """Pins the before-state, so the change is attributable to tier 7."""
    d = _trace("test13", tmp_path / "t6.dtrace", "--tier", "6")
    block = _decl(d, "..sum_array():::ENTER")
    assert "off0" in block, "tier 6 should still use the field form"


# ---- regression guard for the capture bug ----------------------------------

def test_single_call_function_recovers_its_pointee(tmp_path):
    """Pointee capture used to consult arity(), which is (0,0) until some of
    the function's instructions have run. Every function lost its FIRST call's
    pointee, and a function called once - like sum_array - lost everything to
    `nonsensical`. Any array measurement taken before the fix was meaningless.
    """
    d = _trace("test13", tmp_path / "t7.dtrace", "--tier", "7")
    vals = _values(d, "..sum_array():::ENTER", "arg0[..]")
    assert vals and vals[0] != "nonsensical"


def test_first_call_pointee_is_recovered(tmp_path):
    """The same bug, in its subtler form: sample 1 of a repeatedly-called
    function."""
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    vals = _values(d, "..stack_read():::ENTER", "arg0[..].off0")
    assert vals, "no samples captured"
    assert vals[0] != "nonsensical", "first call lost its pointee again"


# ---- what the sequence form buys -------------------------------------------

def test_sequence_facts_appear(tmp_path):
    """The point of the array model: Daikon reasons over the sequence, which
    the per-field form cannot express."""
    out = tmp_path / "t7.dtrace"
    _trace("test13", out, "--tier", "7")
    report = _daikon(out, tmp_path)
    section = report.split("..sum_array():::ENTER")[1].split("=====")[0]
    assert "arg0[]" in section, f"no sequence facts reported:\n{section}"


# ---- review 2026-09-17 regressions -----------------------------------------

def test_null_argument_does_not_destroy_pointee_recovery(tmp_path):
    """B1. A function called with both a valid pointer and NULL used to emit no
    pointee at all - one NULL demoted the slot to scalar for every call."""
    src = REPO / "tests" / "test14.exe"
    if not src.exists():
        pytest.skip("test14 not built - run `make tests`")
    d = _trace("test14", tmp_path / "t7.dtrace", "--tier", "7")
    block = _decl(d, "..maybe():::ENTER")
    assert "variable arg0[..].off0" in block
    vals = _values(d, "..maybe():::ENTER", "arg0[..].off0")
    assert "[ 3 ]" in vals, f"valid call lost its pointee: {vals}"
    assert "nonsensical" in vals, f"null call should be nonsensical: {vals}"


def test_out_parameter_fields_are_recovered(tmp_path):
    """B2. Only UC_HOOK_MEM_READ was hooked, so a field that is written and
    never read left no footprint. Out-parameters are a common C idiom and were
    invisible in their entirety."""
    src = REPO / "tests" / "test14.exe"
    if not src.exists():
        pytest.skip("test14 not built - run `make tests`")
    d = _trace("test14", tmp_path / "t7.dtrace", "--tier", "7")
    block = _decl(d, "..fill():::ENTER")
    assert "variable arg0[..].off0" in block
    assert "variable arg0[..].off4" in block
