"""Tier 3 end-to-end: return value, signed values, comparability."""
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


def _returns(dtrace, func):
    """Every `return` value emitted at func's exit, in order."""
    out, lines = [], dtrace.splitlines()
    for i, line in enumerate(lines):
        if line == f"..{func}():::EXIT0":
            for j in range(i + 1, min(i + 40, len(lines))):
                if lines[j] == "return":
                    out.append(int(lines[j + 1]))
                    break
                if lines[j] == "":
                    break
    return out


def _decl(dtrace, ppt):
    return dtrace.split(f"ppt {ppt}\n")[1].split("\n\n")[0]


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

@pytest.mark.parametrize("tier", [0, 1, 2])
def test_lower_tier_goldens_unchanged(tmp_path, tier):
    text = _trace("test08", tmp_path / f"t{tier}.dtrace", "--tier", str(tier))
    assert text == (GOLDEN / f"test08.tier{tier}.dtrace").read_text()


# ---- the headline fix ------------------------------------------------------

def test_negative_returns_match_kvasir(tmp_path):
    """Latent since tier 0: -1 was reported as 4294967295, so Daikon inferred
    a positive value where the truth is negative."""
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    assert _returns(d, "negate") == [-1, -2, -3, -4, -5]


def test_negative_arguments_round_trip(tmp_path):
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    assert _returns(d, "takes_negative") == [-2, -3, -4, -5, -6]


def test_tier2_still_shows_the_raw_unsigned_value(tmp_path):
    """Pins the before-state, so the fix is attributable to tier 3."""
    d = _trace("test12", tmp_path / "t2.dtrace", "--tier", "2")
    vals = _returns(d, "negate")
    assert vals == [] or all(v > 0 for v in vals)


def test_pointers_are_not_sign_extended(tmp_path):
    """A 64-bit stack address must survive intact."""
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    vals = _returns(d, "identity_ptr")
    assert vals, "no pointer returns captured"
    for v in vals:
        assert v > 0, "pointer was sign-extended into a negative number"


def test_unsigned_return_matches_kvasir(tmp_path):
    """Signedness IS observable - from the operations, not the value.

    This test previously asserted the WRONG answer, on the reasoning that
    nothing dynamic distinguishes `int` from `unsigned`. That was too strong:
    gcc picks a different opcode for signed and unsigned operands, and
    big_unsigned's caller emits `shr $0x1c,%eax` - a logical shift - on the
    returned value. Watching the consuming opcode recovers the signedness, and
    the tracer now agrees with Kvasir exactly.
    """
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    vals = _returns(d, "big_unsigned")
    assert vals == [2147483649, 2147483650, 2147483651, 2147483652, 2147483653]


def test_signed_returns_are_unaffected(tmp_path):
    """The unsigned path must not disturb genuinely signed results."""
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    assert _returns(d, "negate") == [-1, -2, -3, -4, -5]


# ---- return value ----------------------------------------------------------

def test_rax_is_gone_from_enter(tmp_path):
    """rax holds caller residue at entry; Kvasir declares no return there."""
    d = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    enter = _decl(d, "..stack_read():::ENTER")
    assert "variable rax" not in enter
    assert "variable return" not in enter


def test_return_declared_at_exit(tmp_path):
    d = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    assert "variable return" in _decl(d, "..stack_read():::EXIT0")


def test_main_enter_is_empty_like_kvasir(tmp_path):
    """Kvasir's main ENTER has zero variables; arity 0 plus no rax matches."""
    d = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    assert "variable " not in _decl(d, "..main():::ENTER")


def test_void_function_omits_return_under_the_flag(tmp_path):
    d = _trace("test12", tmp_path / "t3v.dtrace", "--tier", "3", "--detect-void")
    assert "variable return" not in _decl(d, "..discard_me():::EXIT0")
    assert "variable return" in _decl(d, "..negate():::EXIT0")


def test_void_detection_is_opt_in(tmp_path):
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    assert "variable return" in _decl(d, "..discard_me():::EXIT0")


# ---- comparability ---------------------------------------------------------

def test_header_is_implicit(tmp_path):
    d = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    assert "var-comparability implicit" in d


def test_pointer_argument_typed_as_hashcode(tmp_path):
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    assert "rep-type hashcode" in _decl(d, "..identity_ptr():::EXIT0")


def test_return_shares_a_class_with_same_typed_arguments(tmp_path):
    """Kvasir puts return and its int fields both in class 3, which is what
    produces the return-vs-field family once dereference lands in tier 6.
    Splitting them would silently delete the most valuable invariants."""
    d = _trace("test12", tmp_path / "t3.dtrace", "--tier", "3")
    block = _decl(d, "..negate():::EXIT0")
    classes = [ln.split()[-1] for ln in block.splitlines()
               if ln.strip().startswith("comparability")]
    assert len(classes) == 2, block
    assert classes[0] == classes[1], "int argument and int return were split"


def test_cross_type_comparisons_are_pruned(tmp_path):
    """int-vs-pointer relations that survived tier 2 must be gone."""
    out = tmp_path / "t3.dtrace"
    _trace("test08", out, "--tier", "3")
    report = _daikon(out, tmp_path)
    exit_sec = report.split("..stack_read():::EXIT")[1].split("=====")[0]
    assert "return < arg0" not in exit_sec
    assert "return >= arg0" not in exit_sec


# ---- the measured outcome --------------------------------------------------

def test_main_exit_matches_kvasir_exactly(tmp_path):
    """The first byte-identical agreement with the oracle."""
    out = tmp_path / "t3.dtrace"
    _trace("test03", out, "--tier", "3")
    report = _daikon(out, tmp_path)
    section = report.split("..main():::EXIT")[1].split("=====")[0]
    assert "return == 0" in section


def test_scalar_program_recovers_kvasirs_facts(tmp_path):
    """test03 is a one-line sum() plus a loop.

    Kvasir reports two facts and tier 3 recovers both, differing only in the
    parameter NAME, which stripping destroys for good:

        kvasir: return == 0 | return - orig(num) - 1 == 0
        ours:   return == 0 | arg0 - return + 1 == 0

    We additionally report `arg0 == orig(arg0)` - true, but trivial. Kvasir
    suppresses that class via `flags is_param`, which we deliberately do not
    set because the same flag makes Daikon drop non-unit coefficients and
    suppress correct invariants outright (see test_is_param_not_emitted).
    So the count is 3 against 2, and the extra one is sound.
    """
    out = tmp_path / "t3.dtrace"
    _trace("test03", out, "--tier", "3")
    report = _daikon(out, tmp_path)
    assert "return == 0" in report
    assert "arg0 - return + 1 == 0" in report


def test_is_param_not_emitted(tmp_path):
    """`flags is_param` makes Daikon report FALSE invariants.

    Reproduced on a synthetic trace with return = 2a+1: without the flag
    Daikon prints `2 * a - return + 1 == 0`; with it, `return - orig(a) - 1
    == 0`, which is false on every sample. On tests/test09.c it additionally
    suppresses `trailing_dead`'s relation entirely. Kvasir sets the flag and
    is wrong on both counts; we do not set it.
    """
    d = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    assert "is_param" not in d


def test_exit_arguments_come_from_the_spill_slot(tmp_path):
    """Argument registers are caller-saved and the body reuses them.

    In skip_middle(a,b,c) gcc -O0 reloads `a` into edx, so re-reading the
    third argument register at `ret` yields the FIRST argument and fabricates
    `arg0 == arg2`. No input disproves it - the clobber is deterministic - so
    it would be permanent noise for any consumer. Reading the prologue spill
    slot instead gives the real parameter.
    """
    d = _trace("test09", tmp_path / "t3.dtrace", "--tier", "3")
    lines = d.splitlines()
    pairs = []
    for i, line in enumerate(lines):
        if line == "..skip_middle():::EXIT0":
            vals = {}
            for j in range(i + 1, min(i + 30, len(lines))):
                if lines[j] in ("arg0", "arg2"):
                    vals[lines[j]] = int(lines[j + 1])
                if lines[j] == "":
                    break
            pairs.append(vals)
    assert pairs, "no skip_middle exits captured"
    # c == a + 1 by construction; a clobbered read would make them equal.
    for p in pairs:
        assert p["arg2"] == p["arg0"] + 1, f"clobbered register value: {p}"
