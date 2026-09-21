"""Tier 6 end-to-end: dereference and struct recovery."""
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

@pytest.mark.parametrize("tier", [0, 1, 2, 3, 5])
def test_lower_tier_goldens_unchanged(tmp_path, tier):
    text = _trace("test08", tmp_path / f"t{tier}.dtrace", "--tier", str(tier))
    assert text == (GOLDEN / f"test08.tier{tier}.dtrace").read_text()


# ---- field recovery --------------------------------------------------------

def test_stack_pointee_recovers_both_fields(tmp_path):
    """stack_read reads offsets 0 and 4, so both are directly observable."""
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    block = _decl(d, "..stack_read():::ENTER")
    assert "variable arg0[..].off0" in block
    assert "variable arg0[..].off4" in block


def test_attribution_is_by_value_not_register(tmp_path):
    """The pointer is spilled and reloaded into rax before use, so rdi itself
    is never dereferenced. Recovering any field at all proves attribution
    followed the VALUE rather than the argument register."""
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    assert "arg0[..].off" in d


def test_heap_pointee_recovers_only_what_is_read(tmp_path):
    """heap_read computes p->a * 2 and never touches the second field."""
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    block = _decl(d, "..heap_read():::ENTER")
    assert "variable arg0[..].off0" in block
    assert "variable arg0[..].off4" not in block


def test_tail_inference_recovers_the_unread_field(tmp_path):
    """malloc(8) against a 4-byte footprint means 4 bytes are unaccounted for.

    This is the second payoff from the tier-5 allocator: without the recorded
    allocation size the field is unrecoverable.
    """
    d = _trace("test08", tmp_path / "t6i.dtrace", "--tier", "6",
               "--infer-unobserved-fields")
    block = _decl(d, "..heap_read():::ENTER")
    assert "variable arg0[..].off4" in block


def test_declaration_shape_mirrors_kvasir(tmp_path):
    """Kvasir models a pointee as a one-element sequence, and matching that is
    what makes the two sides' invariant FORMS comparable."""
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    block = _decl(d, "..stack_read():::ENTER")
    assert "var-kind array" in block
    assert "enclosing-var arg0" in block
    assert "rep-type hashcode[]" in block
    assert "rep-type int[]" in block
    assert "array 1" in block


def test_pointee_values_use_bracket_syntax(tmp_path):
    d = _trace("test08", tmp_path / "t6.dtrace", "--tier", "6")
    assert "[ " in d and " ]" in d


def test_non_pointer_arguments_get_no_pointee(tmp_path):
    """test10's twelve() takes twelve ints; none should be dereferenced."""
    d = _trace("test10", tmp_path / "t6.dtrace", "--tier", "6")
    assert "[..]" not in _decl(d, "..twelve():::ENTER")


# ---- the recovered invariants ----------------------------------------------

def test_stack_field_relation_matches_kvasir(tmp_path):
    """Kvasir reports `p[].a - p[].b + 1 == 0`; the fields are named by offset
    here because stripping destroys source names."""
    out = tmp_path / "t6.dtrace"
    _trace("test08", out, "--tier", "6")
    report = _daikon(out, tmp_path)
    assert "arg0[].off0 - arg0[].off4 + 1 == 0" in report


def test_field_versus_return_relations_appear(tmp_path):
    """Requires `return` to share a comparability class with the fields - the
    tier-3 decision this phase depends on."""
    out = tmp_path / "t6.dtrace"
    _trace("test08", out, "--tier", "6")
    report = _daikon(out, tmp_path)
    assert "arg0[].off0 elements < return" in report
    assert "arg0[].off4 elements <= return" in report


def test_heap_field_relation_needs_tail_inference(tmp_path):
    """Kvasir reports `3 * p[].a - p[].b == 0`. The second field is never read
    by the program, so only the allocation size makes it recoverable."""
    out = tmp_path / "t6i.dtrace"
    _trace("test08", out, "--tier", "6", "--infer-unobserved-fields")
    report = _daikon(out, tmp_path)
    assert "3 * arg0[].off0 - arg0[].off4 == 0" in report


def test_packed_word_artifact_is_gone(tmp_path):
    """At tier 0 the fixed stack window captured the caller's struct as one
    64-bit word, encoding the true relation unrecognisably as
    `4.29...E9 * rax - 2 * stack0 + ... == 0`. Splitting by observed access
    width replaces it with the field form."""
    out = tmp_path / "t6.dtrace"
    _trace("test08", out, "--tier", "6")
    report = _daikon(out, tmp_path)
    assert "stack0" not in report
    assert "4.294967297E9" not in report


def test_recall_rises_sharply(tmp_path):
    """The criterion this phase is judged by.

    Tiers 2-5 improved precision and correctness while recall stayed flat or
    dipped; tier 6 is the one that must move it.
    """
    def count(path):
        report = _daikon(path, tmp_path)
        return len([ln for ln in report.splitlines()
                    if ln.strip() and ":::" not in ln
                    and not ln.strip().startswith(
                        ("=", "Daikon", "Exiting", "Reading", "Processing", "["))])

    t5, t6 = tmp_path / "t5.dtrace", tmp_path / "t6.dtrace"
    _trace("test08", t5, "--tier", "5")
    _trace("test08", t6, "--tier", "6")
    n5, n6 = count(t5), count(t6)
    assert n6 > n5 * 5, f"expected a large jump, got {n5} -> {n6}"
