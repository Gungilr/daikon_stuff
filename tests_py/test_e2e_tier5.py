"""Tier 5 end-to-end: the emulated allocator against real binaries."""
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
         "--start-func", "main", "-v", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_text(), proc.stdout + proc.stderr


def _values(dtrace, ppt, var):
    out, lines = [], dtrace.splitlines()
    for i, line in enumerate(lines):
        if line == ppt:
            for j in range(i + 1, min(i + 40, len(lines))):
                if lines[j] == var:
                    out.append(int(lines[j + 1])); break
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

@pytest.mark.parametrize("tier", [0, 1, 2, 3])
def test_lower_tier_goldens_unchanged(tmp_path, tier):
    text, _ = _trace("test08", tmp_path / f"t{tier}.dtrace", "--tier", str(tier))
    assert text == (GOLDEN / f"test08.tier{tier}.dtrace").read_text()


# ---- interception ----------------------------------------------------------

def test_allocators_are_detected(tmp_path):
    _, log = _trace("test08", tmp_path / "t5.dtrace", "--tier", "5")
    assert "malloc@" in log and "free@" in log


def test_allocators_detected_in_the_stripped_binary(tmp_path):
    """Nothing about the heap model depends on symbols."""
    _, log = _trace("test08_stripped", tmp_path / "t5s.dtrace", "--tier", "5")
    assert "malloc@" in log


# ---- the fix ---------------------------------------------------------------

def test_heap_pointer_is_no_longer_null(tmp_path):
    """Before tier 5, malloc was skipped with the return register forced to 0,
    so every heap pointer in the trace was null."""
    d, _ = _trace("test08", tmp_path / "t5.dtrace", "--tier", "5")
    vals = _values(d, "..heap_read():::ENTER", "arg0")
    assert vals and all(v != 0 for v in vals)


def test_tier3_still_shows_the_null_pointer(tmp_path):
    """Pins the before-state, so the fix is attributable to tier 5."""
    d, _ = _trace("test08", tmp_path / "t3.dtrace", "--tier", "3")
    assert all(v == 0 for v in _values(d, "..heap_read():::ENTER", "arg0"))


def test_ten_allocations_give_ten_distinct_addresses(tmp_path):
    """Matches Kvasir, which observed 10 distinct addresses under Valgrind
    despite the free() between iterations."""
    d, _ = _trace("test08", tmp_path / "t5.dtrace", "--tier", "5")
    vals = _values(d, "..heap_read():::ENTER", "arg0")
    assert len(vals) == 10
    assert len(set(vals)) == 10, "freed blocks are being reissued"


def test_heap_pointer_is_typed_as_a_pointer(tmp_path):
    """It classified as scalar while the stub made it null."""
    d, _ = _trace("test08", tmp_path / "t5.dtrace", "--tier", "5")
    assert "rep-type hashcode" in _decl(d, "..heap_read():::ENTER")


def test_the_program_still_computes_correctly(tmp_path):
    """heap_read returns p->a * 2 for a = 0..9.

    Getting 0,2,...,18 proves the arena is genuinely writable and readable, not
    merely a plausible-looking address.
    """
    d, _ = _trace("test08", tmp_path / "t5.dtrace", "--tier", "5")
    assert _values(d, "..heap_read():::EXIT0", "return") == list(range(0, 20, 2))


def test_false_positives_are_gone(tmp_path):
    """The stub manufactured two invariants that were true of the emulation and
    false of the program: `arg0 == 0` and `return >= orig(arg0)`."""
    out = tmp_path / "t5.dtrace"
    _trace("test08", out, "--tier", "5")
    report = _daikon(out, tmp_path)
    section = report.split("..heap_read():::ENTER")[1].split("=====")[0]
    assert "arg0 == 0" not in section
    exit_sec = report.split("..heap_read():::EXIT")[1].split("=====")[0]
    assert "return >= orig(arg0)" not in exit_sec


# ---- robustness ------------------------------------------------------------

def test_layouts_relocate_the_heap(tmp_path):
    """A fixed heap address must not masquerade as a program property."""
    d, _ = _trace("test08", tmp_path / "lay.dtrace", "--tier", "5", "--layouts", "3")
    vals = _values(d, "..heap_read():::ENTER", "arg0")
    assert len(vals) == 30
    assert len(set(vals)) == 30, "heap base did not move between layouts"


def test_tiny_arena_degrades_to_null_without_crashing(tmp_path):
    """Exhaustion must fall back to the pre-tier-5 behavior, not corrupt
    memory by handing out unmapped addresses."""
    d, _ = _trace("test08", tmp_path / "tiny.dtrace", "--tier", "5",
                  "--heap-size", "0x20")
    vals = _values(d, "..heap_read():::ENTER", "arg0")
    assert vals, "tracer produced no samples at all"
    assert any(v == 0 for v in vals), "expected some allocations to fail"


def test_arena_overlap_is_refused(tmp_path):
    """Silently overlapping a segment would corrupt program state in a way that
    looks like a bug in the target."""
    binary = REPO / "tests" / "test08.exe"
    if not binary.exists():
        pytest.skip("not built")
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(tmp_path / "x.dtrace"),
         "--start-func", "main", "--tier", "5", "--heap-base", "0x401000"],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode != 0 or "overlap" in (proc.stdout + proc.stderr).lower()
