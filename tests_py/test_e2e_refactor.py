"""End-to-end proof that the package split changed no behavior.

Marked e2e: needs unicorn and the compiled corpus. Deselect with -m "not e2e".

The golden file is the tier-0 output captured BEFORE the refactor. Tier 0 is
the frozen baseline the research measures against, so this doubles as a
permanent regression guard: tiers 1+ are opt-in via --tier, and any change that
moves tier-0 output is a bug, not a feature.
"""
import os
import pathlib
import re
import subprocess
import sys

import pytest

pytest.importorskip("unicorn")

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIM = REPO / "scripts" / "unicorn_dwarf.py"
GOLDEN = REPO / "tests_py" / "golden" / "test08.tier0.dtrace"
BINARY = REPO / "tests" / "test08.exe"

pytestmark = pytest.mark.e2e


def _trace(tmp_path, extra=()):
    if not BINARY.exists():
        pytest.skip(f"{BINARY} not built - run `make tests`")
    out = tmp_path / "out.dtrace"
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(BINARY), "-o", str(out),
         "--start-func", "main", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out, proc


def test_output_matches_pre_refactor_golden(tmp_path):
    if not GOLDEN.exists():
        pytest.skip(f"golden missing: {GOLDEN}")
    out, _ = _trace(tmp_path)
    assert out.read_bytes() == GOLDEN.read_bytes(), (
        "tier-0 output drifted from the pre-refactor baseline"
    )


def test_tier_0_flag_is_a_noop(tmp_path):
    """--tier is parsed but unused at tier 0; it must not perturb output."""
    if not GOLDEN.exists():
        pytest.skip(f"golden missing: {GOLDEN}")
    out, _ = _trace(tmp_path, extra=["--tier", "0"])
    assert out.read_bytes() == GOLDEN.read_bytes()


def test_samples_log_line_matches_the_regex_test_sh_greps():
    """test.sh:168 parses the sample count out of the tracer's log with this
    exact regex. If the prefix changes, test.sh does not fail - it silently
    reports `samp=?` forever, so nothing else would catch it."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out, proc = _trace(pathlib.Path(td))
        combined = proc.stdout + proc.stderr
    match = re.search(r"Samples:[ \t]*([0-9]+)", combined)
    assert match, f"test.sh's Samples: regex found nothing in:\n{combined}"
    assert int(match.group(1)) > 0


def test_emulation_is_deterministic(tmp_path):
    """The golden-file gate is only meaningful if runs are reproducible."""
    a, _ = _trace(tmp_path / "a")
    b, _ = _trace(tmp_path / "b")
    assert a.read_bytes() == b.read_bytes()


@pytest.fixture(autouse=True)
def _mk_subdirs(tmp_path):
    (tmp_path / "a").mkdir(exist_ok=True)
    (tmp_path / "b").mkdir(exist_ok=True)
