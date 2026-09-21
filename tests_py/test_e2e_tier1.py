"""Tier 1 end-to-end: real binaries, real Unicorn, real Daikon where available.

Deselect with -m "not e2e".
"""
import os
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


def _trace(binary, out, *extra):
    if not binary.exists():
        pytest.skip(f"{binary} not built - run `make tests`")
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(out),
         "--start-func", "main", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_text()


def _daikon(dtrace, tmp_path):
    """Run Daikon, returning its text report. Skips if java is unavailable."""
    if shutil.which("java") is None:
        pytest.skip("java not on PATH")
    if not (DAIKON / "java" / "daikon" / "Daikon.class").exists():
        pytest.skip("daikon not built")
    cp = f"{DAIKON}/java:{DAIKON}/java/lib/*"
    proc = subprocess.run(
        ["java", "-cp", cp, "daikon.Daikon",
         "-o", str(tmp_path / "out.inv.gz"), str(dtrace)],
        cwd=str(REPO), capture_output=True, text=True, timeout=600,
    )
    return proc.stdout + proc.stderr


# ---- tier 0 must not move --------------------------------------------------

def test_tier0_unchanged_by_phase1(tmp_path):
    """The phase 1 writer rewrite touched the tier-0 serialization path."""
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "t0.dtrace")
    assert text == GOLDEN_T0.read_text()


def test_tier0_flag_matches_no_flag(tmp_path):
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "t0.dtrace", "--tier", "0")
    assert text == GOLDEN_T0.read_text()


# ---- tier 1 output ---------------------------------------------------------

def test_tier1_matches_golden(tmp_path):
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "t1.dtrace", "--tier", "1")
    assert text == GOLDEN_T1.read_text()


def test_tier1_format_rules(tmp_path):
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "t1.dtrace", "--tier", "1")
    declarations = text.split("\n..")[0]
    assert "this_invocation_nonce" not in declarations, "nonce must not be declared"
    assert "orig(" not in text, "orig() is derived by Daikon, never emitted"
    assert ":::EXIT1" not in text
    assert "ppt-type subexit" in text


def test_tier1_nonce_has_no_modbit(tmp_path):
    """Regression guard for the silent sample-desync failure mode."""
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "t1.dtrace", "--tier", "1")
    block = text.split("\n..stack_read():::ENTER\n")[1].splitlines()
    assert block[0] == "this_invocation_nonce"
    assert block[1].isdigit()
    assert not block[2].isdigit(), (
        f"expected a variable name after the nonce, got {block[2]!r} - "
        f"a modbit here shifts every following triple"
    )


def test_tier1_nonces_unique_across_layouts(tmp_path):
    """--layouts 3 merges three runs into one trace.

    A nonce legitimately appears TWICE - once at ENTER and once at the matching
    EXIT - so file-wide uniqueness is the wrong property. What must hold is that
    each invocation gets its own id: one distinct nonce per ENTER sample, with
    no id reissued by a later layout.
    """
    text = _trace(REPO / "tests" / "test08.exe", tmp_path / "l.dtrace",
                  "--tier", "1", "--layouts", "3")

    enter_nonces, all_nonces = [], []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line != "this_invocation_nonce":
            continue
        nonce = lines[i + 1]
        all_nonces.append(nonce)
        if lines[i - 1].endswith(":::ENTER"):
            enter_nonces.append(nonce)

    assert len(enter_nonces) > 3, "expected several invocations across 3 layouts"
    assert len(set(enter_nonces)) == len(enter_nonces), (
        "an invocation id was reissued - the counter is being reset per layout"
    )
    from collections import Counter
    worst = Counter(all_nonces).most_common(1)[0]
    assert worst[1] <= 2, f"nonce {worst[0]} used {worst[1]} times (max 2: ENTER+EXIT)"


# ---- the actual deliverable ------------------------------------------------

def test_tier1_ppt_names_align_with_kvasir(tmp_path):
    """Tier 1 exists for this.

    Daikon only synthesizes a combined `:::EXIT` when exit sites are declared
    `subexit`. Tier 0 declares `exit`, so it reports `:::EXIT1`, which cannot be
    matched against Kvasir's `:::EXIT` - blocking the phase 4 scorer.
    """
    out = tmp_path / "t1.dtrace"
    _trace(REPO / "tests" / "test08.exe", out, "--tier", "1")
    report = _daikon(out, tmp_path)
    assert "..stack_read():::EXIT\n" in report
    assert "..stack_read():::EXIT1" not in report


def test_tier1_does_not_change_invariant_count(tmp_path):
    """Tier 1 changes framing only.

    Same variables, same values, same facts - only the wrapper differs. If this
    ever fails, tier 1 has started inferring something, which is not its job.
    """
    def count(path):
        report = _daikon(path, tmp_path)
        return len([
            ln for ln in report.splitlines()
            if ln and not ln.startswith(("=", "Daikon", "Exiting", "Reading",
                                         "Processing", "[", " "))
            and ":::" not in ln
        ])

    t0 = tmp_path / "t0.dtrace"
    t1 = tmp_path / "t1.dtrace"
    _trace(REPO / "tests" / "test08.exe", t0, "--tier", "0")
    _trace(REPO / "tests" / "test08.exe", t1, "--tier", "1")
    assert count(t0) == count(t1)


def test_tier1_preserves_recursive_pairing(tmp_path):
    """`return % orig(n) == 0` reads out which pairing Daikon used.

    It holds under LIFO (1%1, 2%2, 6%3, 24%4, 120%5) and fails immediately under
    arrival order (1%5). Tier 0 already gets this right via stack discipline;
    the explicit nonce must not regress it.
    """
    out = tmp_path / "rec.dtrace"
    _trace(REPO / "tests" / "test11.exe", out, "--tier", "1")
    report = _daikon(out, tmp_path)
    exit_section = report.split("..fact():::EXIT")[-1].split("=====")[0]
    assert "rax % orig(rdi) == 0" in exit_section, (
        f"recursive ENTER/EXIT pairing looks wrong:\n{exit_section}"
    )
