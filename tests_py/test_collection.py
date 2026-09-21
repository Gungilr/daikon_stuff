"""Guard pytest's collection scope.

Two real hazards live in this repo:

1. pytest's default `python_files` includes `*_test.py`, which matches
   scripts/daikon_test.py and scripts/archive/unicorn_test.py. Neither is a
   test - daikon_test.py runs `pefile.PE("test.exe")` at module level against a
   file that does not exist in the repo root, so collecting it raises.

2. Without norecursedirs, a bare `pytest .` walks daikon/ (a full vendored java
   source tree), unicorn-2.0.1/ and venv/. Measured: it does not fail, it hangs.

Both are configuration-only defences, so they need a test or they will rot.
"""
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]


def _run_collect(args, timeout=120):
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider", *args],
        cwd=str(REPO), env=env, capture_output=True, text=True, timeout=timeout,
    )


def test_bare_collection_is_clean_and_fast():
    """Must terminate well inside the timeout; a hang here is the bug."""
    result = _run_collect([])
    assert result.returncode == 0, (
        f"collection failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )


def test_collection_never_reaches_scripts_or_vendored_trees():
    result = _run_collect([])
    combined = result.stdout + result.stderr
    for forbidden in ("scripts/daikon_test.py", "scripts/archive/unicorn_test.py",
                      "daikon/", "unicorn-2.0.1/", "venv/", "fjalar/"):
        assert forbidden not in combined, (
            f"collection reached {forbidden!r}; testpaths/norecursedirs regressed"
        )


def test_config_pins_the_narrow_python_files_pattern():
    """`*_test.py` must stay OUT of python_files.

    Re-adding it silently re-enables hazard 1 above.
    """
    cfg = (REPO / "pytest.ini").read_text()
    assert "python_files = test_*.py" in cfg
    assert "*_test.py" not in cfg.split("python_files =")[1].split("\n")[0]


def test_config_pins_pythonpath_and_testpaths():
    cfg = (REPO / "pytest.ini").read_text()
    assert "testpaths = tests_py" in cfg
    assert "pythonpath = scripts" in cfg
