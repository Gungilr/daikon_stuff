"""Enforce the import-purity boundary that makes tiers 2-3 testable.

writer/schema/log must be importable with unicorn, capstone and pyelftools all
unavailable. If that ever stops being true, inference logic can no longer be
unit-tested without booting an emulator, which is the whole reason the package
was split.

Each check runs in a SUBPROCESS. An in-process assertion like
`"unicorn" not in sys.modules` would pass vacuously the moment any other test
in the session imports it, so isolation is load-bearing rather than fussy.
"""
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"

PURE_MODULES = ["tracer.writer", "tracer.schema", "tracer.log", "tracer"]
IMPURE_MODULES = ["tracer.emulate", "tracer.elfload"]

# Installs a meta_path finder that raises on the binary-analysis libraries,
# then imports the target module. Exits 0 only if the import survived.
PROBE = """
import sys

BLOCKED = {{"unicorn", "capstone", "elftools"}}


class Blocker:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in BLOCKED:
            raise ImportError("blocked by purity test: " + fullname)
        return None


sys.meta_path.insert(0, Blocker())
import {module}
print("IMPORT_OK")
"""


def _probe(module):
    # Inherit the real environment and override only PYTHONPATH. A minimal env
    # risks failing for unrelated reasons (missing HOME, PATH, locale), which
    # would make a purity failure indistinguishable from an environment one.
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SCRIPTS)
    return subprocess.run(
        [sys.executable, "-c", PROBE.format(module=module)],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.parametrize("module", PURE_MODULES)
def test_pure_modules_import_without_binary_libs(module):
    result = _probe(module)
    assert "IMPORT_OK" in result.stdout, (
        f"{module} could not be imported with unicorn/capstone/pyelftools "
        f"blocked.\nstderr:\n{result.stderr}"
    )


@pytest.mark.parametrize("module", IMPURE_MODULES)
def test_blocker_actually_blocks(module):
    """Negative control.

    Without this, a silently broken Blocker would make every test above pass
    for the wrong reason. These two modules genuinely need the libraries, so
    they MUST fail under the block.
    """
    result = _probe(module)
    assert "IMPORT_OK" not in result.stdout, (
        f"{module} imported despite the block - the purity probe is broken, "
        f"so the passing results above are meaningless"
    )


def test_package_init_has_no_heavy_reexports():
    """`import tracer.writer` runs tracer/__init__ first.

    Re-exporting anything from emulate.py there would drag unicorn into every
    pure import and silently void this entire file.
    """
    source = (SCRIPTS / "tracer" / "__init__.py").read_text()
    for forbidden in ("from .emulate", "from .elfload", "import emulate"):
        assert forbidden not in source, (
            f"tracer/__init__.py contains {forbidden!r}; that makes every "
            f"'pure' import pull in the emulator"
        )
