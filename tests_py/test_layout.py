"""Migration completeness: every symbol landed in its intended module."""
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def test_log_module():
    from tracer.log import Logger
    assert Logger(quiet=True).quiet is True


def test_schema_module():
    from tracer.schema import NUM_STACK_ARG_SLOTS, REG_VARS_X64, REG_VARS_X86
    assert NUM_STACK_ARG_SLOTS == 4
    assert REG_VARS_X86 == ["eax", "ebx", "ecx", "edx"]


def test_stack_slot_count_agrees_with_name_list():
    """The two consumers of NUM_STACK_ARG_SLOTS must stay in step.

    The name list is built from it, and emulate._read_stack_args loops over it.
    Drift between them is silent in the output, so pin the arithmetic: seven
    register variables (rax + six ABI arg registers) plus the stack window.
    """
    from tracer.schema import NUM_STACK_ARG_SLOTS, REG_VARS_X64
    assert len(REG_VARS_X64) == 7 + NUM_STACK_ARG_SLOTS
    assert REG_VARS_X64[:7] == ["rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    assert REG_VARS_X64[7:] == [f"stack{i}" for i in range(NUM_STACK_ARG_SLOTS)]


def test_writer_module():
    from tracer.writer import DaikonTraceWriter
    assert hasattr(DaikonTraceWriter, "add_sample")


def test_elfload_module():
    from tracer.elfload import (
        DEFAULT_EXCLUDED, find_functions, find_functions_by_prologue,
        parse_symbol_functions,
    )
    assert "_start" in DEFAULT_EXCLUDED
    assert callable(find_functions)
    assert callable(find_functions_by_prologue)
    assert callable(parse_symbol_functions)


def test_emulate_module():
    pytest.importorskip("unicorn")
    from tracer.emulate import LAYOUT_STRIDE, Tracer, discover_main_via_emulation
    assert LAYOUT_STRIDE == 0x1000000
    assert callable(discover_main_via_emulation)
    assert hasattr(Tracer, "run")


def test_cli_docstring_moved_with_build_parser():
    """build_parser passes epilog=__doc__.

    If the module docstring were left behind in the old file, --help would
    still exit 0 while silently losing every usage example - a failure with no
    symptom other than worse docs.
    """
    pytest.importorskip("unicorn")
    import tracer.cli
    assert tracer.cli.__doc__
    assert "--layouts 5" in tracer.cli.__doc__
    assert "unicorn_trace_symtab" in tracer.cli.__doc__


def test_shim_is_thin():
    """scripts/unicorn_dwarf.py should delegate, not reimplement."""
    source = (REPO / "scripts" / "unicorn_dwarf.py").read_text()
    assert "from tracer.cli import main" in source
    assert len(source.splitlines()) < 30


def test_scripts_is_not_a_package():
    """The shim relies on sys.path[0] being scripts/.

    Adding scripts/__init__.py would turn it into a package and break
    `from tracer.cli import main` when run as a script.
    """
    assert not (REPO / "scripts" / "__init__.py").exists()
