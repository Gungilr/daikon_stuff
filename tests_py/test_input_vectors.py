"""Input-vector parsing and the argv/libc models (pure where possible).

Phase 12. The tracer could not hand a program any input, so four of six large
programs in Daikon's suite printed a usage message and exited - Kvasir saw 756
calls in `replace` where we saw 44. That is a measurement of the missing input,
not of the tracer.
"""
import types

import pytest

from tracer.emulate import ARGV_BASE, LIBC_STUBS, Tracer


def _tracer(**kw):
    """A Tracer with only the attributes _input_vectors touches."""
    t = object.__new__(Tracer)
    fields = {"argv": None, "argv_file": None}
    fields.update(kw)
    t.args = types.SimpleNamespace(**fields)
    t.log = types.SimpleNamespace(error=lambda *a, **k: None,
                                  verbose=lambda *a, **k: None,
                                  info=lambda *a, **k: None)
    return t


def test_no_input_is_one_empty_run():
    """`[[]]` reproduces the pre-phase-12 behaviour, which is what keeps every
    golden file valid."""
    assert _tracer()._input_vectors() == [[]]


def test_a_single_vector_splits_on_whitespace():
    t = _tracer(argv="958 1  1   2597")
    assert t._input_vectors() == [["958", "1", "1", "2597"]]


def test_a_vector_file_is_one_run_per_line(tmp_path):
    """Daikon's own tcas goal file is merged from 501 executions, so a
    single-vector interface could not reproduce it - and a fuzzer needs many
    runs by definition."""
    f = tmp_path / "v.txt"
    f.write_text("1 2 3\n4 5 6\n")
    assert _tracer(argv_file=str(f))._input_vectors() == [
        ["1", "2", "3"], ["4", "5", "6"]]


def test_blank_and_comment_lines_are_skipped(tmp_path):
    f = tmp_path / "v.txt"
    f.write_text("# a note\n\n1 2\n\n# another\n3 4\n")
    assert _tracer(argv_file=str(f))._input_vectors() == [["1", "2"], ["3", "4"]]


def test_an_empty_vector_file_falls_back(tmp_path):
    """Rather than running zero times and producing an empty trace."""
    f = tmp_path / "v.txt"
    f.write_text("# nothing but comments\n")
    assert _tracer(argv_file=str(f))._input_vectors() == [[]]


def test_a_vector_file_beats_a_single_vector(tmp_path):
    f = tmp_path / "v.txt"
    f.write_text("7 8\n")
    t = _tracer(argv="1 2", argv_file=str(f))
    assert t._input_vectors() == [["7", "8"]]


# ---- the modelled library calls --------------------------------------------

def test_exit_is_modelled():
    """An unmodelled call returns 0 and execution CONTINUES, so an input that
    lands on an error path would run through code the real program never
    reaches and every later sample would be fiction. Confirmed against Kvasir:
    on tcas neither side records main:::EXIT, because main calls exit().
    """
    assert "exit" in LIBC_STUBS


def test_atoi_is_modelled():
    """tcas does `atoi(argv[1])` twelve times; skipping it returns garbage."""
    assert "atoi" in LIBC_STUBS


def test_argv_lives_off_the_stack():
    """--layouts shifts the stack base per run and must not land on the
    argument strings."""
    assert ARGV_BASE >= 0x10000000
