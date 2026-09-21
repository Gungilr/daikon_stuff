"""Behavior lock on DaikonTraceWriter's TIER 0 output.

Tier 0 is the frozen baseline the whole research effort measures against, so
these assertions must keep holding forever - every tier is opt-in via --tier.
The API moved to per-ppt schemas in phase 1; the expected bytes did not.
"""
import pytest

from tracer.writer import DaikonTraceWriter, VarSpec, legacy_specs

VARS = ["rax", "rdi", "rsi"]


def _write(tmp_path, samples, var_names=VARS):
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    for ppt, values in samples:
        ppt_type = "enter" if "ENTER" in ppt else "exit"
        w.declare(ppt, ppt_type, legacy_specs(var_names))
        w.add_sample(ppt, values)
    w.close()
    return path.read_text()


def test_header(tmp_path):
    text = _write(tmp_path, [("..f():::ENTER", [1, 2, 3])])
    assert text.startswith("decl-version 2.0\nvar-comparability none\n\n")


def test_declarations_precede_data(tmp_path):
    text = _write(tmp_path, [("..f():::ENTER", [1, 2, 3])])
    assert text.index("ppt ..f():::ENTER") < text.index("\n..f():::ENTER\n")


def test_ppt_type_enter_vs_exit(tmp_path):
    text = _write(
        tmp_path,
        [("..f():::ENTER", [1, 2, 3]), ("..f():::EXIT1", [4, 5, 6])],
    )
    assert "ppt-type enter" in text
    assert "ppt-type exit" in text


def test_variable_declaration_field_order(tmp_path):
    """Field order is part of the tier-0 byte contract.

    Daikon does not care, but the golden file does: dec-type precedes rep-type
    here, whereas Kvasir emits the reverse. Changing it silently breaks the
    byte-identity gate rather than anything functional.
    """
    text = _write(tmp_path, [("..f():::ENTER", [1, 2, 3])])
    assert (
        "variable rax\n"
        "  var-kind variable\n"
        "  dec-type int\n"
        "  rep-type int\n"
        "  comparability 22\n"
    ) in text


def test_sample_values_and_modbits(tmp_path):
    text = _write(tmp_path, [("..f():::ENTER", [10, 20, 30])])
    assert "rax\n10\n1\n" in text
    assert "rdi\n20\n1\n" in text


def test_tier0_emits_no_nonce(tmp_path):
    text = _write(tmp_path, [("..f():::ENTER", [1, 2, 3])])
    assert "this_invocation_nonce" not in text


def test_tier0_emits_no_orig(tmp_path):
    text = _write(tmp_path, [("..f():::EXIT1", [1, 2, 3])])
    assert "orig(" not in text


def test_repeated_ppt_declared_once(tmp_path):
    text = _write(
        tmp_path,
        [("..f():::ENTER", [1, 2, 3]), ("..f():::ENTER", [4, 5, 6])],
    )
    assert text.count("ppt ..f():::ENTER\n") == 1


def test_declaration_order_is_first_seen(tmp_path):
    """The golden depends on declaration order matching first-sample order."""
    text = _write(
        tmp_path,
        [("..b():::ENTER", [1, 2, 3]), ("..a():::ENTER", [4, 5, 6])],
    )
    assert text.index("ppt ..b():::ENTER") < text.index("ppt ..a():::ENTER")


def test_too_few_values_raises(tmp_path):
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    w.declare("..f():::ENTER", "enter", legacy_specs(VARS))
    try:
        w.add_sample("..f():::ENTER", [1, 2])
    except ValueError as e:
        assert "2 values" in str(e) and "3 declared" in str(e)
    else:
        raise AssertionError("short value list was accepted")


def test_too_many_values_raises(tmp_path):
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    w.declare("..f():::ENTER", "enter", legacy_specs(VARS))
    try:
        w.add_sample("..f():::ENTER", [1, 2, 3, 4])
    except ValueError:
        pass
    else:
        raise AssertionError("long value list was accepted")


def test_sample_before_declare_raises(tmp_path):
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    try:
        w.add_sample("..f():::ENTER", [1, 2, 3])
    except ValueError as e:
        assert "before declare" in str(e)
    else:
        raise AssertionError("undeclared ppt was accepted")


def test_empty_trace_still_writes_header(tmp_path):
    path = tmp_path / "t.dtrace"
    DaikonTraceWriter(str(path)).close()
    assert path.read_text() == "decl-version 2.0\nvar-comparability none\n\n"


# ---- structural validation (phase 10) --------------------------------------

def test_enclosing_var_must_exist():
    """Daikon rejects the WHOLE trace, not just the variable.

    Phase 9 shipped `g[..]` with an undeclared `g` and nine binaries produced
    8-fact reports that looked like successful runs.
    """
    w = DaikonTraceWriter("/tmp/unused.dtrace")
    w.declare("..f():::ENTER", "enter", [
        VarSpec("g[..]", var_kind="array", enclosing_var="g", array=1)])
    with pytest.raises(ValueError, match="enclosing-var"):
        w.validate()


def test_a_forward_reference_is_legal():
    """Daikon resolves after reading the whole ppt, so ORDER does not matter.

    `return[..]` has been declared before `return` since phase 8 and Daikon
    has always accepted it. An order rule here rejected five binaries that
    Daikon is perfectly happy with - the validator was wrong, not the code.
    """
    w = DaikonTraceWriter("/tmp/unused.dtrace")
    w.declare("..f():::EXIT0", "subexit", [
        VarSpec("return[..]", var_kind="array", enclosing_var="return",
                array=1),
        VarSpec("return")])
    w.validate()


def test_field_var_kind_needs_a_relative_name():
    """`var-kind field` with no name: "end-of-line found where relative name
    expected". Took two binaries to zero in phase 10."""
    w = DaikonTraceWriter("/tmp/unused.dtrace")
    w.declare("..f():::ENTER", "enter", [
        VarSpec("g"), VarSpec("g.off0", var_kind="field", enclosing_var="g")])
    with pytest.raises(ValueError, match="relative name"):
        w.validate()


def test_a_well_formed_schema_validates():
    w = DaikonTraceWriter("/tmp/unused.dtrace")
    w.declare("..f():::ENTER", "enter", [
        VarSpec("g"),
        VarSpec("g.off0", var_kind="field off0", enclosing_var="g")])
    w.validate()


def test_duplicate_declarations_are_rejected():
    w = DaikonTraceWriter("/tmp/unused.dtrace")
    w.declare("..f():::ENTER", "enter", [VarSpec("a"), VarSpec("a")])
    with pytest.raises(ValueError, match="twice"):
        w.validate()
