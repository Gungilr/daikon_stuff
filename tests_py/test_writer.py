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


# ---- gzip output (phase 11) ------------------------------------------------

def test_a_gz_path_is_compressed_and_still_readable(tmp_path):
    """Daikon decides to decompress purely from the `.gz` suffix
    (FileIO.java:1418), so the writer uses the same rule and no flag is needed
    on either side."""
    import gzip
    path = tmp_path / "t.dtrace.gz"
    w = DaikonTraceWriter(str(path))
    w.declare("..f():::ENTER", "enter", legacy_specs(["a", "b"]))
    w.add_sample("..f():::ENTER", [1, 2])
    w.close()
    assert path.read_bytes()[:2] == bytes((0x1F, 0x8B))   # gzip magic
    text = gzip.open(path, "rt").read()
    assert "decl-version 2.0" in text and "variable a" in text


def test_a_plain_path_is_not_compressed(tmp_path):
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    w.declare("..f():::ENTER", "enter", legacy_specs(["a"]))
    w.add_sample("..f():::ENTER", [1])
    w.close()
    assert path.read_text().startswith("decl-version 2.0")


def test_compression_does_not_change_the_content(tmp_path):
    """The gzip path must be the same bytes, only deflated."""
    import gzip
    specs = legacy_specs(["a", "b"])
    plain, gz = tmp_path / "p.dtrace", tmp_path / "g.dtrace.gz"
    for path in (plain, gz):
        w = DaikonTraceWriter(str(path))
        w.declare("..f():::ENTER", "enter", specs)
        w.add_sample("..f():::ENTER", [7, 8])
        w.close()
    assert plain.read_text() == gzip.open(gz, "rt").read()


# ---- the value cap (phase 11) ----------------------------------------------

def test_a_value_too_wide_for_the_declared_type_is_nonsensical(tmp_path):
    """Daikon's `int` rep-type is a signed 64-bit long.

    `space` had a 2000-byte global with no recovered shape; read whole it became
    an integer of ~5000 digits and the run died in the writer AFTER a complete
    and correct emulation. Out of range is `nonsensical` - that is what the
    marker is for - rather than a number the consumer has to wrap.
    """
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    w.declare("..f():::ENTER", "enter", legacy_specs(["huge", "ok"]))
    w.add_sample("..f():::ENTER", [1 << 900, 42])
    w.close()
    text = path.read_text()
    assert "nonsensical" in text
    assert "42" in text
    assert "1" * 20 not in text        # no giant literal anywhere


def test_int64_boundaries_are_kept():
    from tracer.writer import format_value
    assert format_value((1 << 63) - 1) == str((1 << 63) - 1)
    assert format_value(-(1 << 63)) == str(-(1 << 63))
    assert format_value(1 << 63) == "nonsensical"
    assert format_value(-(1 << 63) - 1) == "nonsensical"


def test_an_oversized_element_inside_a_sequence_is_also_caught():
    from tracer.writer import format_value
    assert format_value([1, 1 << 900, 3]) == "[ 1 nonsensical 3 ]"
