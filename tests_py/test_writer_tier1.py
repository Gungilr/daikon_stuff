"""Tier 1 output format.

Every assertion here was derived from Kvasir's actual output
(traces/test08.kvasir.{decls,dtrace}) and Daikon's parser, not from the format
documentation. Two of them encode mistakes the plan originally specified.
"""
from tracer.writer import DaikonTraceWriter, VarSpec, legacy_specs

VARS = ["rax", "rdi"]


def _tier1(tmp_path, samples):
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    for ppt, values, nonce in samples:
        ppt_type = "enter" if "ENTER" in ppt else "subexit"
        w.declare(ppt, ppt_type, legacy_specs(VARS))
        w.add_sample(ppt, values, nonce=nonce)
    w.close()
    return path.read_text()


# ---- nonce placement -------------------------------------------------------

def test_nonce_is_first_line_after_ppt_name(tmp_path):
    """Daikon peeks EXACTLY one line past the ppt name to detect the nonce.

    Anywhere else and it is parsed as a variable name.
    """
    text = _tier1(tmp_path, [("..f():::ENTER", [10, 20], 7)])
    body = text.split("..f():::ENTER\n")[-1].splitlines()
    assert body[0] == "this_invocation_nonce"
    assert body[1] == "7"


def test_nonce_has_no_modbit(tmp_path):
    """Two lines, not three.

    A modbit here shifts every following name/value/modbit triple by one and
    silently desyncs the whole sample block.
    """
    text = _tier1(tmp_path, [("..f():::ENTER", [10, 20], 7)])
    body = text.split("..f():::ENTER\n")[-1].splitlines()
    assert body[2] == "rax", f"expected variable name after nonce, got {body[2]!r}"
    assert body[3] == "10"
    assert body[4] == "1"


def test_nonce_is_never_declared(tmp_path):
    """Kvasir emits the nonce in every sample and declares it zero times."""
    text = _tier1(tmp_path, [("..f():::ENTER", [10, 20], 7)])
    declarations = text.split("..f():::ENTER\n")[0]
    assert "this_invocation_nonce" not in declarations


def test_nonce_none_omits_the_prefix(tmp_path):
    """The tier-0 path must be unaffected."""
    text = _tier1(tmp_path, [("..f():::ENTER", [10, 20], None)])
    assert "this_invocation_nonce" not in text


def test_nonce_zero_is_emitted_not_skipped(tmp_path):
    """0 is a valid nonce - Kvasir's first sample uses it.

    A truthiness check instead of `is not None` would drop it.
    """
    text = _tier1(tmp_path, [("..f():::ENTER", [10, 20], 0)])
    assert "this_invocation_nonce\n0\n" in text


# ---- orig() ----------------------------------------------------------------

def test_no_orig_variables_emitted(tmp_path):
    """Daikon DERIVES orig() at exit points from the paired entry sample.

    Emitting them creates a literal variable named `orig(rax)`, for which
    Daikon then derives `orig(orig(rax))`.
    """
    text = _tier1(
        tmp_path,
        [("..f():::ENTER", [1, 2], 0), ("..f():::EXIT0", [3, 4], 0)],
    )
    assert "orig(" not in text


# ---- ppt naming and type ---------------------------------------------------

def test_exit_declared_subexit(tmp_path):
    text = _tier1(tmp_path, [("..f():::EXIT0", [1, 2], 0)])
    assert "ppt ..f():::EXIT0\nppt-type subexit\n" in text


def test_enter_still_declared_enter(tmp_path):
    text = _tier1(tmp_path, [("..f():::ENTER", [1, 2], 0)])
    assert "ppt ..f():::ENTER\nppt-type enter\n" in text


# ---- nonce allocation ------------------------------------------------------

def test_next_nonce_is_monotonic_and_unique(tmp_path):
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    issued = [w.next_nonce() for _ in range(100)]
    assert issued == sorted(issued)
    assert len(set(issued)) == 100


def test_nonce_counter_starts_at_zero(tmp_path):
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    assert w.next_nonce() == 0


# ---- per-ppt schemas -------------------------------------------------------

def test_two_ppts_may_carry_different_schemas(tmp_path):
    """The phase 2 prerequisite: arity differs per function."""
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    w.declare("..a():::ENTER", "enter", legacy_specs(["rdi"]))
    w.declare("..b():::ENTER", "enter", legacy_specs(["rdi", "rsi", "rdx"]))
    w.add_sample("..a():::ENTER", [1])
    w.add_sample("..b():::ENTER", [1, 2, 3])
    w.close()
    text = path.read_text()
    a_block = text.split("ppt ..a():::ENTER\n")[1].split("\n\n")[0]
    b_block = text.split("ppt ..b():::ENTER\n")[1].split("\n\n")[0]
    assert a_block.count("variable ") == 1
    assert b_block.count("variable ") == 3


def test_length_guard_is_per_ppt(tmp_path):
    """With one global schema a mismatch was impossible; now it is the main
    hazard, so the guard must use the right ppt's schema."""
    w = DaikonTraceWriter(str(tmp_path / "t.dtrace"))
    w.declare("..a():::ENTER", "enter", legacy_specs(["rdi"]))
    w.declare("..b():::ENTER", "enter", legacy_specs(["rdi", "rsi"]))
    w.add_sample("..a():::ENTER", [1])          # fine
    try:
        w.add_sample("..b():::ENTER", [1])      # short for b
    except ValueError:
        pass
    else:
        raise AssertionError("per-ppt length guard did not fire")


# ---- optional VarSpec fields (tiers 3 and 6) -------------------------------

def test_optional_fields_omitted_when_none(tmp_path):
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    w.declare("..f():::ENTER", "enter", [VarSpec("rdi")])
    w.add_sample("..f():::ENTER", [1])
    w.close()
    text = path.read_text()
    for absent in ("enclosing-var", "array ", "flags "):
        assert absent not in text


def test_optional_fields_emitted_when_set(tmp_path):
    path = tmp_path / "t.dtrace"
    w = DaikonTraceWriter(str(path))
    # The intermediate `p[..]` is declared because the schema has to be
    # well-formed: Daikon rejects a whole trace whose enclosing-var names
    # something absent, and `validate()` now enforces that before writing.
    w.declare("..f():::ENTER", "enter", [
        VarSpec("p", dec_type="pair_t*", rep_type="hashcode",
                comparability="1", flags="is_param"),
        VarSpec("p[..]", dec_type="pair_t[]", rep_type="hashcode[]",
                comparability="1", var_kind="array",
                enclosing_var="p", array=1),
        VarSpec("p[..].a", dec_type="int[]", rep_type="int[]",
                comparability="3", var_kind="field a",
                enclosing_var="p[..]", array=1),
    ])
    w.add_sample("..f():::ENTER", [0x1000, [0x1000], 5])
    w.close()
    text = path.read_text()
    assert "  rep-type hashcode\n" in text
    assert "  flags is_param\n" in text
    assert "  enclosing-var p[..]\n" in text
    assert "  array 1\n" in text
    assert "  var-kind field a\n" in text


def test_custom_var_comparability_header(tmp_path):
    """Tier 3 switches this to `implicit`."""
    path = tmp_path / "t.dtrace"
    DaikonTraceWriter(str(path), var_comparability="implicit").close()
    assert "var-comparability implicit\n" in path.read_text()
