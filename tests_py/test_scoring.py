"""The scorer is the project's measurement instrument, so it needs its own tests.

Three bugs were found in it during the 2026-09-17 evaluation, and each one
made the tracer look worse than it is:

  * no orig() substitution      test03 scored 1/2 when it agrees 2/2
  * no equality symmetry        `p == return` vs `return == p` counted as a miss
  * no comparison direction     `return >= b` vs `b <= return` counted as a miss

Together they understated F1 by 16 points (51% -> 67%). A measurement
instrument with no tests will quietly mis-report the thing it exists to
measure.

A fourth was found after phase 8 — a subscript variable left un-renamed, so
`arr[arg1-1]` and `arr[n-1]` scored as a miss AND a false positive at once.
Same shape as the other three: it made the tracer look worse, and it was found
by disbelieving a number rather than by reading code.
"""
import sys

from score_invariants import (apply_renames, canonical, drop_orig,
                              fold_signs, invariant_holds, norm_ppt,
                              parse_report, rename_map, unchanged_vars)


# ---- number formats --------------------------------------------------------

def test_scientific_notation_matches_its_decimal_spelling():
    """Daikon prints the same constant two ways depending on declared type.

    Kvasir's report says `-2.14748e+09`, ours says `2.147483648E9`, and they
    are one fact about `big_unsigned`. Before this, the `e` was parsed as a
    variable name, the invariant fell through uncanonicalized, and the one
    signedness fact phase 8 recovered scored as a miss AND a false positive.
    """
    assert canonical("1*return + -1*x + -2.14748e+09 == 0") ==         canonical("x - return + 2.147483648E9 == 0")


def test_doubled_signs_are_folded():
    """Daikon writes a negative coefficient as `+ -1*x`."""
    assert canonical("a + -1*b + -3 == 0") == canonical("a - b - 3 == 0")
    assert fold_signs("a--b") == "a+b"
    assert fold_signs("2.14748e+09") == "2.14748e+09"   # exponent sign survives


def test_a_doubled_sign_does_not_validate_a_false_oracle_fact():
    """The subtlest of the scorer bugs, because it produced a plausible answer.

    Kvasir reports `return - orig(x) - -2147483648 == 0` for `big_unsigned`.
    Read with the doubled sign collapsed the wrong way it becomes our own
    (correct) invariant and validates; read properly it is false on Kvasir's
    own samples. The wrong reading cost the tracer a point of recall for being
    right.
    """
    rows = [{"return": 2147483649, "orig(x)": 1},
            {"return": 2147483650, "orig(x)": 2}]
    assert invariant_holds("return - orig(x) - -2147483648 == 0", rows) is False
    assert invariant_holds("return - orig(x) - 2147483648 == 0", rows) is True


# ---- renaming --------------------------------------------------------------

def test_subscript_variables_are_renamed():
    """Daikon derives indexed elements, and the index is itself a variable.

    We emit `arr[arg1-1]` where Kvasir emits `arr[n-1]`; without renaming
    inside the bracket the two never match. Worth 4 facts on test13 alone.
    """
    m = {"arg0": "arr", "arg1": "n"}
    assert apply_renames("arr[arg1-1] one of { 5, 30 }", m) ==         "arr[n-1] one of { 5, 30 }"
    assert apply_renames("size(arg0[]) == arg0[arg1-1]", m) ==         "size(arr[]) == arr[n-1]"


def test_longer_keys_win_over_their_prefixes():
    """`arg0[].off4` must not be renamed by the `arg0` rule first."""
    m = rename_map("f", {"f": ["p"]}, {"f": {4: "b"}})
    assert apply_renames("arg0[].off4 == 3", m) == "p[].b == 3"
    assert apply_renames("arg0[] == [ 1 ]", m) == "p[] == [ 1 ]"
    assert apply_renames("arg0 != null", m) == "p != null"


def test_a_longer_name_is_not_a_prefix_match():
    """arg1 must not match inside arg10."""
    assert apply_renames("arg10 == 1", {"arg1": "n"}) == "arg10 == 1"


# ---- linear canonicalization ----------------------------------------------

def test_flipped_linear_equalities_are_one_fact():
    """Daikon's choice of anchor variable is arbitrary."""
    assert canonical("a - c + 1 == 0") == canonical("c - a - 1 == 0")


def test_coefficients_survive_normalization():
    assert canonical("2 * a - return + 1 == 0") == canonical("return - 2 * a - 1 == 0")


def test_genuinely_different_relations_stay_different():
    """The guard against a canonicalizer that flattens everything to equal."""
    assert canonical("a - c + 1 == 0") != canonical("a - c + 2 == 0")
    assert canonical("2 * a - return + 1 == 0") != canonical("a - return + 1 == 0")


def test_non_linear_forms_pass_through_untouched():
    for inv in ("p[].a elements < return", "size(p[]) == 1",
                "p has only one value", "return % orig(b) == 0"):
        assert canonical(inv) == canonical(inv)
    assert "elements" in canonical("p[].a elements < return")


# ---- equality symmetry -----------------------------------------------------

def test_equality_is_symmetric():
    assert canonical("p == return") == canonical("return == p")


def test_equality_with_a_constant_is_symmetric():
    assert canonical("b == 5") == canonical("5 == b")


def test_symmetry_does_not_merge_different_pairs():
    assert canonical("p == return") != canonical("p == other")


# ---- comparison direction --------------------------------------------------

def test_comparison_direction_is_normalized():
    """`return >= orig(b)` and `b <= return` are one fact once b is known
    unmodified; the direction alone must not make them differ."""
    assert canonical("return >= b") == canonical("b <= return")
    assert canonical("return > a") == canonical("a < return")


def test_strict_and_non_strict_stay_distinct():
    assert canonical("a < b") != canonical("a <= b")


def test_elementwise_suffix_is_preserved():
    out = canonical("p[].b >= p[].a (elementwise)")
    assert "(elementwise)" in out


def test_comparison_operands_are_not_sorted():
    """Unlike equality, a comparison is directional - sorting would invert it."""
    assert canonical("a <= b") != canonical("b <= a")


# ---- orig() substitution ---------------------------------------------------

def test_unchanged_variable_is_detected():
    assert unchanged_vars(["num == orig(num)"]) == {"num"}


def test_similar_but_different_pair_is_not_detected():
    assert unchanged_vars(["a == orig(b)"]) == set()


def test_orig_is_rewritten_for_unmodified_variables():
    """The test03 case: one fact spelled over `num` on one side and
    `orig(num)` on the other."""
    u = unchanged_vars(["num == orig(num)"])
    assert drop_orig("orig(num) - return + 1 == 0", u) == "num - return + 1 == 0"


def test_tautology_is_dropped_not_counted():
    """`num == orig(num)` carries no information once substituted, and counting
    it as a false positive would penalise the tracer for reporting a truth the
    oracle suppresses."""
    u = unchanged_vars(["num == orig(num)"])
    assert drop_orig("num == orig(num)", u) is None


def test_orig_survives_for_variables_that_do_change():
    u = unchanged_vars(["x == orig(x)"])
    assert drop_orig("orig(y) - return == 0", u) == "orig(y) - return == 0"


# ---- report parsing --------------------------------------------------------

def test_parses_ppts_and_invariants(tmp_path):
    p = tmp_path / "r.txt"
    p.write_text("Daikon version 5.8\n"
                 "===========\n"
                 "..f():::ENTER\n"
                 "a == 1\n"
                 "..f():::EXIT\n"
                 "return == 0\n"
                 "Exiting Daikon.\n")
    got = parse_report(str(p))
    assert got["..f():::ENTER"] == ["a == 1"]
    assert got["..f():::EXIT"] == ["return == 0"]


def test_carriage_return_padding_is_stripped(tmp_path):
    """Daikon's progress output overwrites with CRs and can leave whitespace
    on an invariant line. A naive filter drops the invariant; my own count was
    wrong for two phases because of exactly this."""
    p = tmp_path / "r.txt"
    p.write_text("..f():::EXIT\n\r     return == 0\n")
    assert parse_report(str(p))["..f():::EXIT"] == ["return == 0"]


def test_exit0_and_exit_align():
    """Kvasir declares EXIT0; Daikon prints the combined point as EXIT."""
    assert norm_ppt("..f():::EXIT0") == norm_ppt("..f():::EXIT")


def test_file_scoped_function_names_align():
    """Kvasir qualifies a `static` function with its source path.

    Found on Daikon's own Kvasir suite: `createCopy` is static, so the oracle
    calls it `/abs/path/TypedefTest.c.createCopy()` while we call it
    `..createCopy()`. Unstripped, the name never reaches the DWARF rename map
    and every fact at that point counts twice against us.
    """
    assert norm_ppt("/a/b/TypedefTest.c.createCopy():::ENTER") ==         norm_ppt("..createCopy():::ENTER")
    assert norm_ppt("/a/b/x.cpp.f():::EXIT0") == norm_ppt("..f():::EXIT")


def test_a_plain_name_is_left_alone():
    assert norm_ppt("..main():::ENTER") == "..main():::ENTER"
