"""The comparability classifier behind docs/RELATED-WORK.md section 1a.

It decides which of our unmatched facts Kvasir could never have printed. The
rules that matter are the ones that make a fact NOT cross-class, because a
classifier that over-reports cross-class facts would overstate what an
emulator-side DynComp could buy. The first version of this measurement did
exactly that: it treated Kvasir's array comparabilities as ordinary classes,
and labelled 41 facts Kvasir had actually printed as impossible.
"""
from measure_comparability import classify, parse_decls, variables


# ---- unary facts: comparability never applies ------------------------------

def test_single_variable_is_unary():
    assert classify("::globalInt > 0", {"::globalInt": "4"}) == "unary"


def test_daikon_keywords_are_not_variables():
    assert classify("::x one of { 1, 2, 3 }", {"::x": "1"}) == "unary"
    assert classify("::p has only one value", {"::p": "1"}) == "unary"


def test_string_literals_are_not_variables():
    assert classify('::s == "hello world"', {"::s": "1"}) == "unary"


def test_orig_of_the_same_variable_is_one_variable():
    assert classify("::x == orig(::x)", {"::x": "1"}) == "unary"


def test_numbers_in_scientific_notation_are_not_names():
    assert variables("::x == 2.147483648E9") == {"::x": False}


# ---- the rules that keep a fact OUT of cross-class --------------------------

def test_scalars_in_one_class_are_same():
    assert classify("::a < ::b", {"::a": "3", "::b": "3"}) == "same"


def test_negative_comparability_is_comparable_to_everything():
    assert classify("::a == ::b", {"::a": "-1", "::b": "2"}) == "same"


def test_array_against_scalar_is_never_cross():
    """Kvasir writes `comparability 24` for an array, with no index part.

    Daikon parses that as a dimensionless comparability, and elementType() of a
    dimensionless comparability is `unknown`, comparable to everything. So
    Kvasir prints `::globalInt in ::multiDimensional[]` although the two have
    different numbers. Counting it as cross-class was the original bug.
    """
    comps = {"::globalInt": "10", "::multiDimensional[]": "24"}
    assert classify("::globalInt in ::multiDimensional[]", comps) == "sequence"
    assert classify("::multiDimensional[] elements == ::globalInt", comps) == "sequence"


def test_size_terms_are_never_cross():
    comps = {"::population[]": "2", "b[]": "67"}
    assert classify("size(::population[]) == size(b[])-1", comps) == "sequence"


def test_unknown_scalar_is_unresolved_not_cross():
    assert classify("g_0x404040.off8 == ::n", {"::n": "5"}) == "unresolved"


# ---- the one rule that makes a fact cross-class -----------------------------

def test_scalars_in_different_classes_are_cross():
    comps = {"::leaf_global1": "3", "::leaf_global3": "7"}
    assert classify("::leaf_global1 == ::leaf_global3", comps) == "cross"


def test_cross_wins_over_an_unresolved_third_name():
    comps = {"::a": "1", "::b": "2"}
    assert classify("::a + ::b - g_0x1 == 0", comps) == "cross"


def test_field_paths_and_arrows_are_single_names():
    assert set(variables("p[].a < ::q->next")) == {"p[].a", "::q->next"}


# ---- declarations ------------------------------------------------------------

def test_parse_decls_normalises_names_like_the_scorer(tmp_path):
    decls = tmp_path / "x.kvasir.decls"
    decls.write_text(
        "decl-version 2.0\n"
        "var-comparability implicit\n"
        "\n"
        "ppt ..f():::EXIT0\n"
        "  ppt-type subexit\n"
        "  variable ::population[..].age\n"
        "    var-kind field age\n"
        "    comparability 3\n"
        "  variable return\n"
        "    var-kind return\n"
        "    comparability 5\n")
    out = parse_decls(str(decls))
    assert out == {"..f():::EXIT": {"::population[].age": "3", "return": "5"}}
