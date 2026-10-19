"""Unit tests for the pure half of the fuzzing loop: trace handling, invariant
evaluation and mutation. No compiler, Valgrind or JVM needed.
"""
import random
import struct

import pytest

from fuzzloop import dtrace, invariants, mutate
from fuzzloop.invariants import compile_invariant


# --- dtrace -----------------------------------------------------------------

DECLS = """input-language C/C++
decl-version 2.0
var-comparability implicit

ppt ..f():::ENTER
  ppt-type enter
  variable a
    var-kind variable
    rep-type int
    dec-type int
    flags is_param
    comparability 1

ppt ..fuzz_input_begin():::ENTER
  ppt-type enter
  variable fuzz_id
    var-kind variable
    rep-type int
    dec-type int
    flags is_param non_null
    comparability 1
"""

DTRACE = """input-language C/C++
decl-version 2.0
var-comparability implicit


..main():::ENTER
this_invocation_nonce
0
argc
2
1

..fuzz_input_begin():::ENTER
this_invocation_nonce
1
fuzz_id
0
1

..f():::ENTER
this_invocation_nonce
2
a
5
1

..f():::EXIT0
this_invocation_nonce
2
a
6
1
return
11
1

..fuzz_input_begin():::ENTER
this_invocation_nonce
3
fuzz_id
1
1

..f():::ENTER
this_invocation_nonce
4
a
-3
1

..f():::EXIT0
this_invocation_nonce
4
a
-3
1
return
-5
1
"""


def test_split_by_input_attributes_samples_to_the_preceding_marker():
    per = dtrace.split_by_input(dtrace.parse_dtrace(DTRACE))
    assert sorted(per) == [0, 1]
    assert [s.ppt for s in per[0]] == ["..f():::ENTER", "..f():::EXIT0"]
    assert per[1][1].get("return") == "-5"


def test_samples_before_the_first_marker_belong_to_no_input():
    per = dtrace.split_by_input(dtrace.parse_dtrace(DTRACE))
    assert all(s.ppt != "..main():::ENTER" for ss in per.values() for s in ss)


def test_render_renumbers_nonces_so_runs_can_be_concatenated():
    per = dtrace.split_by_input(dtrace.parse_dtrace(DTRACE))
    text0, nxt = dtrace.render_samples(per[0], 100)
    text1, nxt = dtrace.render_samples(per[1], nxt)
    again = dtrace.parse_dtrace(text0 + text1)
    assert [s.nonce for s in again] == [100, 100, 101, 101]
    assert nxt == 102


def test_rows_fill_orig_from_the_matching_enter():
    per = dtrace.split_by_input(dtrace.parse_dtrace(DTRACE))
    rows = dtrace.rows(per[0])
    assert rows[1] == ("..f():::EXIT0", {"a": 6, "return": 11, "orig(a)": 5})


def test_keep_ppt_drops_the_harness():
    for ppt in ("..main():::ENTER", "..fuzz_target():::EXIT0",
                "..fuzz_input_begin():::ENTER",
                "/x/fuzz/targets/a.c.fuzz_take_i32():::ENTER",
                "fuzz/runtime/harness.c.read_file():::EXIT0"):
        assert not dtrace.keep_ppt(ppt), ppt
    assert dtrace.keep_ppt("..abs_diff():::EXIT0")
    assert dtrace.keep_ppt("a.c.static_helper():::ENTER")


def test_is_param_is_stripped_but_other_flags_survive():
    header, blocks = dtrace.parse_decls(DECLS)
    out = dtrace.render_decls(header, blocks)
    assert "is_param" not in out
    assert "flags non_null" in out
    kept = dtrace.render_decls(header, blocks, is_param=True)
    assert kept.count("is_param") == 2


def test_parse_value():
    pv = dtrace.parse_value
    assert pv("42") == 42 and pv("-7") == -7
    assert pv("0x1ffeffe460") == 0x1ffeffe460
    assert pv("1.5") == 1.5
    assert pv('"a b"') == "a b"
    assert pv("[ 1 2 nonsensical ]") == [1, 2, None]
    assert pv('[ "x y" "z" ]') == ["x y", "z"]
    assert pv("nonsensical") is None
    assert pv("null") == 0


# --- invariants -------------------------------------------------------------

REPORT = """Daikon version 5.9.0, released September 1, 2026
Reading declaration files .
===========================================================================
..abs_diff():::EXIT
a == orig(a)
return >= 0
===========================================================================
..abs_diff():::EXIT;condition="a > b"
return == a - b
Exiting Daikon.
"""


def test_parse_report_and_conditional_points_are_skipped():
    rep = invariants.parse_report(REPORT)
    assert rep["..abs_diff():::EXIT"] == ["a == orig(a)", "return >= 0"]
    compiled, unsupported = invariants.compile_report(rep)
    assert list(compiled) == ["..abs_diff():::EXIT"]
    assert unsupported == []


def test_numbered_exits_also_match_the_combined_exit():
    assert invariants.report_ppts_for("..f():::EXIT0") == ["..f():::EXIT0", "..f():::EXIT"]
    assert invariants.report_ppts_for("..f():::ENTER") == ["..f():::ENTER"]


def check(text, **row):
    inv = compile_invariant("p", text)
    assert inv is not None, "unsupported: " + text
    return inv.check({k.replace("__", "."): v for k, v in row.items()})


@pytest.mark.parametrize("text,row,expect", [
    # distance = how far from VIOLATION; 0 iff violated
    ("return >= 0", {"return": 40}, (True, 41)),
    ("return >= 0", {"return": 0}, (True, 1)),
    ("return >= 0", {"return": -1}, (False, 0)),
    ("x > 5", {"x": 9}, (True, 4)),
    ("x < 5", {"x": 2}, (True, 3)),
    ("x <= 5", {"x": 5}, (True, 1)),
    ("x != 3", {"x": 7}, (True, 4)),
    ("x == 3", {"x": 3}, (True, 1)),
    ("x == 3", {"x": 4}, (False, 0)),
])
def test_comparison_distances(text, row, expect):
    assert check(text, **row) == expect


def test_linear_forms_and_orig():
    assert check("2 * a - return + 1 == 0", a=3, **{"return": 7}) == (True, 1)
    assert check("return - orig(a) - 1 == 0", **{"return": 6, "orig(a)": 5})[0]
    assert check("return == orig(key)", **{"return": 9, "orig(key)": 8}) == (False, 0)


def test_one_of_and_mod():
    assert check("return one of { -1, 1 }", **{"return": 1}) == (True, 1)
    assert check("return one of { -1, 1 }", **{"return": 0}) == (False, 0)
    assert check("x == 1  (mod 2)", x=7) == (True, 1)
    assert check("x == 1  (mod 2)", x=-3) == (True, 1)      # Daikon's mod is non-negative
    assert check("x != 0  (mod 4)", x=8) == (False, 0)


def test_sequences():
    row = {"buf[..]": [5, 6, 0, 0], "n": 2, "return": 1}
    inv = compile_invariant
    assert inv("p", "buf[] elements >= 0").check(row) == (True, 1)
    assert inv("p", "buf[] elements <= 5").check(row) == (False, 0)
    assert inv("p", "size(buf[]) == 4").check(row)[0]
    assert inv("p", "n < size(buf[])-1").check(row)[0]
    assert inv("p", "buf[n] == 0").check(row)[0]
    assert inv("p", "buf[n-1] != 0").check(row) == (True, 6)
    assert inv("p", "buf[return] > 5").check(row)[0]
    assert inv("p", "buf[] == orig(buf[])").check(dict(row, **{"orig(buf[..])": [5, 6, 0, 0]}))[0]


def test_implication_distance_needs_antecedent_true_and_consequent_false():
    t = "(return == 0)  ==>  (x == 0)"
    # consequent already false: only the antecedent's distance (3) remains
    assert check(t, x=5, **{"return": 3}) == (True, 3)
    # both halves need moving: 3 to make return 0, 1 to break x == 0
    assert check(t, x=0, **{"return": 3}) == (True, 4)
    assert check(t, x=0, **{"return": 0}) == (True, 1)
    assert check(t, x=5, **{"return": 0}) == (False, 0)


def test_missing_and_nonsensical_values_are_not_evaluated():
    assert check("x >= 0") is None
    assert check("x >= 0", x=None) is None
    assert check("buf[n] == 0", **{"buf[..]": [1], "n": 5}) is None


@pytest.mark.parametrize("text", [
    "buf has only one value", "buf[] sorted by <", "x is a pointer",
    "return == 0 ==> x == 1 ==> y", "a[] is reverse of b[]",
])
def test_unsupported_forms_compile_to_none(text):
    assert compile_invariant("p", text) is None


# --- mutation ---------------------------------------------------------------

def test_mutation_is_deterministic_for_a_seed():
    a = mutate.Mutator(random.Random(7))
    b = mutate.Mutator(random.Random(7))
    seed = struct.pack("<iii", 1, 2, 3)
    assert [a.mutate(seed) for _ in range(50)] == [b.mutate(seed) for _ in range(50)]


def test_mutation_respects_max_len_and_reaches_the_empty_input():
    m = mutate.Mutator(random.Random(1), max_len=8)
    outs = [m.mutate(b"abcdefgh") for _ in range(2000)]
    assert max(len(o) for o in outs) <= 8
    assert b"" in outs


def test_dictionary_constants_are_used():
    m = mutate.Mutator(random.Random(3))
    m.add_constants([0x5eed1337])
    magic = struct.pack("<I", 0x5eed1337)
    assert any(magic in m.mutate(b"\0" * 12) for _ in range(2000))


def test_pack_batch_matches_the_harness_format():
    assert mutate.pack_batch([b"ab", b""]) == b"\x02\0\0\0ab\0\0\0\0"


def test_seed_file_formats():
    seeds = mutate.parse_seed_file(
        "# comment\ni32: 1 -1\nstr: a # b\n0a0b  # hex\n")
    assert seeds == [struct.pack("<ii", 1, -1), b"a # b", b"\x0a\x0b"]
