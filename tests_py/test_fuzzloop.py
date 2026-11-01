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


def test_cov_crash_after_the_last_record_blames_that_record(tmp_path):
    """A memory bug can corrupt the heap and kill the process only after its
    record reported (Juliet's heap overflow did). That must not end the run."""
    import os
    import sys
    from fuzzloop import runner
    fake = tmp_path / "fake_cov"
    fake.write_text(
        "#!%s\nimport os, signal, sys\n"
        "open(sys.argv[2], 'w').write('S 0\\nF 0 1\\nS 1\\nF 1 2\\n')\n"
        "os.kill(os.getpid(), signal.SIGSEGV)\n" % sys.executable)
    os.chmod(str(fake), 0o755)
    results, crashes = runner.run_cov(str(fake), [b"a", b"b"], str(tmp_path))
    assert sorted(results) == [0]
    assert crashes == [(1, "SIGSEGV")]


def test_timeout_kills_the_wrapped_child_too(tmp_path):
    """kvasir-dtrace is sh around Valgrind: the child holds the pipes open,
    so killing only the shell let a 40 s timeout run for 300 s."""
    import subprocess
    import time
    from fuzzloop import runner
    t0 = time.time()
    with pytest.raises(subprocess.TimeoutExpired):
        runner._subprocess_run(["sh", "-c", "sleep 30; true"], timeout=1,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert time.time() - t0 < 10


def test_own_sources_include_files_the_target_includes(tmp_path):
    from fuzzloop import runner
    d = tmp_path / "juliet"
    (d / "cases").mkdir(parents=True)
    (d / "juliet.c").write_text("")
    (d / "cases" / "CWE194.c").write_text("")
    assert set(runner.own_sources(str(d / "juliet.c"))) == {"juliet.c", "CWE194.c"}
    top = tmp_path / "targets"
    top.mkdir()
    (top / "arith.c").write_text("")
    (top / "buffer.c").write_text("")
    assert runner.own_sources(str(top / "arith.c")) == ("arith.c",)


def test_var_list_adds_the_parents_kvasir_needs():
    """Kvasir's own dump omits `p[]` and `p[0]`; read back without them it
    declares fields with no enclosing variable and Daikon rejects the file."""
    from fuzzloop import runner
    got = runner._with_parents(["s", "s[].a", "t", "t[].c->d", "t[].c->e"])
    assert got == ["s", "s[]", "s[].a", "t", "t[]", "t[].c[0]", "t[].c->d", "t[].c->e"]


@pytest.mark.parametrize("fork", ["0", "1"])
def test_harness_survives_a_target_that_smashes_its_callers_locals(tmp_path, fork):
    """Juliet's stack overflows write past a stack array at an index the input
    picks. With the harness's loop counters on the stack, that reset `pos`
    and the batch replayed forever under Kvasir (80,201 inputs traced for a
    batch of 908). The harness must instead stop, blaming that record."""
    import os
    import shutil
    import subprocess
    from fuzzloop import mutate
    cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        pytest.skip("no C compiler")
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rt = os.path.join(repo, "fuzz", "runtime")
    tgt = tmp_path / "smash.c"
    tgt.write_text(r'''
#include <stdio.h>
#include "fuzz.h"
__attribute__((noinline)) void fuzz_target(const uint8_t *d, size_t n) {
    printf("call\n");
    fflush(stdout);
    if (n && d[0] == 'X') {
        /* Rewind the caller's loop counter to an earlier record, as a stray
         * int write did in Juliet. This record's length field is at byte
         * 5 and its data at byte 9; a counter holding either is sent back
         * to the same point of record 0 (byte 0, or byte 4 = one before
         * the old harness adds the length). */
        size_t *top = __builtin_frame_address(1);
        for (size_t *w = top - 16; w < top; w++) {
            if (*w == 5)
                *w = 0;
            else if (*w == 9)
                *w = 4;
        }
    }
}
''')
    exe = tmp_path / "smash"
    subprocess.run([cc, "-O0", "-fno-stack-protector", "-fno-omit-frame-pointer",
                    "-I", rt, str(tgt), os.path.join(rt, "harness.c"),
                    "-o", str(exe)], check=True)
    batch = tmp_path / "b"
    batch.write_bytes(mutate.pack_batch([b"a", b"X", b"c"]))
    try:
        p = subprocess.run([str(exe), str(batch)], capture_output=True,
                           timeout=10, env=dict(os.environ, FUZZ_FORK=fork))
    except subprocess.TimeoutExpired:
        pytest.fail("the harness replayed the batch")
    calls = p.stdout.decode().count("call")
    # Either the corruption is caught (nonzero exit, never past the bad
    # record) or it missed the loop state and all three ran once each.
    assert calls <= 3
    if calls < 3:
        assert p.returncode != 0


def test_attack_writes_a_constant_boundary_into_a_binary_field():
    from fuzzloop import attack
    data = struct.pack("<iii", 7, 958, 3)
    kids = attack.children(data, "alt <= 1000", {"alt": 958}, random.Random(0))
    vals = sorted(struct.unpack("<iii", k)[1] for k in kids)
    assert vals == [999, 1000, 1001]
    assert all(struct.unpack("<iii", k)[0::2] == (7, 3) for k in kids)


def test_attack_uses_the_other_variable_and_decimal_text():
    from fuzzloop import attack
    data = b"12 40\n"
    kids = attack.children(data, "a < b", {"a": 12, "b": 40}, random.Random(1))
    assert kids and all(k.endswith(b" 40\n") or k.startswith(b"12 ") for k in kids)
    got = {k for k in kids}
    assert got <= {b"39 40\n", b"40 40\n", b"41 40\n", b"12 11\n", b"12 12\n", b"12 13\n"}


def test_attack_gives_nothing_without_a_handle():
    from fuzzloop import attack
    rng = random.Random(0)
    assert attack.children(b"abc", "x <= 5", {"x": 900}, rng) == []      # not in input
    assert attack.children(b"\x05", "size(a[]) > 0", {}, rng) == []      # not simple
    assert attack.children(b"\x05", "x == y", {"x": 5}, rng) == []       # y unknown
