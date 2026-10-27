"""The bug checker: parsing sanitizer output (pure) and the sanitizer build
end to end, including an ASan abort in the middle of a batch (e2e)."""
import os
import shutil

import pytest

from fuzzloop import bugs

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UBSAN_AND_ASAN = """@@FUZZ-INPUT 0
@@FUZZ-INPUT 1
/x/fuzz/targets/arith.c:35:26: runtime error: signed integer overflow: 9 - -2147483648 cannot be represented in type 'int'
/x/fuzz/targets/arith.c:35:26: runtime error: signed integer overflow: 5 - -2147483647 cannot be represented in type 'int'
@@FUZZ-INPUT 2
=================================================================
==240==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014 at pc 0x1 bp 0x2 sp 0x3
WRITE of size 1 at 0x502000000014 thread T0
    #0 0x556f2f1f84d4 in memset_helper /usr/lib/libc_like.c:12
    #1 0x556f2f1f84d5 in write_at /x/tests_py/fixtures/heap_bug.c:8
    #2 0x7f5f0022a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
"""


def test_reports_are_attributed_to_the_preceding_input():
    per, last = bugs.parse_stderr(UBSAN_AND_ASAN, own_sources=("heap_bug.c",))
    assert last == 2
    assert 0 not in per
    assert [b.key for b in per[1]] == [("signed integer overflow", "arith.c:35:26")] * 2
    (asan,) = per[2]
    assert asan.kind == "heap-buffer-overflow"
    # located at the first frame in the target's own source, not the helper
    assert asan.location == "heap_bug.c:8" and asan.function == "write_at"
    assert "WRITE of size 1" in asan.message


def test_asan_falls_back_to_first_frame_without_own_sources():
    per, _ = bugs.parse_stderr(UBSAN_AND_ASAN)
    assert per[2][0].location == "libc_like.c:12"


def test_reports_before_any_marker_are_ignored():
    per, last = bugs.parse_stderr("a.c:1:1: runtime error: x\n")
    assert per == {} and last is None


@pytest.mark.e2e
def test_sanitizer_build_finds_both_bugs_and_keeps_going(tmp_path):
    if not shutil.which("gcc"):
        pytest.skip("needs gcc")
    from fuzzloop import runner
    exe = runner.build_san(os.path.join(REPO, "tests_py", "fixtures", "heap_bug.c"),
                           str(tmp_path))
    inputs = [b"\x01", b"\x07", b"\x09", b"\x02", b"\x07"]
    found = runner.run_san(exe, inputs, str(tmp_path), own_sources=("heap_bug.c",))
    # Recover mode: the heap overflow in input 1 does not stop the batch, so
    # input 2's overflow is still found. Input 4 repeats input 1's bug at the
    # same location, and both runtimes print each location once per process.
    assert sorted(found) == [1, 2]
    assert found[1][0].kind == "heap-buffer-overflow"
    assert found[1][0].function == "write_at"
    assert found[2][0].kind == "signed integer overflow"


@pytest.mark.e2e
def test_a_fatal_signal_costs_one_input_not_the_batch(tmp_path):
    from fuzzloop import runner
    exe = runner.build_san(os.path.join(REPO, "fuzz", "targets", "stats.c"),
                           str(tmp_path))
    inputs = [b"\x00", bytes([3, 1, 2, 3]), b"\x00"]   # n == 0 divides by zero
    found = runner.run_san(exe, inputs, str(tmp_path), own_sources=("stats.c",))
    assert found[0][0].kind == "division by zero"
    assert 1 not in found


@pytest.mark.e2e
def test_wrapv_hides_the_overflow_and_the_checker_does_not_use_it(tmp_path):
    """The reason the checker is a separate build: gcc drops UBSan's
    signed-overflow check under -fwrapv."""
    from fuzzloop import runner
    assert "-fwrapv" not in runner.SAN_CFLAGS
    assert "-fwrapv" in runner.KV_CFLAGS
