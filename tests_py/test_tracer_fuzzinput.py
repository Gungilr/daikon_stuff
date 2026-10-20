"""Fuzz-input mode for the emulation tracer: the input format (pure) and one
end-to-end run on a stripped binary (e2e).
"""
import json
import os
import shutil
import struct
import subprocess
import sys

import pytest

from tracer import fuzzinput

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_find_blob_requires_exactly_one_magic():
    m = fuzzinput.BLOB_MAGIC
    seg = {"vaddr": 0x404000, "data": b"\0" * 8 + m + b"\0" * 20}
    assert fuzzinput.find_blob([seg]) == 0x404008
    assert fuzzinput.find_blob([{"vaddr": 0, "data": b"none"}]) is None
    twice = {"vaddr": 0, "data": m + m}
    assert fuzzinput.find_blob([twice]) is None


def test_batch_round_trip_and_encoding():
    blob = struct.pack("<I", 2) + b"ab" + struct.pack("<I", 0)
    assert fuzzinput.parse_batch(blob) == [b"ab", b""]
    assert fuzzinput.encode_input(b"xyz") == struct.pack("<I", 3) + b"xyz"
    big = fuzzinput.encode_input(b"x" * (fuzzinput.FUZZ_MAX + 10))
    assert len(big) == 4 + fuzzinput.FUZZ_MAX


@pytest.mark.e2e
def test_stripped_binary_receives_each_input(tmp_path):
    pytest.importorskip("unicorn")
    if not (shutil.which("gcc") and shutil.which("strip")):
        pytest.skip("needs gcc and strip")
    from fuzzloop import dtrace, runner
    exe = runner.build_blackbox(os.path.join(REPO, "fuzz", "targets", "arith.c"),
                                str(tmp_path))
    inputs = [struct.pack("<iii", 5, 3, 9), struct.pack("<iii", -7, 2, 4), b""]
    decls, per_input, feats, bad, start = runner.run_tracer(
        exe, inputs, str(tmp_path), tier=3)
    assert bad == [] and sorted(per_input) == [0, 1, 2]
    assert start and start.startswith("sub_0x")      # no symbols were used

    def first_return(samples):
        # classify() is the first function fuzz_target calls
        for ppt, row in dtrace.rows(samples):
            if ppt.endswith(":::EXIT0") and "return" in row and "arg0" in row:
                return row["arg0"], row["return"]

    assert first_return(per_input[0]) == (5, 1)       # classify(5) == 1
    assert first_return(per_input[1]) == (-7, -1)     # classify(-7) == -1
    assert first_return(per_input[2]) == (0, 0)       # empty input -> x = 0
    assert feats[0][0] != feats[1][0]                 # different paths
    assert all(dtrace.func_of(p) != "..%s()" % start for p in decls[1])
