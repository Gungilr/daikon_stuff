"""The loop end to end on fuzz/targets/arith.c: real gcc, Kvasir and Daikon.

Needs DAIKONDIR (or ./daikon) with Kvasir built. Deselect with -m "not e2e".
"""
import json
import os
import pathlib
import shutil

import pytest

from fuzzloop import runner
from fuzzloop.loop import FuzzLoop

REPO = pathlib.Path(__file__).resolve().parents[1]
DAIKONDIR = os.environ.get("DAIKONDIR") or str(REPO / "daikon")

pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module")
def arith(tmp_path_factory):
    if runner.check_tools(DAIKONDIR) or not shutil.which("gcc"):
        pytest.skip("needs gcc, java and Daikon with Kvasir built: "
                    + "; ".join(runner.check_tools(DAIKONDIR)))
    out = tmp_path_factory.mktemp("arith")
    FuzzLoop(str(REPO / "fuzz" / "targets" / "arith.c"), str(out), DAIKONDIR,
             rng_seed=0, batch_size=300, batches_per_round=2, rounds=4,
             patience=2, log=lambda *_: None).run()
    return json.loads((out / "history.json").read_text())


def _rec(history, ppt, text):
    for r in history["invariants"]:
        if r["ppt"] == ppt and r["text"] == text:
            return r
    raise AssertionError("never reported: %s %s" % (ppt, text))


def test_overflow_refutes_a_plausible_invariant(arith):
    r = _rec(arith, "..abs_diff():::EXIT", "return >= 0")
    assert r["first_round"] == 0 and r["refuted_round"] is not None
    assert r["violated_by"]


def test_seed_bias_is_refuted(arith):
    assert _rec(arith, "..classify():::EXIT", "return == 1")["refuted_round"] is not None


def test_true_invariants_survive(arith):
    for text in ("lo <= return", "hi >= return"):
        assert _rec(arith, "..clamp():::EXIT", text)["refuted_round"] is None


def test_fuzzer_and_daikon_agree(arith):
    # Daikon falsifies on one counterexample, so anything the fuzzer saw
    # violated must be gone from Daikon's report.
    assert arith["disagreements"] == []


def test_bug_checker_reports_the_overflow(arith):
    # Independent of whether Daikon ever proposed `return >= 0`.
    overflows = [b for b in arith["bugs"] if b["kind"] == "signed integer overflow"]
    assert overflows and all(b["location"].startswith("arith.c:") for b in overflows)
    assert all(b["hits"] >= 1 and b["input"] for b in overflows)
