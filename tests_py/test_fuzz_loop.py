"""The Daikon <-> fuzzer loop: real input to the tracer, invariant checks, mapping."""
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "scripts" / "fuzz"))

import invariants as I  # noqa: E402
from loop import Mapping, wrap32  # noqa: E402


def test_compile_constant_forms():
    inv = I.compile_inv("p", "x >= 600")
    assert inv.kind == "const" and inv.holds({"x": 600}) and not inv.holds({"x": 599})
    inv = I.compile_inv("p", "0 <= x")          # constant on the left is flipped
    assert inv.holds({"x": 0}) and not inv.holds({"x": -1})
    inv = I.compile_inv("p", "return one of { 400, 500, 640, 740 }")
    assert inv.holds({"return": 640}) and not inv.holds({"return": 550})


def test_compile_relations_orig_and_linear():
    inv = I.compile_inv("p", "orig(g_0x404040) < g_0x404044")
    assert inv.vars == ("orig(g_0x404040)", "g_0x404044")
    assert inv.holds({"orig(g_0x404040)": 1, "g_0x404044": 2})
    inv = I.compile_inv("p", "return - x - 100 == 0")
    assert inv.kind == "linear" and inv.holds({"return": 150, "x": 50})
    assert not inv.holds({"return": 151, "x": 50})


def test_unknown_forms_and_missing_variables_are_not_guessed():
    assert I.compile_inv("p", "a[] elements == 0") is None
    assert I.compile_inv("p", "(x == 1)  ==>  (y == 2)") is None
    assert I.compile_inv("p", "x == y").holds({"x": 1}) is None


def test_mapping_learns_a_field_only_when_it_is_unambiguous():
    m = Mapping(3)
    runs = ([5, 7, 9], [6, 7, 1], [8, 7, 4], [1, 7, 2], [3, 7, 5])
    for f in runs[:4]:
        m.observe(f, {"p": [{"g": 0, "h": 7}, {"g": f[0], "h": f[1]}]})
    assert m.field("g") is None                  # 4 runs: below the 5-run minimum
    m.observe(runs[4], {"p": [{"g": 0, "h": 7}, {"g": runs[4][0], "h": 7}]})
    assert m.field("g") == 0 and m.field("orig(g)") == 0   # the unset 0 washes out
    assert m.field("h") is None                  # field 1 is always 7: one value only


def test_wrap32():
    assert wrap32(2**31) == -2**31 and wrap32(-1) == -1


def test_c_integer_parsing():
    from tracer.emulate import Tracer
    assert Tracer._parse_c_integer(b"  -42xyz") == (-42, 5)
    assert Tracer._parse_c_integer(b"0x1f", 16) == (31, 4)
    assert Tracer._parse_c_integer(b"abc") == (0, 0)


SRC = r"""
#include <stdlib.h>
int g_a, g_b;
int pick(void) { return g_a > g_b ? 1 : 2; }
int main(int argc, char **argv) {
    if (argc < 3) exit(1);
    g_a = atoi(argv[1]); g_b = atoi(argv[2]);
    return pick();
}
"""


@pytest.fixture(scope="module")
def prog(tmp_path_factory):
    pytest.importorskip("unicorn")
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("fz")
    (d / "p.c").write_text(SRC)
    subprocess.run([gcc, "-O0", "-no-pie", "-fno-stack-protector", "-o", str(d / "p.exe"),
                    str(d / "p.c")], check=True)
    return d


def _trace(d, *extra):
    out = d / "t.dtrace"
    cov = d / "t.cov"
    p = subprocess.run([sys.executable, str(REPO / "scripts" / "unicorn_dwarf.py"),
                        str(d / "p.exe"), "-o", str(out), "--start-func", "main",
                        "--tier", "10", "--coverage-out", str(cov), *extra],
                       capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, p.stderr
    return out.read_text(), json.loads(cov.read_text())


def _samples(dt, ppt):
    """Sample blocks only (a declaration block starts with `ppt `)."""
    return [b for b in dt.split("\n\n") if b.startswith(ppt + "\n")]


def _pick_return(dt):
    return _samples(dt, "..pick():::EXIT0")[0].split("return\n")[1].split("\n")[0]


def test_e2e_argv_and_modelled_atoi_reach_the_program(prog):
    dt, cov = _trace(prog, "--model-libc", "--program-arg", "9", "--program-arg", "3")
    assert _pick_return(dt) == "1"               # 9 > 3
    dt2, cov2 = _trace(prog, "--model-libc", "--program-arg", "2", "--program-arg", "5")
    assert _pick_return(dt2) == "2"
    assert set(map(tuple, cov["edges"])) != set(map(tuple, cov2["edges"]))


def test_e2e_exit_stops_the_run(prog):
    dt, cov = _trace(prog, "--model-libc")       # argc == 1: exit(1)
    assert cov["exit"] == 1 and not _samples(dt, "..pick():::ENTER")


def test_e2e_batch_mode_traces_every_input_into_one_file(prog):
    lst = prog / "in.jsonl"
    lst.write_text('["9","3"]\n["2","5"]\n["4","4"]\n')
    dt, _ = _trace(prog, "--model-libc", "--program-args-file", str(lst))
    assert len(_samples(dt, "..pick():::ENTER")) == 3
