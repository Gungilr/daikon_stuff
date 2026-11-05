"""--type-hints (docs/plans/resym-hints.md, step 1): candidate types per argument,
applied only when the run refutes none of the survivors and they all agree."""
import json
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from tracer import hints  # noqa: E402
from tracer.classify import TypeInfo, FieldType, STRUCT, SCALAR as T_SCALAR, SINT  # noqa: E402
from tracer.memmap import POINTER, SCALAR  # noqa: E402

CHARP = {"kind": "pointer", "pointee": {"kind": "char", "size": 1}}
INTP = {"kind": "pointer", "pointee": {"kind": "int", "size": 4, "signed": True}}
STRUCTP = {"kind": "pointer", "pointee": {"kind": "struct", "size": 16}}
INT = {"kind": "int", "size": 4, "signed": True}
UCHARP = {"kind": "pointer", "pointee": {"kind": "int", "size": 1, "signed": False}}


def test_effects():
    assert hints.effect(CHARP) == ("string",)
    assert hints.effect(INTP) == ("array", 4, SINT, True)
    assert hints.effect(STRUCTP) is None
    assert hints.effect(INT) is None


def test_is_cstring():
    assert hints.is_cstring(b"hello\0junk")
    assert hints.is_cstring(b"\0")
    assert not hints.is_cstring(b"\x01\x00")
    assert not hints.is_cstring(b"no terminator")
    assert not hints.is_cstring(None)


def test_single_survivor_applies():
    assert hints.select([CHARP], POINTER, True, 0, None)[:2] == (("string",), "applied")


def test_refuted_by_non_string_value():
    eff, status, why = hints.select([CHARP], POINTER, True, 1, None)
    assert eff is None and status == "all-refuted" and why == ["not a C string"]


def test_pointer_refuted_by_non_address():
    assert hints.select([INTP], SCALAR, True, 0, None)[1] == "all-refuted"


def test_null_only_slot_does_not_refute_a_pointer():
    assert hints.select([CHARP], SCALAR, False, 0, None)[:2] == (("string",), "applied")


def test_array_refuted_by_observed_struct():
    T = TypeInfo(("heap", 1), STRUCT, 16,
                 [FieldType(0, 4, SINT, True), FieldType(8, 8, SINT, True)])
    assert hints.select([INTP], POINTER, True, 0, T)[1] == "all-refuted"


def test_array_refuted_by_other_width():
    T = TypeInfo(("heap", 1), T_SCALAR, 8, [FieldType(0, 8, SINT, True)])
    assert hints.refuted(INTP, POINTER, True, 0, T) == "pointee width differs"


def test_disagreeing_survivors_abstain():
    eff, status, _ = hints.select([CHARP, INTP], POINTER, True, 0, None)
    assert eff is None and status == "contested"


def test_survivors_without_effect():
    assert hints.select([STRUCTP], POINTER, True, 0, None)[1] == "no-effect"


def test_load_maps_args_to_raw_slots(tmp_path):
    p = tmp_path / "h.json"
    p.write_text(json.dumps({"functions": {"0x401000": {"args": {"0": [CHARP], "7": [INT]},
                                                        "return": [INTP]}}}))
    got = hints.load(str(p))
    assert got == {(0x401000, 1): [CHARP], (0x401000, 0): [INTP]}   # arg 7: no register


# ------------------------------------------------------------------ end to end
SRC = r"""
int count_chars(const char *s) { int n = 0; while (s[n]) n++; return n; }
int peek(int *p) { return p[0]; }
int mixed(const char *s) { return s[0]; }
int main(void) {
    int arr[5] = {1, 2, 3, 4, 5};
    count_chars("hello"); count_chars("hi");
    peek(arr); mixed("abc");
    return 0;
}
"""


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    pytest.importorskip("unicorn")
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("hints")
    (d / "h.c").write_text(SRC)
    exe = d / "h.exe"
    subprocess.run([gcc, "-O0", "-no-pie", "-fno-stack-protector", "-o", str(exe),
                    str(d / "h.c")], check=True)
    syms = {}
    for line in subprocess.run(["nm", str(exe)], capture_output=True, text=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt":
            syms[parts[2]] = "0x" + parts[0].lstrip("0")
    return d, exe, syms


def _run(d, exe, hint_spec, tag):
    hf = d / f"{tag}.json"
    hf.write_text(json.dumps({"functions": hint_spec}))
    out = d / f"{tag}.dtrace"
    proc = subprocess.run([sys.executable, str(REPO / "scripts" / "unicorn_dwarf.py"), str(exe),
                           "-o", str(out), "--start-func", "main", "--tier", "10",
                           "--type-hints", str(hf)], capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    return out.read_text(), proc.stdout + proc.stderr


def _decl(dtrace, func):
    return dtrace.split(f"ppt ..{func}():::ENTER\n")[1].split("\n\n")[0]


def test_e2e_string_and_array(built):
    d, exe, syms = built
    dt, log = _run(d, exe, {syms["count_chars"]: {"args": {"0": [CHARP]}},
                            syms["peek"]: {"args": {"0": [INTP]}}}, "ok")
    assert "applied 2" in log
    decl = _decl(dt, "count_chars")
    assert "variable arg0\n  var-kind variable\n  dec-type char*\n  rep-type java.lang.String" in decl
    assert '"hello"' in dt and '"hi"' in dt
    assert "variable arg0[..]" in _decl(dt, "peek")
    assert "[ 1 2 3 4 5 " in dt


def test_e2e_run_refutes_the_wrong_width(built):
    d, exe, syms = built
    # mixed() reads one byte: an int* candidate is refuted, char* survives alone.
    _, log = _run(d, exe, {syms["mixed"]: {"args": {"0": [CHARP, INTP]}}}, "width")
    assert "applied 1" in log


def test_e2e_refuted_and_contested_change_nothing(built):
    d, exe, syms = built
    base, _ = _run(d, exe, {}, "none")
    dt, log = _run(d, exe, {syms["peek"]: {"args": {"0": [CHARP]}},          # int array: not text
                            # both survive a byte-wide read, and disagree on the effect
                            syms["mixed"]: {"args": {"0": [CHARP, UCHARP]}}},
                   "abstain")
    assert "all-refuted 1" in log and "contested 1" in log
    assert dt == base
