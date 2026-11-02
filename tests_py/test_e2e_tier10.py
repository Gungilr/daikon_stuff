"""Tier 10 end-to-end: the object model (docs/plans/phase11.md) on tests/test16.c."""
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

pytest.importorskip("unicorn")

REPO = pathlib.Path(__file__).resolve().parents[1]
SHIM = REPO / "scripts" / "unicorn_dwarf.py"
DAIKON = pathlib.Path(os.environ.get("DAIKONDIR", REPO / "daikon"))

pytestmark = pytest.mark.e2e


def _trace(name, out, *extra, binary=None):
    binary = binary or (REPO / "tests" / f"{name}.exe")
    if not binary.exists():
        pytest.skip(f"{binary} not built - run `make tests`")
    proc = subprocess.run(
        [sys.executable, str(SHIM), str(binary), "-o", str(out),
         "--start-func", "main", *extra],
        cwd=str(REPO), capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, f"tracer failed:\n{proc.stderr}"
    return out.read_text(), proc.stdout + proc.stderr


def _decl(dtrace, ppt):
    return dtrace.split(f"ppt {ppt}\n")[1].split("\n\n")[0]


def _vars(decl):
    return [l.split(" ", 1)[1] for l in decl.splitlines() if l.startswith("variable ")]


def _values(dtrace, ppt, var):
    out, lines = [], dtrace.splitlines()
    for i, line in enumerate(lines):
        if line == ppt:
            for j in range(i + 1, min(i + 200, len(lines))):
                if lines[j] == var:
                    out.append(lines[j + 1])
                    break
                if lines[j] == "":
                    break
    return out


@pytest.fixture(scope="module")
def t16(tmp_path_factory):
    d = tmp_path_factory.mktemp("t16")
    dtrace, _ = _trace("test16", d / "t16.dtrace", "--tier", "10", "--shadow",
                       "--dump-layouts", str(d / "layouts.json"))
    return dtrace, json.loads((d / "layouts.json").read_text())


def test_linked_list_is_walked_two_levels(t16):
    dtrace, _ = t16
    v = _vars(_decl(dtrace, "..second():::ENTER"))
    assert "arg0[..].off8" in v                  # next
    assert "arg0[..].off8->off0" in v            # next->val
    # head->next->val is 2 on the only call
    assert _values(dtrace, "..second():::ENTER", "arg0[..].off8->off0") == ["[ 2 ]"]


def test_pointer_field_is_a_hashcode(t16):
    blocks = _blocks(_decl(t16[0], "..sum_list():::ENTER"))
    assert "rep-type hashcode[]" in blocks["arg0[..].off8"]


def test_two_pointer_copy_credits_each_object(t16):
    """copy_item(dst, src): src is read, dst written; both get the full
    layout of their OWN object - nothing is credited to the wrong one."""
    dtrace, lay = t16
    v = _vars(_decl(dtrace, "..copy_item():::EXIT0"))
    for a in ("arg0", "arg1"):
        assert f"{a}[..].off0" in v and f"{a}[..].off8" in v
    roots = lay["roots"]
    sites = {s for f in roots.values() for s in f.values()}
    stack_sites = [s for s in sites if s.startswith("stack")]
    assert len(stack_sites) >= 2                 # dst and src are distinct objects


def test_union_read_both_ways_abstains(t16):
    v = _vars(_decl(t16[0], "..as_int():::ENTER"))
    assert not any(x.startswith("arg0[..]") for x in v)


def _blocks(decl):
    """{variable name: its declaration lines}."""
    out, cur = {}, None
    for line in decl.splitlines():
        if line.startswith("variable "):
            cur = line.split(" ", 1)[1]
            out[cur] = []
        elif cur is not None:
            out[cur].append(line.strip())
    return out


def test_double_global_is_a_double(t16):
    blocks = _blocks(_decl(t16[0], "..main():::ENTER"))
    assert any(n.startswith("g_0x") and "rep-type double" in b for n, b in blocks.items())


def test_string_field_of_a_struct_global(t16):
    dtrace, _ = t16
    decl = _decl(dtrace, "..tagged():::ENTER")
    assert "rep-type java.lang.String" in decl
    name = [x for x in _vars(decl) if x.startswith("g_0x") and x.endswith(".off0")][0]
    assert _values(dtrace, "..tagged():::ENTER", name)[0] == '"fixture"'


def test_shadow_reports_a_never_written_field_as_nonsensical(t16, tmp_path):
    dtrace, _ = t16
    assert _values(dtrace, "..peek():::ENTER", "arg0[..].off4") == ["nonsensical"]
    plain, _ = _trace("test16", tmp_path / "plain.dtrace", "--tier", "10")
    assert _values(plain, "..peek():::ENTER", "arg0[..].off4") == ["[ 0 ]"]


def test_lower_tiers_do_not_change(tmp_path):
    a, _ = _trace("test16", tmp_path / "t9.dtrace", "--tier", "9")
    assert "->" not in a


def test_fault_on_unmapped_stops_on_a_wild_pointer(tmp_path):
    if shutil.which("gcc") is None:
        pytest.skip("gcc not available")
    src = tmp_path / "wild.c"
    src.write_text("int deref(int *p){return *p;}\n"
                   "int main(void){return deref((int*)0x13370000);}\n")
    exe = tmp_path / "wild.exe"
    subprocess.run(["gcc", "-O0", "-no-pie", "-o", str(exe), str(src)], check=True)
    _, log = _trace("wild", tmp_path / "w.dtrace", "--tier", "10",
                    "--fault-on-unmapped", binary=exe)
    assert "Fault: unmapped access at 0x13370000" in log
    _, log2 = _trace("wild", tmp_path / "w2.dtrace", "--tier", "10", binary=exe)
    assert "Fault" not in log2


def test_daikon_accepts_the_trace(t16, tmp_path):
    if shutil.which("java") is None or not (DAIKON / "java" / "daikon" / "Daikon.class").exists():
        pytest.skip("daikon not built")
    p = tmp_path / "t16.dtrace"
    p.write_text(t16[0])
    proc = subprocess.run(
        ["java", "-cp", f"{DAIKON}/java:{DAIKON}/java/lib/*", "daikon.Daikon",
         "-o", str(tmp_path / "o.inv.gz"), str(p)],
        capture_output=True, text=True, timeout=600)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0 and "Exception" not in out, out[-2000:]
    assert "arg0[].off8->off0" in out or "second()" in out
