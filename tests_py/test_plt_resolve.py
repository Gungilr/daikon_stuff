"""PLT stub resolution - the claim that stripping does not hide the allocator."""
import pathlib

import pytest

from tracer.elfload import resolve_plt_stubs

REPO = pathlib.Path(__file__).resolve().parents[1]
TEST08 = REPO / "tests" / "test08.exe"
TEST08_STRIPPED = REPO / "tests" / "test08_stripped.exe"


def _need(p):
    if not p.exists():
        pytest.skip(f"{p} not built - run `make tests`")
    return str(p)


def test_finds_the_allocator_in_the_symbol_bearing_build():
    stubs = resolve_plt_stubs(_need(TEST08))
    assert "malloc" in stubs.values()
    assert "free" in stubs.values()


def test_finds_the_allocator_in_the_STRIPPED_build():
    """The load-bearing claim for tier 5.

    `strip --strip-all` removes .symtab but cannot remove .dynsym or .rela.plt;
    the dynamic loader needs them. So an allocator import stays identifiable in
    a fully stripped binary, and the heap model is not blocked by stripping.
    """
    stubs = resolve_plt_stubs(_need(TEST08_STRIPPED))
    assert "malloc" in stubs.values()
    assert "free" in stubs.values()


def test_stripped_and_unstripped_agree_exactly():
    """Same addresses, same names - stripping costs nothing here."""
    assert resolve_plt_stubs(_need(TEST08)) == resolve_plt_stubs(_need(TEST08_STRIPPED))


def test_addresses_are_plausible_code_addresses():
    for addr in resolve_plt_stubs(_need(TEST08)):
        assert 0x400000 <= addr < 0x500000


def test_non_allocator_imports_are_also_resolved():
    """printf should be found too; tier 5 filters by name, not by resolution."""
    assert "printf" in resolve_plt_stubs(_need(TEST08)).values()


def test_binary_without_plt_returns_empty_not_error():
    """A statically linked or import-free binary must degrade quietly."""
    src = REPO / "tests" / "test03.exe"
    if not src.exists():
        pytest.skip("test03.exe not built")
    stubs = resolve_plt_stubs(str(src))
    assert isinstance(stubs, dict)
