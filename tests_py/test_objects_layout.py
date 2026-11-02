"""Phase 11 steps 1-3: object table, per-site layouts, classification (pure)."""
from tracer.objects import ObjectTable, HEAP, GLOBAL
from tracer.layout import Evidence, INT, SEXT, ZEXT, SSE
from tracer.classify import (classify, ARRAY, STRUCT, SCALAR, POINTER, FLOAT,
                             SINT, UINT, ABSTAIN, looks_like_string)

STACK_LO, STACK_HI = 0x7ff000, 0x800000


# ------------------------------------------------------------------- objects
def table():
    t = ObjectTable()
    t.set_stack(STACK_LO, STACK_HI)
    return t


def test_heap_lookup_and_free():
    t = table()
    a = t.add(HEAP, 0x5000, 16, ("heap", 0x401234))
    assert t.lookup(0x5008) == (a, 8)
    assert t.lookup(0x5010) is None            # one past the end
    t.kill(0x5000)
    assert t.lookup(0x5008) is None            # freed objects stop resolving
    assert a.site == ("heap", 0x401234)        # but keep their site


def test_adjacent_objects_do_not_bleed():
    t = table()
    a = t.add(HEAP, 0x5000, 8, ("heap", 1))
    b = t.add(HEAP, 0x5010, 8, ("heap", 2))
    assert t.lookup(0x5007)[0] is a
    assert t.lookup(0x500c) is None            # alignment gap belongs to nobody
    assert t.lookup(0x5010)[0] is b


def test_frames_are_bounded_by_their_neighbours():
    t = table()
    t.push_frame(0x7fff00, 0xA)       # main
    t.push_frame(0x7ffe00, 0xB)       # callee; its frame is below 0x7ffe00
    # main's frame: [callee entry rsp + 8, main entry rsp)
    assert t.frame_owner(0x7ffe08) == 0xA
    assert t.frame_owner(0x7ffef0) == 0xA
    # the callee's return address slot belongs to the callee's frame top region
    assert t.frame_owner(0x7ffdf0) == 0xB
    assert t.frame_owner(0x7fff00) is None     # main's own return address: caller's
    assert t.stack_site(0x7ffee0) == ("stack", 0xA, -0x20)
    assert t.stack_extent(0x7ffee0) == 0x20
    t.pop_frame()
    assert t.frame_owner(0x7ffdf0) == 0xA      # innermost frame extends down


def test_site_of_points_into_middle():
    t = table()
    t.add(GLOBAL, 0x404000, 32, ("global", 0x404000))
    assert t.site_of(0x404010) == (("global", 0x404000), 16)


# -------------------------------------------------------------------- layout
def lay(accesses, sizes=None, stack_roots=(), resolve=None):
    """accesses: (key, off, width, write, cls, pc, instance[, target])."""
    ev = Evidence()
    for a in accesses:
        ev.note_access(*a)
    for k, s in (sizes or {}).items():
        ev.note_size(k, s)
    for func, off in stack_roots:
        ev.note_stack_root(func, off)
    return ev.layouts(resolve)


H = ("heap", 0x401100)


def test_evidence_pools_across_instances():
    # two different objects from one malloc site, each touched at one field
    L = lay([(H, 0, 4, True, INT, 0x10, 1), (H, 8, 8, False, INT, 0x20, 2)], {H: 16})
    s = L[H]
    assert sorted(s.fields) == [0, 8] and s.size == 16 and s.instances == {1, 2}


def test_min_size_kept():
    L = lay([(H, 0, 4, True, INT, 1, 1)], {H: 20})
    ev = Evidence()
    ev.note_size(H, 20)
    ev.note_size(H, 12)
    assert ev.layouts()[H].size == 12


def test_stack_objects_are_carved_at_roots():
    # main (0xA) has two locals handed out at -0x20 and -0x10
    F = ("sframe", 0xA)
    L = lay([(F, -0x20, 4, False, INT, 1, 9), (F, -0x1c, 4, False, INT, 2, 9),
             (F, -0x10, 8, False, INT, 3, 9)],
            stack_roots=[(0xA, -0x20), (0xA, -0x10)])
    a, b = L[("stack", 0xA, -0x20)], L[("stack", 0xA, -0x10)]
    assert sorted(a.fields) == [0, 4] and sorted(b.fields) == [0]


def test_stack_access_without_root_is_dropped():
    L = lay([(("sframe", 0xA), -0x30, 4, False, INT, 1, 9)])
    assert L == {}


def test_global_raw_addresses_resolve_at_finalize():
    def resolve(addr):
        return (("global", 0x404000), addr - 0x404000, 16) if 0x404000 <= addr < 0x404010 else None
    L = lay([(("graw",), 0x404008, 4, False, INT, 1, 0),
             (("graw",), 0x405000, 4, False, INT, 1, 0)], resolve=resolve)
    assert list(L) == [("global", 0x404000)] and list(L[("global", 0x404000)].fields) == [8]


def test_pointer_targets_are_mapped_to_sites():
    T = ("heap", 0x401200)
    L = lay([(H, 8, 8, True, INT, 1, 1, (T, 0))], {H: 16, T: 8})
    assert L[H].fields[8].targets == {(T, 0): 1}


# ------------------------------------------------------------------ classify
def test_struct_with_pointer_float_and_signed_fields():
    T = ("heap", 0x401200)
    L = lay([(H, 0, 4, False, SEXT, 1, 1), (H, 8, 8, False, SSE, 2, 1),
             (H, 16, 8, True, INT, 3, 1, (T, 0)), (H, 24, 1, False, ZEXT, 4, 1)],
            {H: 32})
    ti = classify(L[H])
    assert ti.shape == STRUCT
    kinds = {f.offset: (f.kind, f.width, f.signed) for f in ti.fields}
    assert kinds[0] == (SINT, 4, True)
    assert kinds[8] == (FLOAT, 8, None)
    assert kinds[16][0] == POINTER and ti.pointer_fields()[0].targets[0][0] == T
    assert kinds[24] == (UINT, 1, False)


def test_strided_loop_is_an_array():
    acc = [(H, o, 4, False, INT, 0x55, 1) for o in range(0, 40, 4)]
    ti = classify(lay(acc, {H: 40})[H])
    assert ti.shape == ARRAY and ti.stride == 4 and ti.count == 10
    assert ti.fields[0].width == 4


def test_short_loop_is_still_a_struct():
    # Howard: fewer than 4 looped elements is a struct, not an array
    acc = [(H, o, 4, False, INT, 0x55, 1) for o in (0, 4)]
    acc += [(H, 8, 8, False, INT, 0x60, 1)]
    ti = classify(lay(acc, {H: 16})[H])
    assert ti.shape == STRUCT


def test_one_field_is_a_scalar():
    ti = classify(lay([(H, 0, 4, False, INT, 1, 1)], {H: 4})[H])
    assert ti.shape == SCALAR


def test_sse_and_pointer_at_one_offset_abstains():
    T = ("heap", 0x401200)
    L = lay([(H, 0, 8, False, SSE, 1, 1), (H, 0, 8, True, INT, 2, 1, (T, 0)),
             (H, 8, 4, False, INT, 3, 1)], {H: 16})
    ti = classify(L[H])
    assert {f.offset: f.kind for f in ti.fields}[0] == ABSTAIN


def test_conflicting_sign_evidence_gives_no_signedness():
    L = lay([(H, 0, 4, False, SEXT, 1, 1), (H, 0, 4, False, ZEXT, 2, 1),
             (H, 4, 4, False, INT, 3, 1)], {H: 8})
    assert classify(L[H]).fields[0].signed is None


def test_strings():
    assert looks_like_string(b"hello\0junk")
    assert not looks_like_string(b"\x01\x02\0")
    assert not looks_like_string(b"no terminator")
    assert not looks_like_string(b"\0")
