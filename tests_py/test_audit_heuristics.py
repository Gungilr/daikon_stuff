"""The grader's ground truth: System V classification from DWARF types.

Every verdict scripts/audit_heuristics.py hands down compares the tracer with
these functions, so they are tested against the ABI's own examples rather than
against the tracer. Pure: no binaries, no emulator.
"""
from audit_heuristics import (assign_params, eightbytes, global_shape,
                              read_dtrace, return_class)


def i(size=4, signed=True):
    return {"k": "int", "size": size, "signed": signed, "bool": False}


def f(size=8):
    return {"k": "float", "size": size}


PTR = {"k": "pointer", "size": 8}
LONG_DOUBLE = {"k": "x87", "size": 16}


def struct(*members):
    """Members laid out naturally aligned, as a C compiler would."""
    off, laid = 0, []
    for m in members:
        align = min(m["size"], 8) or 1
        off = (off + align - 1) // align * align
        laid.append((off, m))
        off += m["size"]
    size = (off + 7) // 8 * 8 if any(m["size"] >= 8 for m in members) else (
        (off + 3) // 4 * 4)
    return {"k": "struct", "size": size, "members": laid}


# ---- one argument's classes -------------------------------------------------

def test_scalars():
    assert eightbytes(i()) == ["INTEGER"]
    assert eightbytes(PTR) == ["INTEGER"]
    assert eightbytes(f(4)) == ["SSE"]
    assert eightbytes(f(8)) == ["SSE"]
    assert eightbytes(LONG_DOUBLE) == "X87"
    assert eightbytes(i(16)) == ["INTEGER", "INTEGER"]        # __int128


def test_small_structs_split_per_eightbyte():
    assert eightbytes(struct(i(), i())) == ["INTEGER"]
    assert eightbytes(struct(f(), f())) == ["SSE", "SSE"]
    assert eightbytes(struct(f(), i(8))) == ["SSE", "INTEGER"]
    # an int and a float sharing one eightbyte: INTEGER wins
    assert eightbytes(struct(i(), f(4))) == ["INTEGER"]


def test_large_structs_go_in_memory():
    assert eightbytes(struct(i(8), i(8), i(8))) == "MEMORY"
    assert eightbytes({"k": "struct", "size": 252, "members": []}) == "MEMORY"


# ---- whole parameter lists ----------------------------------------------------

def test_mixed_list_counts_each_register_file_separately():
    a = assign_params([i(), f(), i()])
    assert (len(a["gpr"]), len(a["sse"]), a["stack_words"]) == (2, 1, 0)
    assert [pi for pi, _ in a["gpr"]] == [0, 2]


def test_seventh_integer_goes_on_the_stack():
    a = assign_params([i()] * 7)
    assert (len(a["gpr"]), a["stack_words"]) == (6, 1)


def test_struct_by_value_in_memory_is_stack_words_not_registers():
    """The case the tracer gets 6 of 6 wrong: one parameter, 32 stack words."""
    a = assign_params([{"k": "struct", "size": 252, "members": []}])
    assert (len(a["gpr"]), a["stack_words"]) == (0, 32)
    assert a["aggregate_on_stack"]


def test_struct_that_no_longer_fits_in_registers_moves_whole_to_the_stack():
    a = assign_params([i()] * 5 + [struct(i(8), i(8))])
    assert (len(a["gpr"]), a["stack_words"]) == (5, 2)


def test_aggregate_register_pieces_carry_no_scalar_type():
    a = assign_params([struct(i(), i())])
    assert a["gpr"] == [(0, None)] and a["aggregate_in_regs"]


# ---- returns ----------------------------------------------------------------------

def test_return_classes():
    assert return_class(None) == "void"
    assert return_class(i()) == "int"
    assert return_class(PTR) == "pointer"
    assert return_class(f()) == "float"
    assert return_class(LONG_DOUBLE) == "x87"
    assert return_class(i(16)) == "int128"
    assert return_class(struct(i(), i())) == "aggregate:INTEGER"
    assert return_class(struct(i(8), i(8), i(8))) == "memory"


def test_global_shapes():
    assert global_shape(i()) == "scalar"
    assert global_shape(struct(i(), f())) == "struct"
    assert global_shape({"k": "array", "size": 20, "elem": i(), "count": 5}) == "array"
    assert global_shape({"k": "array", "size": 600, "count": 5,
                         "elem": {"k": "struct", "size": 120, "members": []}}
                        ) == "array-of-struct"


# ---- reading our own trace ----------------------------------------------------------

def test_read_dtrace_keeps_scalars_and_drops_arrays(tmp_path):
    p = tmp_path / "t.dtrace"
    p.write_text(
        "decl-version 2.0\nvar-comparability implicit\n\n"
        "ppt ..f():::ENTER\n  ppt-type enter\n  variable arg0\n"
        "    var-kind variable\n    rep-type int\n    dec-type int\n"
        "    comparability 1\n\n"
        "..f():::ENTER\nthis_invocation_nonce\n7\narg0\n-3\n1\n"
        "arg1[..]\n[1 2 3]\n1\n\n"
        "..f():::EXIT0\nthis_invocation_nonce\n7\nreturn\n4294967295\n1\n\n")
    out = read_dtrace(str(p))
    assert out["..f():::ENTER"] == [{"arg0": -3}]
    assert out["..f():::EXIT0"] == [{"return": 4294967295}]
