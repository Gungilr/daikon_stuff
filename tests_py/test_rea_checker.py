"""Stage 1 type checker: observations from hand-built p-code, and the rules on top.

A varnode is [kind, size, location, constant_hex]; an op is [id, opcode, inputs, output].
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "rea_eval"))

from observe import Function  # noqa: E402
from check import Binary, check, claim_with_pointee_size, proposal  # noqa: E402

REG = lambda size=8, loc="register:0x38": ["register", size, loc, None]  # noqa: E731
UNIQ = lambda size=8, n=1: ["unique", size, f"unique:{n:x}", None]  # noqa: E731
CONST = lambda value, size=8: ["constant", size, None, format(value, "x")]  # noqa: E731
SPACE = CONST(0x1b1, 4)


def binary(ops, def_use, param_uses, procedures=None, addr="0x401000"):
    rec = {"ops": ops, "def_use": def_use,
           "parameter_uses": [{"ordinal": o, "use": u, "input_index": i} for o, u, i in param_uses]}
    return Binary({"procedures": procedures or {}, "functions": {addr: rec}})


def evidence_for_param(b, ordinal=0, addr="0x401000"):
    return b.evidence(b.param_obs(addr, ordinal))


def test_dereference_makes_a_long_parameter_fail_r1():
    # param0 -> LOAD 1 byte
    b = binary([["a#1", "LOAD", [SPACE, REG()], UNIQ(1)]], [], [(0, "a#1", 1)])
    ev = evidence_for_param(b)
    assert ev["ptr"] and ev["deref_sizes"] == {1}
    verdict, rules = check(claim_with_pointee_size("/long", 8), ev)
    assert verdict == "FAIL" and "R1" in rules
    assert proposal(ev) == "pointer"


def test_pointer_through_constant_offsets_is_followed():
    # param0 -> PTRSUB +8 -> LOAD 4 ; param0 -> LOAD 8  : struct-like
    ops = [["a#1", "PTRSUB", [REG(), CONST(8)], UNIQ(8, 1)],
           ["a#2", "LOAD", [SPACE, UNIQ(8, 1)], UNIQ(4, 2)],
           ["a#3", "LOAD", [SPACE, REG()], UNIQ(8, 3)]]
    b = binary(ops, [["a#1", "a#2", 1]], [(0, "a#1", 0), (0, "a#3", 1)])
    ev = evidence_for_param(b)
    assert {(8, 4), (0, 8)} <= ev["deref_offsets"]
    verdict, rules = check(claim_with_pointee_size("/int *", 8), ev)
    assert verdict == "FAIL" and rules == ["R6"]  # 4-byte access exists, so R5 does not fire


def test_right_pointee_width_passes():
    b = binary([["a#1", "LOAD", [SPACE, REG()], UNIQ(4)]], [], [(0, "a#1", 1)])
    verdict, _ = check(claim_with_pointee_size("/int *", 8), evidence_for_param(b))
    assert verdict == "PASS"


def test_libc_argument_is_pointer_evidence():
    ops = [["a#1", "CALL", [["address", 8, "0x4010d0", None], REG()], None]]
    b = binary(ops, [], [(0, "a#1", 1)],
               procedures={"0x4010d0": {"name": "<EXTERNAL>::memcmp"}})
    ev = evidence_for_param(b)
    assert any("memcmp" in x for x in ev["ptr"])
    assert check(claim_with_pointee_size("/long", 8), ev)[0] == "FAIL"


def test_signed_ops_reject_an_unsigned_claim():
    ops = [["a#1", "INT_SLESS", [REG(4), CONST(3, 4)], ["unique", 1, "unique:1", None]]]
    b = binary(ops, [], [(0, "a#1", 0)])
    verdict, rules = check(claim_with_pointee_size("/uint", 4), evidence_for_param(b))
    assert verdict == "FAIL" and rules == ["R3"]
    assert check(claim_with_pointee_size("/int", 4), evidence_for_param(b))[0] == "PASS"


def test_float_ops_reject_an_integer_claim():
    ops = [["a#1", "FLOAT_ADD", [REG(8), REG(8, "register:0x1200")], UNIQ(8)]]
    b = binary(ops, [], [(0, "a#1", 0)])
    verdict, rules = check(claim_with_pointee_size("/long", 8), evidence_for_param(b))
    assert verdict == "FAIL" and "R4" in rules


def test_no_uses_is_no_evidence_not_a_failure():
    b = binary([], [], [])
    assert check(claim_with_pointee_size("/long", 8), evidence_for_param(b))[0] == "NO-EVIDENCE"


def test_abstention_gets_no_verdict():
    b = binary([["a#1", "LOAD", [SPACE, REG()], UNIQ(4)]], [], [(0, "a#1", 1)])
    assert check(claim_with_pointee_size("/undefined8", 8), evidence_for_param(b))[0] == "ABSTAIN"


def test_global_whose_address_is_only_taken_is_not_a_pointer_variable():
    # PTRSUB(0, &g) -> LOAD at +8 : g is an object, not a pointer value
    ops = [["a#1", "PTRSUB", [CONST(0), CONST(0x404000)], UNIQ(8, 1)],
           ["a#2", "PTRSUB", [UNIQ(8, 1), CONST(8)], UNIQ(8, 2)],
           ["a#3", "LOAD", [SPACE, UNIQ(8, 2)], UNIQ(8, 3)]]
    b = binary(ops, [["a#1", "a#2", 0], ["a#2", "a#3", 1]], [])
    ev = b.global_evidence("0x404000", 64)
    assert ev["addr_taken"] and (8, 8) in ev["accesses"]
    verdict, rules = check({"kind": "pointer", "size": 8, "pointee": "void"}, ev, is_global=True)
    assert verdict == "FAIL" and "R7" in rules


def test_global_read_as_a_pointer_value_passes():
    # LOAD through the 8-byte value stored at &g : g really holds a pointer
    ops = [["a#1", "LOAD", [SPACE, ["address", 8, "0x404000", None]], UNIQ(4)]]
    b = binary(ops, [], [])
    ev = b.global_evidence("0x404000", 8)
    assert ev["ptr"]
    verdict, _ = check({"kind": "pointer", "size": 8, "pointee": "void"}, ev, is_global=True)
    assert verdict == "PASS"


def test_function_follows_through_copies():
    ops = [["a#1", "COPY", [REG()], UNIQ(8, 1)],
           ["a#2", "LOAD", [SPACE, UNIQ(8, 1)], UNIQ(2, 2)]]
    f = Function({"ops": ops, "def_use": [["a#1", "a#2", 1]],
                  "parameter_uses": [{"ordinal": 0, "use": "a#1", "input_index": 0}]})
    assert f.param(0)["derefs"] == [(0, 2, "r")]
