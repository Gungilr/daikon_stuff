"""Turn Ghidra high p-code into per-variable observations: what the code DOES with a value.

Pure module: no Ghidra, no REA, no debug info.  Input is one function record as
saved by collect_pcode.py:
    ops        [[id, opcode, [input varnodes], output varnode], ...]
    def_use    [[definition_id, use_id, input_index], ...]
    parameter_uses [{"ordinal", "use", "input_index"}, ...]
A varnode is [kind, size_bytes, location, constant_hex].

For each parameter we follow its value forward through value-preserving ops
(COPY, CAST, MULTIEQUAL, INDIRECT) and pointer arithmetic (PTRADD, PTRSUB,
INT_ADD/INT_SUB by a constant), and record:
    derefs       [(offset or None, size, "r"|"w")]   - used as a LOAD/STORE address
    indexed      element sizes of variable-index pointer arithmetic (array-like)
    signed / unsigned   counts of sign-revealing ops consuming it
    arith        ops that make no sense on a pointer (MULT, DIV, REM, signed shift)
    float        FLOAT_* ops consuming it
    int2float    INT2FLOAT consuming it (the value is an integer)
    calls        [(target_address, argument_index)] - passed to a call
    callind      used as an indirect call target (function pointer)
    narrowed     sizes it is truncated to by SUBPIECE at offset 0
    returned     flows into RETURN

Caveat recorded in the plan: high p-code reflects some of Ghidra's own typing
(e.g. PTRADD element size follows Ghidra's pointee guess).  Rules built on top
must lean on facts that do not depend on that guess: dereference itself, LOAD /
STORE sizes, and the opcodes applied.
"""
from collections import defaultdict

PASS_THROUGH = {"COPY", "CAST", "MULTIEQUAL", "INDIRECT"}
SIGNED_OPS = {"INT_SDIV", "INT_SREM", "INT_SRIGHT", "INT_SLESS", "INT_SLESSEQUAL",
              "INT_SBORROW", "INT_SCARRY", "INT_SEXT"}
UNSIGNED_OPS = {"INT_DIV", "INT_REM", "INT_RIGHT", "INT_LESS", "INT_LESSEQUAL",
                "INT_CARRY", "INT_ZEXT"}
NON_POINTER_ARITH = {"INT_MULT", "INT_DIV", "INT_SDIV", "INT_REM", "INT_SREM",
                     "INT_SRIGHT", "INT_2COMP", "INT2FLOAT"}
MAX_STEPS = 400


def _const(vn):
    if vn and vn[0] == "constant" and vn[3] is not None:
        v = int(vn[3], 16)
        size = vn[1] or 8
        if v >= 1 << (8 * size - 1):  # two's complement
            v -= 1 << (8 * size)
        return v
    return None


def new_obs():
    return {"derefs": [], "indexed": [], "signed": 0, "unsigned": 0, "arith": [],
            "float": 0, "int2float": 0, "calls": [], "callind": 0, "narrowed": [],
            "returned": 0, "uses": 0}


class Function:
    def __init__(self, rec):
        self.ops = {o[0]: o for o in rec.get("ops", [])}
        self.uses = defaultdict(list)          # definition op id -> [(use op id, input index)]
        for d, u, i in rec.get("def_use", []):
            self.uses[d].append((u, i))
        self.param_uses = defaultdict(list)    # ordinal -> [(use op id, input index)]
        for pu in rec.get("parameter_uses", []):
            self.param_uses[pu["ordinal"]].append((pu["use"], pu["input_index"]))

    def follow(self, seeds):
        """Forward walk from (op_id, input_index) uses of one value."""
        obs = new_obs()
        work = [(s[0], s[1], s[2] if len(s) > 2 else 0) for s in seeds]
        seen = set()
        steps = 0
        while work and steps < MAX_STEPS:
            op_id, idx, off = work.pop()
            if (op_id, idx, off) in seen:
                continue
            seen.add((op_id, idx, off))
            steps += 1
            op = self.ops.get(op_id)
            if op is None:
                continue
            _, opc, ins, out = op
            obs["uses"] += 1

            def forward(new_off):
                for u, i in self.uses.get(op_id, []):
                    work.append((u, i, new_off))

            if opc == "LOAD" and idx == 1:
                obs["derefs"].append((off, out[1] if out else None, "r"))
            elif opc == "STORE" and idx == 1:
                obs["derefs"].append((off, ins[2][1] if len(ins) > 2 and ins[2] else None, "w"))
            elif opc in PASS_THROUGH:
                forward(off)
            elif opc == "PTRSUB" and idx == 0:
                c = _const(ins[1]) if len(ins) > 1 else None
                forward(None if off is None or c is None else off + c)
            elif opc == "PTRADD" and idx == 0:
                k, elem = (_const(ins[1]) if len(ins) > 1 else None), (_const(ins[2]) if len(ins) > 2 else None)
                if k is not None and elem is not None and off is not None:
                    forward(off + k * elem)
                else:
                    if elem:
                        obs["indexed"].append(elem)
                    forward(None)
            elif opc in ("INT_ADD", "INT_SUB") and len(ins) == 2:
                other = ins[1 - idx] if idx in (0, 1) else None
                c = _const(other)
                if c is not None:
                    forward(None if off is None else off + (c if opc == "INT_ADD" else -c))
                else:
                    forward(None)
            elif opc == "SUBPIECE" and idx == 0:
                if _const(ins[1]) == 0 and out:
                    obs["narrowed"].append(out[1])
            elif opc.startswith("FLOAT_") and opc not in ("FLOAT_NAN",):
                obs["float"] += 1
            elif opc == "INT2FLOAT":
                obs["int2float"] += 1
                obs["arith"].append(opc)
            elif opc in ("CALL", "CALLIND"):
                if idx == 0 and opc == "CALLIND":
                    obs["callind"] += 1
                elif idx >= 1:
                    tgt = ins[0][2] if opc == "CALL" and ins and ins[0] else None
                    obs["calls"].append((tgt, idx - 1))
            elif opc == "RETURN" and idx >= 1:
                obs["returned"] += 1
            if opc in SIGNED_OPS:
                obs["signed"] += 1
            if opc in UNSIGNED_OPS:
                obs["unsigned"] += 1
            if opc in NON_POINTER_ARITH:
                obs["arith"].append(opc)
        obs["truncated_walk"] = bool(work)
        return obs

    def param(self, ordinal):
        return self.follow(self.param_uses.get(ordinal, []))

    def output_uses(self, op_id, off=0):
        """Seeds for the value an op produces (e.g. a CALL's return value)."""
        return [(u, i, off) for u, i in self.uses.get(op_id, [])]

    def returned_value(self):
        """What produces the value(s) this function returns.

        Returns a list of (defining opcode or 'param'/'const'/'global', varnode size).
        """
        defs = {}
        for d, u, i in ((d, u, i) for d, uses in self.uses.items() for u, i in uses):
            defs[(u, i)] = d
        out = []
        for op_id, op in self.ops.items():
            if op[1] != "RETURN" or len(op[2]) < 2 or op[2][1] is None:
                continue
            vn = op[2][1]
            d = defs.get((op_id, 1))
            if d and d in self.ops:
                out.append((self.ops[d][1], vn[1], d))
            elif vn[0] == "constant":
                out.append(("const", vn[1], vn[3]))
            elif vn[0] == "address":
                out.append(("global", vn[1], vn[2]))
            else:
                out.append(("input", vn[1], None))
        return out

    def calls(self):
        """[(op_id, target_address, output varnode)] for direct calls."""
        res = []
        for op_id, op in self.ops.items():
            if op[1] == "CALL" and op[2] and op[2][0]:
                res.append((op_id, op[2][0][2], op[3]))
        return res

    def global_refs(self, lo, hi):
        """Seeds and raw accesses for a global occupying [lo, hi).

        - direct read: an 'address' varnode input in range -> the op consumes the value
        - direct write: an 'address' varnode output in range
        - address taken: a constant in range used by PTRSUB / PTRADD / COPY / CALL,
          followed as a pointer with offset = constant - lo
        """
        reads, writes, ptr_seeds = [], [], []
        for op_id, (_, opc, ins, out) in self.ops.items():
            for i, vn in enumerate(ins):
                if not vn:
                    continue
                if vn[0] == "address" and not (opc in ("CALL", "BRANCH", "CBRANCH") and i == 0):
                    a = int(vn[2], 16)
                    if lo <= a < hi:
                        reads.append((a - lo, vn[1], op_id, i))
                elif vn[0] == "constant" and vn[3] is not None and opc in ("PTRSUB", "PTRADD", "COPY", "CALL", "INT_ADD"):
                    a = int(vn[3], 16)
                    if lo <= a < hi:
                        if opc == "CALL" and i >= 1:
                            ptr_seeds.append(("arg", op_id, i))
                        else:
                            ptr_seeds.append(("ptr", op_id, a - lo))
            if out and out[0] == "address":
                a = int(out[2], 16)
                if lo <= a < hi:
                    writes.append((a - lo, out[1], op_id))
        return reads, writes, ptr_seeds
