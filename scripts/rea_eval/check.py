"""Stage 1 type checker: does Ghidra's claimed type explain what the code does?

For every parameter, return value and global, build EVIDENCE from the stripped
binary's p-code (observe.py) plus libc prototypes, then apply rules to
Ghidra's claim (from collect.py's rea_out):

  R1 pointer-ness   claimed non-pointer but used as a pointer (dereferenced, called
                    through, passed where libc wants a pointer) - or the reverse
  R3 signedness     claimed signed/unsigned but only the opposite kind of ops
  R4 float          claimed integer but only float ops - or the reverse
  R5 pointee width  claimed T* but every dereference is a different width than T
  R6 pointee struct claimed pointer-to-scalar but derefs at >=2 offsets with >=2 widths
                    (globals: claimed scalar but accessed at >=2 offsets or by index)
  R7 global object  claimed the global HOLDS a pointer, but code only takes its address
                    (an array or struct object, never loaded as a pointer value)
  (R2 width and R8 void-return are not implemented: Ghidra's high p-code is
   sized and shaped by its own prototype, so evidence for them would be circular.)

Each claim gets PASS, FAIL(rules) or NO-EVIDENCE; abstentions (undefinedN) get
no verdict but still get an evidence-based PROPOSAL (pointer / scalar / float).

Scoring against the DWARF answer key happens only in the report section.

Usage:
    python3 scripts/rea_eval/check.py TRUTH.jsonl REA_OUT_DIR PCODE_DIR [--examples N]
"""
import collections
import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from observe import Function, new_obs  # noqa: E402
from libc_protos import lookup, POINTER_CLASSES  # noqa: E402
from score import ghidra_type, truth_facts, same_kind  # noqa: E402

FLOAT_OPCODES_PREFIX = "FLOAT_"


class Binary:
    def __init__(self, pcode):
        self.procs = pcode.get("procedures", {})
        self.funcs = {a: Function(r) for a, r in pcode.get("functions", {}).items() if "ops" in r}
        self._param_cache = {}
        self._callsites = None

    def proc_name(self, addr):
        p = self.procs.get(addr) or {}
        return p.get("name")

    def param_obs(self, faddr, ordinal):
        key = (faddr, ordinal)
        if key not in self._param_cache:
            f = self.funcs.get(faddr)
            self._param_cache[key] = f.param(ordinal) if f else new_obs()
        return self._param_cache[key]

    def callsites(self):
        """target address -> [(caller Function, call op id)]"""
        if self._callsites is None:
            self._callsites = collections.defaultdict(list)
            for f in self.funcs.values():
                for op_id, tgt, out in f.calls():
                    self._callsites[tgt].append((f, op_id))
        return self._callsites

    # ------------------------------------------------------------ evidence
    def evidence(self, obs, depth=0):
        ev = {"ptr": [], "nonptr": [], "float": [], "int": [], "signed": 0, "unsigned": 0,
              "deref_sizes": set(), "deref_offsets": set(), "indexed": bool(obs["indexed"]),
              "char": False}
        if obs["derefs"]:
            ev["ptr"].append("dereferenced")
            for off, size, _ in obs["derefs"]:
                if size:
                    ev["deref_sizes"].add(size)
                if off is not None:
                    ev["deref_offsets"].add((off, size))
        if obs["callind"]:
            ev["ptr"].append("called through")
        if obs["arith"]:
            ev["nonptr"].append("arith:" + ",".join(sorted(set(obs["arith"]))))
        if obs["float"]:
            ev["float"].append("float ops")
        if obs["int2float"]:
            ev["int"].append("int2float")
        ev["signed"] += obs["signed"]
        ev["unsigned"] += obs["unsigned"]
        if obs["signed"]:
            ev["nonptr"].append("signed ops")
            ev["int"].append("signed ops")
        if obs["unsigned"]:
            ev["int"].append("unsigned ops")
        for tgt, argi in obs["calls"]:
            proto = lookup(self.proc_name(tgt))
            if proto:
                ret, args, variadic = proto
                if argi < len(args):
                    c = args[argi]
                    name = self.proc_name(tgt).split("::")[-1]
                    if c in POINTER_CLASSES:
                        ev["ptr"].append(f"arg{argi} of {name}")
                        if c == "s":
                            ev["char"] = True
                    elif c == "d":
                        ev["float"].append(f"arg{argi} of {name}")
                    elif c in "iul":
                        ev["nonptr"].append(f"arg{argi} of {name}")
                        ev["int"].append(f"arg{argi} of {name}")
                        if c in "il":
                            ev["signed"] += 1
                        else:
                            ev["unsigned"] += 1
            elif depth == 0 and tgt in self.funcs:
                sub = self.evidence(self.param_obs(tgt, argi), depth=1)
                for k in ("ptr", "nonptr", "float", "int"):
                    ev[k] += [f"{x} (via callee {tgt})" for x in sub[k]]
                ev["signed"] += sub["signed"]
                ev["unsigned"] += sub["unsigned"]
                ev["char"] |= sub["char"]
                ev["deref_sizes"] |= sub["deref_sizes"]
        if ev["deref_sizes"] == {1}:
            ev["char"] = True
        return ev

    def return_evidence(self, faddr):
        ev = {"ptr": [], "nonptr": [], "float": [], "int": [], "signed": 0, "unsigned": 0,
              "deref_sizes": set(), "deref_offsets": set(), "indexed": False, "char": False,
              "used_by_callers": 0}
        f = self.funcs.get(faddr)
        if f:
            for opc, size, extra in f.returned_value():
                if opc in ("PTRSUB", "PTRADD"):
                    ev["ptr"].append("returns address arithmetic")
                elif opc == "INT_SEXT":
                    ev["signed"] += 1
                    ev["int"].append("returns sign-extended")
                elif opc == "INT_ZEXT":
                    ev["unsigned"] += 1
                    ev["int"].append("returns zero-extended")
                elif opc.startswith(FLOAT_OPCODES_PREFIX) or opc == "INT2FLOAT":
                    ev["float"].append("returns float op")
                elif opc in ("INT_MULT", "INT_SDIV", "INT_DIV", "INT_SREM", "INT_REM", "INT_SRIGHT"):
                    ev["nonptr"].append(f"returns {opc}")
                elif opc in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "BOOL_NEGATE",
                             "BOOL_AND", "BOOL_OR", "INT_SLESSEQUAL", "INT_LESSEQUAL"):
                    ev["nonptr"].append("returns a comparison")
                elif opc == "CALL" and extra in f.ops:
                    tgt = f.ops[extra][2][0][2] if f.ops[extra][2] and f.ops[extra][2][0] else None
                    proto = lookup(self.proc_name(tgt))
                    if proto:
                        c = proto[0]
                        name = self.proc_name(tgt).split("::")[-1]
                        if c in POINTER_CLASSES:
                            ev["ptr"].append(f"returns {name}()")
                        elif c in "iul":
                            ev["nonptr"].append(f"returns {name}()")
                        elif c == "d":
                            ev["float"].append(f"returns {name}()")
        # how callers use the result
        for caller, op_id in self.callsites().get(faddr, []):
            seeds = caller.output_uses(op_id)
            if not seeds:
                continue
            ev["used_by_callers"] += 1
            sub = self.evidence(caller.follow(seeds), depth=1)
            for k in ("ptr", "nonptr", "float", "int"):
                ev[k] += [f"caller: {x}" for x in sub[k]]
            ev["signed"] += sub["signed"]
            ev["unsigned"] += sub["unsigned"]
            ev["deref_sizes"] |= sub["deref_sizes"]
            ev["char"] |= sub["char"]
        return ev

    def global_evidence(self, addr, size):
        lo = int(addr, 16)
        hi = lo + max(int(size or 1), 1)
        ev = {"ptr": [], "nonptr": [], "float": [], "int": [], "signed": 0, "unsigned": 0,
              "deref_sizes": set(), "deref_offsets": set(), "indexed": False, "char": False,
              "accesses": set(), "reads": set(), "addr_taken": 0, "refs": 0}
        for f in self.funcs.values():
            reads, writes, ptr_seeds = f.global_refs(lo, hi)
            for off, sz, op_id, i in reads:
                ev["refs"] += 1
                ev["accesses"].add((off, sz))
                ev["reads"].add((off, sz))
                sub = self.evidence(f.follow([(op_id, i)]), depth=1)
                for k in ("ptr", "nonptr", "float", "int"):
                    ev[k] += sub[k]
                ev["signed"] += sub["signed"]
                ev["unsigned"] += sub["unsigned"]
                ev["deref_sizes"] |= sub["deref_sizes"]
            for off, sz, op_id in writes:
                ev["refs"] += 1
                ev["accesses"].add((off, sz))
                if f.ops[op_id][1].startswith(FLOAT_OPCODES_PREFIX):
                    ev["float"].append("written by float op")
            for kind, op_id, x in ptr_seeds:
                ev["refs"] += 1
                ev["addr_taken"] += 1
                if kind == "ptr":
                    o = f.follow(f.output_uses(op_id, x))
                    for off, sz, _ in o["derefs"]:
                        if off is not None and sz:
                            ev["accesses"].add((off, sz))
                    if o["indexed"]:
                        ev["indexed"] = True
                    if o["float"]:
                        ev["float"].append("element float ops")
        return ev


# ---------------------------------------------------------------- rules
def proposal(ev):
    p, n = bool(ev["ptr"]), bool(ev["nonptr"])
    if ev["float"] and not ev["int"] and not p:
        return "float"
    if p and not n:
        return "pointer"
    if n and not p:
        return "scalar"
    return None


def check(claim, ev, is_global=False):
    """claim: ghidra_type() dict. Returns (verdict, [failed rules])."""
    k = claim["kind"]
    if k == "abstain":
        return "ABSTAIN", []
    fails = []
    p, n = bool(ev["ptr"]), bool(ev["nonptr"])
    has_any = p or n or ev["float"] or ev["int"] or ev["signed"] or ev["unsigned"] \
        or (is_global and ev.get("accesses"))
    if k in ("int", "bool", "float", "enum") and p and not n:
        fails.append("R1")
    if k == "pointer" and n and not p:
        fails.append("R1")
    if k == "int" and claim.get("signed") is not None:
        if claim["signed"] and ev["unsigned"] and not ev["signed"]:
            fails.append("R3")
        if not claim["signed"] and ev["signed"] and not ev["unsigned"]:
            fails.append("R3")
    if k == "int" and ev["float"] and not ev["int"]:
        fails.append("R4")
    if k == "float" and ev["int"] and not ev["float"]:
        fails.append("R4")
    if k == "pointer":
        pk = claim.get("pointee")
        sizes = ev["deref_sizes"]
        psize = claim.get("pointee_size")
        if pk in ("int", "char", "float") and psize and sizes and psize not in sizes:
            fails.append("R5")
        offs = {o for o, _ in ev["deref_offsets"]}
        widths = {s for _, s in ev["deref_offsets"]}
        if pk in ("int", "char", "float") and len(offs) >= 2 and len(widths) >= 2:
            fails.append("R6")
    if is_global and k == "pointer" and ev.get("addr_taken") \
            and not any(o == 0 and sz == 8 for o, sz in ev.get("reads", ())):
        fails.append("R7")
    if is_global and k in ("int", "float"):
        offs = {o for o, _ in ev.get("accesses", ())}
        if len(offs) >= 2 or ev["indexed"]:
            fails.append("R6")
    if fails:
        return "FAIL", fails
    return ("PASS" if has_any else "NO-EVIDENCE"), []


def claim_with_pointee_size(dtype, size):
    c = ghidra_type(dtype, size)
    if c["kind"] == "pointer" and dtype:
        base = ghidra_type(dtype.rsplit("/", 1)[-1].rstrip("*").strip())
        c["pointee_size"] = base.get("size") if base["kind"] in ("int", "float") else None
    return c


def correct(pred, true):
    """kind right, and pointee/sign/size consistent where both sides state them."""
    if not same_kind(pred, true):
        return False
    if true["kind"] == "pointer" and pred.get("pointee") not in (None, "void") \
            and pred.get("pointee") != true.get("pointee"):
        return False
    if true["kind"] == "int" and pred.get("signed") is not None and true.get("signed") is not None \
            and pred["signed"] != true["signed"]:
        return False
    if pred.get("size") and true.get("size") and pred["size"] != true["size"]:
        return False
    return True


# ---------------------------------------------------------------- report
def pct(a, b):
    return f"{100.0 * a / b:5.1f}%" if b else "  n/a "


def main(argv):
    truth_path, rea_dir, pcode_dir = argv[1:4]
    n_ex = int(argv[argv.index("--examples") + 1]) if "--examples" in argv else 0
    stats = {k: collections.Counter() for k in ("param", "return", "global")}
    rule_hits = {k: collections.Counter() for k in stats}
    examples = collections.defaultdict(list)
    seen_f, seen_g = set(), set()
    nbin = 0
    for line in open(truth_path):
        t = json.loads(line)
        h = os.path.basename(t["binary"])
        rp, pp = os.path.join(rea_dir, h + ".json"), os.path.join(pcode_dir, h + ".json.gz")
        if not (os.path.exists(rp) and os.path.exists(pp)):
            continue
        nbin += 1
        rea = json.load(open(rp))
        B = Binary(json.load(gzip.open(pp, "rt")))

        def record(kind, claim, ev, true, label):
            c = stats[kind]
            c["total"] += 1
            verdict, rules = check(claim, ev, is_global=(kind == "global"))
            c[verdict] += 1
            if verdict == "ABSTAIN":
                prop = proposal(ev)
                c["abstain_proposed"] += prop is not None
                if prop:
                    tk = "pointer" if true["kind"] == "pointer" else \
                        ("float" if true["kind"] == "float" else "scalar")
                    c["abstain_proposal_ok"] += prop == tk
                return
            ok = correct(claim, true)
            c["claim_ok" if ok else "claim_wrong"] += 1
            kind_wrong = not same_kind(claim, true)
            c["kind_wrong"] += kind_wrong
            c["kind_wrong_kept"] += kind_wrong and verdict != "FAIL"
            ptr_err = true["kind"] == "pointer" and claim["kind"] in ("int", "bool")
            c["ptr_as_int"] += ptr_err
            if verdict == "FAIL":
                c["fail_on_ok" if ok else "fail_on_wrong"] += 1
                c["caught_ptr_as_int"] += ptr_err
                for r in rules:
                    rule_hits[kind][(r, "wrong" if not ok else "right")] += 1
                if ok and len(examples[(kind, "false_reject")]) < 6:
                    examples[(kind, "false_reject")].append((label, rules, ev))
                if not ok and len(examples[(kind, "catch")]) < 6:
                    examples[(kind, "catch")].append((label, rules, ev))
            elif not ok:
                c["missed_wrong"] += 1
                if len(examples[(kind, "missed")]) < 6:
                    examples[(kind, "missed")].append((label, [], ev))

        for f in t["functions"]:
            sig = (f["name"], f["return"]["c"], tuple(p["type"]["c"] for p in f["params"]))
            if sig in seen_f:
                continue
            seen_f.add(sig)
            r = rea["functions"].get(f["addr"], {})
            if not r.get("recognised") or "error" in r or f["addr"] not in B.funcs:
                continue
            tparams = [p for p in f["params"] if p["type"]["kind"] != "varargs"]
            rps = r.get("params") or []
            # a struct returned by value in memory (> 16 bytes) arrives as a hidden
            # first pointer argument, shifting every declared parameter by one
            shift = 1 if (f["return"]["kind"] in ("struct", "union")
                          and (f["return"].get("size") or 0) > 16
                          and len(rps) == len(tparams) + 1) else 0
            for i, p in enumerate(tparams):
                j = i + shift
                if j >= len(rps):
                    continue
                claim = claim_with_pointee_size(rps[j]["data_type"], rps[j].get("size_bytes"))
                ev = B.evidence(B.param_obs(f["addr"], j))
                record("param", claim, ev, truth_facts(p["type"]),
                       f"{f['name']} p{i} true={p['type']['c']} ghidra={rps[j]['data_type']}")
            ret = r.get("return") or {}
            claim = claim_with_pointee_size(ret.get("data_type"), ret.get("size_bytes"))
            if f["return"]["kind"] != "void" and claim["kind"] != "void":
                record("return", claim, B.return_evidence(f["addr"]), truth_facts(f["return"]),
                       f"{f['name']} return true={f['return']['c']} ghidra={ret.get('data_type')}")
        for g in t["globals"]:
            gsig = (g["name"], g["type"]["c"], g["type"].get("size"))
            if gsig in seen_g:
                continue
            seen_g.add(gsig)
            r = rea["globals"].get(g["addr"], {})
            if r.get("status") == "available" and r.get("kind") == "scalar":
                claim = claim_with_pointee_size(r.get("name"), r.get("size_bytes"))
            elif r.get("status") == "available" and r.get("kind") == "pointer":
                claim = ghidra_type((r.get("referenced_type") or "undefined") + " *")
            elif r.get("status") == "available" and r.get("kind") in ("struct", "array", "union"):
                claim = {"kind": r["kind"], "size": r.get("size_bytes")}
            else:
                claim = {"kind": "abstain", "size": None}
            ev = B.global_evidence(g["addr"], g["type"].get("size"))
            record("global", claim, ev, truth_facts(g["type"]),
                   f"{g['name']} true={g['type']['c']} ghidra={r.get('name') or r.get('kind')}")

    print(f"binaries checked: {nbin}")
    for kind in ("param", "return", "global"):
        c = stats[kind]
        answered = c["claim_ok"] + c["claim_wrong"]
        print(f"\n== {kind.upper()}S: {c['total']}  (Ghidra answered {answered}, abstained {c['ABSTAIN']})")
        print(f"  verdicts on answers: PASS {c['PASS']}  FAIL {c['FAIL']}  NO-EVIDENCE {c['NO-EVIDENCE']}")
        print(f"  Ghidra answers right {c['claim_ok']}  wrong {c['claim_wrong']}")
        print(f"  CATCH rate  (wrong answers flagged)   {pct(c['fail_on_wrong'], c['claim_wrong'])}")
        print(f"  FALSE REJECT (right answers flagged)  {pct(c['fail_on_ok'], c['claim_ok'])}")
        print(f"  pointer-called-integer errors caught  {pct(c['caught_ptr_as_int'], c['ptr_as_int'])}"
              f" of {c['ptr_as_int']}")
        print(f"  confident-wrong of all: before {pct(c['claim_wrong'], c['total'])}"
              f"  after filtering {pct(c['missed_wrong'], c['total'])}")
        print(f"  wrong KIND of type, of all: before {pct(c['kind_wrong'], c['total'])}"
              f"  after filtering {pct(c['kind_wrong_kept'], c['total'])}")
        print(f"  abstentions with an evidence proposal {pct(c['abstain_proposed'], c['ABSTAIN'])},"
              f" proposal right {pct(c['abstain_proposal_ok'], c['abstain_proposed'])}")
        rules = sorted({r for r, _ in rule_hits[kind]})
        for r in rules:
            print(f"    {r}: catches {rule_hits[kind][(r, 'wrong')]:6}   false rejects {rule_hits[kind][(r, 'right')]:6}")
    if n_ex:
        for (kind, what), exs in sorted(examples.items()):
            print(f"\n-- {kind} {what}")
            for label, rules, ev in exs[:n_ex]:
                short = {k: (sorted(v)[:4] if isinstance(v, (set, list)) else v)
                         for k, v in ev.items() if v and k not in ("deref_offsets",)}
                print(f"   {label}  {rules}  {short}")


if __name__ == "__main__":
    main(sys.argv)
