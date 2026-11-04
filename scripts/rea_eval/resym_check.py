"""Filter ReSym's predicted PARAMETER types with evidence from the binary.

ReSym (VarDecoder) always answers.  This asks: if every predicted type that
the binary's own code contradicts is dropped, how good are the types kept?

Evidence is the Stage 1 checker's (check.py): Ghidra high p-code of the
stripped binary, walked forward from each parameter (dereferences, arithmetic,
signed/unsigned ops, float ops, libc call arguments).  Ghidra's own TYPE guess
is never used - only what the instructions do with the value.

Matching: ReSym's prompts are IDA pseudocode whose signature names the function
`sub_<ADDR>(T1 a1, T2 a2, ...)`; parameter aN is ordinal N-1 both in DWARF and
in Ghidra's prototype.  A function is skipped when Ghidra's parameter count
differs from IDA's, or when IDA's signature has float/double parameters
(passed in xmm registers, so the ordinals may then name different values).

Truth: DWARF (sample/truth.jsonl, from ground_truth.py) for the kind/sign/
pointee facts; ReSym's own label for the exact-string score.

Usage:
    python3 scripts/rea_eval/resym_check.py PRED.jsonl TRUTH.jsonl PCODE_DIR \
        [--traces TRACE_DIR] [--examples N]
TRACE_DIR: the tracer's <sha256>.dtrace for each stripped binary (its ENTER
declarations type each integer-register argument void* / int from the values seen).
PRED.jsonl: the authors' vardecoder_pred.jsonl (bin / input / output / predict).
"""
import collections
import gzip
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check import Binary, check, correct, pct  # noqa: E402
from score import truth_facts  # noqa: E402
from resym_score import INT_W, INT_WORDS, norm, parse  # noqa: E402

UNSIGNED_BASES = {"_BYTE", "_WORD", "_DWORD", "_QWORD", "size_t", "_BOOL8", "bool"}
CHAR_BASES = {"char", "__int8", "_BYTE", "int8_t", "uint8_t"}


def _int_facts(base):
    """(size, signed) for an integer base type name, else None."""
    words = base.split()
    if base in INT_W:
        signed = not (base.startswith(("uint", "u_")) or base in UNSIGNED_BASES)
        if base.startswith("unsigned"):
            signed = False
        return INT_W[base], signed
    if words and set(words) <= INT_WORDS:
        unsigned = "unsigned" in words
        if "_Bool" in words or "bool" in words or "char" in words:
            w = 1
        elif "short" in words:
            w = 2
        elif "long" in words:
            w = 8
        else:
            w = 4
        return w, not unsigned
    m = re.fullmatch(r"u?int(8|16|32|64)(_t)?|__u?int(8|16|32|64)", base)
    if m:
        return int(m.group(1) or m.group(3)) // 8, "u" not in base.split("int")[0]
    return None


def c_claim(t):
    """A C type string -> the checker's claim dict (kind/size/signed/pointee/pointee_size)."""
    t = norm(t)
    if "(" in t and "*" in t:
        return {"kind": "pointer", "size": 8, "pointee": "func"}
    t = re.sub(r"\[\d*\]", "*", t)
    stars = t.count("*")
    base = re.sub(r"^(struct|union|enum) ", "", t.replace("*", "").strip())
    if stars:
        c = {"kind": "pointer", "size": 8}
        if stars >= 2:
            c["pointee"] = "pointer"
        elif base == "void":
            c["pointee"] = "void"
        elif base in ("float", "double", "long double"):
            c["pointee"], c["pointee_size"] = "float", {"float": 4}.get(base, 8)
        elif _int_facts(base):
            sz, _ = _int_facts(base)
            c["pointee"] = "char" if sz == 1 or base in CHAR_BASES else "int"
            c["pointee_size"] = sz
        else:
            c["pointee"] = "struct"     # a named pointee: almost always a struct/typedef'd struct
        return c
    if base == "void":
        return {"kind": "void"}
    if base in ("float", "double", "long double"):
        return {"kind": "float", "size": {"float": 4}.get(base, 8)}
    if base in ("_Bool", "bool", "_BOOL8"):
        return {"kind": "bool", "size": INT_W.get(base, 1)}
    f = _int_facts(base)
    if f:
        return {"kind": "int", "size": f[0], "signed": f[1]}
    return {"kind": "named"}


def for_check(claim):
    """check() applies R1 to scalar kinds only; a non-pointer named type
    (struct by value, enum, int typedef) is a scalar claim for R1."""
    return dict(claim, kind="enum") if claim["kind"] == "named" else claim


def ida_signature(inp):
    m = re.search(r"\bsub_([0-9A-Fa-f]+)\s*\(([^)]*)\)", inp)
    if not m:
        return None, None, False
    params = [p for p in m.group(2).split(",") if p.strip() and p.strip() != "void"]
    has_float = any(re.search(r"\b(float|double)\b", p) and "*" not in p for p in params)
    return "0x" + m.group(1).lower(), len(params), has_float


def load_traces(d):
    """{binary: {function addr: {raw arg index: tracer dec-type}}} from the
    tracer's .dtrace declarations (ENTER program points)."""
    out = {}
    for f in os.listdir(d) if d else []:
        if not f.endswith(".dtrace"):
            continue
        fn = out.setdefault(f[:-len(".dtrace")], {})
        ppt = var = None
        for line in open(os.path.join(d, f)):
            line = line.rstrip("\n")
            if line.startswith("ppt "):
                m = re.match(r"ppt \.\.sub_(0x[0-9a-f]+)\(\):::ENTER$", line)
                ppt = m.group(1) if m else None
            elif line.startswith("variable "):
                var = line.split()[1]
            elif ppt and var and line.strip().startswith("dec-type") and re.fullmatch(r"arg\d+", var):
                fn.setdefault(ppt, {})[int(var[3:])] = line.split(None, 1)[1]
            elif not line.strip():
                ppt = var = None if not line.startswith(" ") else ppt
    return out


def trace_check(claim, ttype):
    """The tracer types an argument void* when its value pointed into mapped
    memory at a call it observed, else int.  Only the first is used to reject:
    `int` is no proof of a scalar - a NULL or a tagged pointer reads as one
    (on this corpus that rule rejected 41 right answers to catch 23 wrong)."""
    if ttype is None or claim["kind"] in ("void",):
        return "NO-EVIDENCE", None
    if ttype == "void*" and claim["kind"] != "pointer":
        return "FAIL", "T-ptr"
    if ttype == "int" and claim["kind"] == "pointer":
        return "NO-EVIDENCE", None
    return "PASS", None


def main(argv):
    pred_path, truth_path, pcode_dir = argv[1:4]
    n_ex = int(argv[argv.index("--examples") + 1]) if "--examples" in argv else 0
    traces = load_traces(argv[argv.index("--traces") + 1]) if "--traces" in argv else {}
    T = collections.Counter()
    truth = {}
    for line in open(truth_path):
        t = json.loads(line)
        truth[os.path.basename(t["binary"])] = {f["addr"]: f for f in t["functions"]}
    preds = collections.defaultdict(list)
    for line in open(pred_path):
        d = json.loads(line)
        if d.get("bin") in truth:
            preds[d["bin"]].append(d)

    C = collections.Counter()
    rules = collections.Counter()
    ex = collections.defaultdict(list)
    for h, entries in sorted(preds.items()):
        pp = os.path.join(pcode_dir, h + ".json.gz")
        if not os.path.exists(pp):
            continue
        B = Binary(json.load(gzip.open(pp, "rt")))
        raw = json.load(gzip.open(pp, "rt"))["functions"]
        for d in entries:
            addr, n_ida, has_float = ida_signature(d["input"])
            tf = truth[h].get(addr) if addr else None
            if tf is None:
                C["fn_unmatched"] += 1
                continue
            if has_float:
                # float args go in xmm registers; IDA's and Ghidra's ordinals
                # then need not name the same value
                C["fn_float_params"] += 1
                continue
            g = raw.get(addr)
            if not g or "ops" not in g or len(g.get("parameters", [])) != n_ida:
                C["fn_param_count_differs"] += 1
                continue
            C["functions"] += 1
            lab, pr = parse(d["output"]), parse(d["predict"])
            for tp in tf["params"]:
                v = f"a{tp['ordinal'] + 1}"
                if v not in lab or lab[v][1].strip() == "-" or tp["ordinal"] >= n_ida:
                    continue
                true = truth_facts(tp["type"])
                C["params"] += 1
                if v not in pr:
                    C["no_answer"] += 1
                    continue
                ptype = pr[v][1]
                claim = c_claim(ptype)
                ok = correct(claim, true) if claim["kind"] != "named" else true["kind"] in ("struct", "union", "int")
                exact = norm(ptype) == norm(lab[v][1])
                ev = B.evidence(B.param_obs(addr, tp["ordinal"]))
                verdict, failed = check(for_check(claim), ev)
                C["answered"] += 1
                C["ok"] += ok
                C["exact"] += exact
                C[f"{verdict}"] += 1
                C[f"{verdict}:ok"] += ok
                C[f"{verdict}:exact"] += exact
                ttype = traces.get(h, {}).get(addr, {}).get(tp["ordinal"])
                if h in traces and addr in traces[h]:
                    tv, trule = trace_check(claim, ttype)
                    T["n"] += 1
                    T["ok"] += ok
                    T["exact"] += exact
                    T[tv] += 1
                    T[f"{tv}:ok"] += ok
                    T[f"{tv}:exact"] += exact
                    T[f"static:{verdict}"] += 1
                    T[f"static:{verdict}:ok"] += ok
                    both = "FAIL" if "FAIL" in (tv, verdict) else ("PASS" if "PASS" in (tv, verdict) else "NO-EVIDENCE")
                    T[f"both:{both}"] += 1
                    T[f"both:{both}:ok"] += ok
                    if trule:
                        rules[(trule, ok)] += 1
                        key = "trace_false_reject" if ok else "trace_catch"
                        if len(ex[key]) < n_ex:
                            ex[key].append(f"{d.get('funname')} {v}: ReSym {ptype!r}, truth {tp['type']['c']!r}, "
                                           f"tracer {ttype}")
                if verdict == "FAIL":
                    for r in failed:
                        rules[(r, ok)] += 1
                    key = "false_reject" if ok else "catch"
                    if len(ex[key]) < n_ex:
                        ex[key].append(f"{d.get('funname')} {v}: ReSym {ptype!r}, truth {tp['type']['c']!r}, "
                                       f"rules {failed}, evidence ptr={ev['ptr'][:2]} nonptr={ev['nonptr'][:2]}")

    n = C["answered"]
    wrong = n - C["ok"]
    kept = n - C["FAIL"]
    kept_ok = C["ok"] - C["FAIL:ok"]
    kept_exact = C["exact"] - C["FAIL:exact"]
    print(f"functions matched {C['functions']}  (address not in DWARF {C['fn_unmatched']}, "
          f"Ghidra/IDA parameter count differs {C['fn_param_count_differs']}, "
          f"float parameters {C['fn_float_params']})")
    print(f"parameters with a ReSym label {C['params']}, answered {n} (no answer {C['no_answer']})")
    print()
    print("                         kept     facts right   exact string")
    print(f"ReSym alone            {n:6d}     {pct(C['ok'], n)}        {pct(C['exact'], n)}")
    print(f"ReSym, contradicted    {kept:6d}     {pct(kept_ok, kept)}        {pct(kept_exact, kept)}"
          f"     ({pct(kept, n)} of answers kept)")
    pe = C["PASS"]
    print(f"ReSym, evidence agrees {pe:6d}     {pct(C['PASS:ok'], pe)}        {pct(C['PASS:exact'], pe)}"
          f"     ({pct(pe, n)} of answers kept)")
    print()
    print(f"verdicts: PASS {C['PASS']}  FAIL {C['FAIL']}  NO-EVIDENCE {C['NO-EVIDENCE']}")
    print(f"wrong-facts answers caught  {pct(C['FAIL'] - C['FAIL:ok'], wrong)}  ({C['FAIL'] - C['FAIL:ok']} of {wrong})")
    print(f"right answers rejected      {pct(C['FAIL:ok'], C['ok'])}  ({C['FAIL:ok']} of {C['ok']})")
    print(f"confident wrong, of all answers: before {pct(wrong, n)}  after dropping contradicted "
          f"{pct(kept - kept_ok, n)}")
    print("per rule (catches / false rejects): " + ", ".join(
        f"{r} {rules[(r, False)]}/{rules[(r, True)]}" for r in sorted({r for r, _ in rules})))
    if T["n"]:
        n = T["n"]
        print(f"\n== functions the tracer reached: {n} ReSym parameter answers")

        def row(name, verdicts, prefix=""):
            kept = n - T[f"{prefix}FAIL"]
            kept_ok = T["ok"] - T[f"{prefix}FAIL:ok"]
            pe = T[f"{prefix}PASS"]
            print(f"  {name:34s} drop contradicted: kept {kept:5d} ({pct(kept, n)}), facts right {pct(kept_ok, kept)}"
                  f" | keep only agreed: kept {pe:5d} ({pct(pe, n)}), facts right {pct(T[f'{prefix}PASS:ok'], pe)}")
        print(f"  ReSym alone: facts right {pct(T['ok'], n)}, exact string {pct(T['exact'], n)}")
        row("static evidence", None, "static:")
        row("trace evidence", None, "")
        row("static + trace", None, "both:")
        print(f"  trace verdicts: PASS {T['PASS']}  FAIL {T['FAIL']}  NO-EVIDENCE {T['NO-EVIDENCE']}; "
              f"trace caught {T['FAIL'] - T['FAIL:ok']} of {n - T['ok']} wrong, rejected {T['FAIL:ok']} of {T['ok']} right")
    for k, v in ex.items():
        print(f"\n{k}:")
        for x in v:
            print("  " + x)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
