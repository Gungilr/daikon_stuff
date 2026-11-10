"""Slot-by-slot audit of model type hints against the oracle (DWARF) hints.

Answers: for every integer-class argument where a CORRECT type changes the
tracer's output (the oracle hint's effect is applied), what did the model
predict for that argument, and what did the tracer do with it?  And the
reverse: of the arguments the model typed correctly, how many have any effect
to apply at all?

It runs the tracer verbosely once per binary with each hint directory and
reads its per-slot decisions ("hint func=... slot=... applied/all-refuted/...").
DWARF is read here for SCORING only.

Usage:
    python3 scripts/rea_eval/hint_audit.py BINS TRUTH.jsonl PROMPT_DIR VAR_PRED.jsonl \\
        ORACLE_HINT_DIR MODEL_HINT_DIR [--all] [--decomp DECOMP_DIR]
--all prints every hinted slot, not only the ones where a type has an effect.
--decomp adds a column: does the function's own code dereference the parameter
(Ghidra p-code, as saved by ghidra_decompile.py)?  "dropped" = Ghidra's
decompiler did not recover that parameter at all (the function never uses it).
"""
import collections
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from hints_from_dwarf import hint_type  # noqa: E402
from resym_check import facts_right  # noqa: E402
from resym_score import parse  # noqa: E402
from resym_to_hints import arg_index, ctype, pointee_hint  # noqa: E402
from tracer import hints as H  # noqa: E402

LINE = re.compile(r"hint func=0x([0-9a-f]+) slot=(\d+) (\S+) effect=(.*?) refuted=(.*)$")


def decisions(binary, hint_file):
    """{(func addr, slot): (status, effect text, reasons text)} from one verbose run."""
    if not os.path.exists(hint_file):
        return {}
    with tempfile.TemporaryDirectory() as d:
        p = subprocess.run([sys.executable, os.path.join(ROOT, "scripts/unicorn_dwarf.py"), binary,
                            "-o", os.path.join(d, "x.dtrace"), "--start-func", "main",
                            "--tier", "10", "--infer-unobserved-fields",
                            "--poison-uninitialized", "--type-hints", hint_file, "-v"],
                           capture_output=True, text=True)
    out = {}
    for line in (p.stdout + p.stderr).splitlines():
        m = LINE.search(line)
        if m:
            out[(int(m.group(1), 16), int(m.group(2)))] = (m.group(3), m.group(4), m.group(5))
    return out


def eff_of_truth(t):
    h = hint_type(t)
    return H.effect(h) if h else None


def eff_of_model(tstr):
    ct = ctype(tstr)
    if not ct or ct[0] != "ptr":
        return None
    return H.effect({"kind": "pointer", "pointee": pointee_hint(ct[1], {})})


def short(e):
    if e is None:
        return "-"
    if e[0] == "string":
        return "string"
    return f"{e[2]}{e[1] * 8}[]"


def main(argv):
    show_all = "--all" in argv
    decomp = argv[argv.index("--decomp") + 1] if "--decomp" in argv else None
    a = [x for x in argv[1:] if not x.startswith("--") and x != decomp]
    bins, truth_path, pdir, pred_path, odir, mdir = a[:6]
    truth = {}
    for line in open(truth_path):
        t = json.loads(line)
        truth[os.path.basename(t["binary"])[:-4]] = {int(f["addr"], 16): f for f in t["functions"]}
    prompts = collections.defaultdict(dict)
    for line in open(os.path.join(pdir, "var_prompts.jsonl")):
        r = json.loads(line)
        prompts[r["bin"]][int(r["addr"], 16)] = r
    preds = {}
    for line in open(pred_path):
        r = json.loads(line)
        preds[r["funname"]] = parse(r["predict"])

    C = collections.Counter()
    rows = []
    for name in sorted(truth):
        exe = os.path.join(bins, name + ".exe")
        if not os.path.exists(exe):
            continue
        B = None
        if decomp and os.path.exists(os.path.join(decomp, name + ".json")):
            from check import Binary
            B = Binary(json.load(open(os.path.join(decomp, name + ".json"))))
        dec_o = decisions(exe, os.path.join(odir, name + ".hints.json"))
        dec_m = decisions(exe, os.path.join(mdir, name + ".hints.json"))
        for addr, f in sorted(truth[name].items()):
            ints = [p for p in f["params"] if p["type"].get("kind") != "float"]
            pr = prompts[name].get(addr)
            model = {}                      # slot -> predicted type string
            ghidra_ord = {}                 # slot -> Ghidra parameter ordinal
            if pr:
                pred = preds.get(pr["funname"], {})
                for o, n, _t, _gt in pr["params"]:
                    k = arg_index(pr["params"], o)
                    if k is not None:
                        ghidra_ord[1 + k] = o
                    if k is not None and n in pred:
                        model[1 + k] = pred[n][1]
            for k, p in enumerate(ints[:6]):
                slot = 1 + k
                if (addr, slot) not in dec_o:
                    continue                # the run never sampled this function
                C["slots"] += 1
                o_status, o_eff, o_why = dec_o[(addr, slot)]
                te = eff_of_truth(p["type"])
                mt = model.get(slot)
                m_status, m_eff, m_why = dec_m.get((addr, slot), ("(no hint)", "", ""))
                if B is None:
                    deref = "?"
                elif slot not in ghidra_ord:
                    deref = "dropped"
                else:
                    deref = "yes" if B.param_obs(hex(addr), ghidra_ord[slot])["derefs"] else "no"
                right = mt is not None and facts_right(mt, p["type"])
                me = eff_of_model(mt) if mt else None
                C["model asked"] += mt is not None
                C["model facts right"] += right
                if right:
                    C["right, and the type has an effect"] += te is not None
                    C["right, no effect to apply (scalar / struct pointer / void*)"] += te is None
                if o_status == "applied":
                    C["oracle applied"] += 1
                    C[f"oracle applied: code derefs the parameter = {deref}"] += 1
                    if me == te:
                        C[f"   ...and model predicts the same effect (deref {deref})"] += 1
                    C["oracle applied: model not asked"] += mt is None
                    C["oracle applied: model predicts the same effect"] += me == te
                    C["oracle applied: model hint applied with the same effect"] += (
                        m_status == "applied" and me == te)
                if m_status == "applied":
                    C["model applied"] += 1
                    C["model applied, same effect as truth"] += me == te
                    C["model applied, truth has NO such effect"] += te is None
                    C["model applied, truth has a different effect"] += te is not None and me != te
                if show_all or o_status == "applied" or me is not None or m_status == "applied":
                    rows.append((name, f["name"], p["name"], p["type"]["c"], short(te),
                                 f"{o_status}" + (f" {o_why}" if o_status == "all-refuted" else ""),
                                 deref, mt or "(not asked)", short(me),
                                 m_status + (f" {m_why}" if m_status == "all-refuted" else "")))
    print(f"{'binary':18s} {'function':22s} {'param':12s} {'truth type':22s} {'effect':9s} "
          f"{'oracle hint':28s} {'derefs':7s} | {'model type':22s} {'effect':9s} model hint")
    for r in rows:
        print(f"{r[0]:18s} {r[1]:22s} {r[2]:12s} {r[3]:22s} {r[4]:9s} {r[5]:28s} {r[6]:7s} | "
              f"{r[7]:22s} {r[8]:9s} {r[9]}")
    print()
    for k, v in C.items():
        print(f"{v:5d}  {k}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
