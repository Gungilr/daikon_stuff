"""Does the Ghidra -> IDA-style conversion (ghidra_to_resym.py) cost ReSym its accuracy?

A self-test of the MODEL-INPUT side of the pipeline, on ReSym's own test set,
where each function has (a) the authors' IDA prompt, (b) ground-truth labels and
(c) the authors' published predictions. The same functions are decompiled with
Ghidra from the stripped binary, converted with ghidra_to_resym.py, and asked
about their parameters. Three answers are then scored on the same parameters:

    authors   their predictions (IDA code, all variables asked)
    ida       our local run on the IDA code, PARAMETERS ONLY asked (controls for
              the shorter question our pipeline uses)
    ghidra    our local run on the converted Ghidra code, parameters only

Steps:
    select  TEST.jsonl RAW.zip OUT [--funcs 80] [--seed 0]
            pick small test binaries, extract them, decompile the selected
            functions with Ghidra through REA -> OUT/decomp, OUT/selection.jsonl,
            OUT/ida_prompts.jsonl
    (then)  ghidra_to_resym.py OUT/decomp OUT/prompts
            resym_infer.py OUT/prompts/var_prompts.jsonl OUT/ghidra_pred.jsonl MODEL TOK --n 100000
            resym_infer.py OUT/ida_prompts.jsonl        OUT/ida_pred.jsonl    MODEL TOK --n 100000
    score   OUT AUTHORS_PRED.jsonl
"""
import collections
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from resym_check import ida_signature  # noqa: E402
from resym_score import category, norm, parse  # noqa: E402

MAX_INPUT_CHARS = 5000
MAX_PER_BIN = 10
MAX_BIN_BYTES = 400_000


def _opt(argv, name, default):
    return type(default)(argv[argv.index(name) + 1]) if name in argv else default


def select(argv):
    test_path, zip_path, out = argv[2:5]
    want = _opt(argv, "--funcs", 80)
    seed = _opt(argv, "--seed", 0)
    os.makedirs(os.path.join(out, "decomp"), exist_ok=True)
    z = zipfile.ZipFile(zip_path)
    sizes = {os.path.basename(i.filename): i for i in z.infolist()
             if "/bin/" in i.filename and not i.filename.startswith("__MACOSX")
             and not i.filename.endswith("/")}
    by_bin = collections.defaultdict(list)
    for idx, line in enumerate(open(test_path)):
        d = json.loads(line)
        addr, n, has_float = ida_signature(d["input"])
        if not addr or not n or has_float or len(d["input"]) > MAX_INPUT_CHARS:
            continue
        lab = parse(d["output"])
        if not any(f"a{i + 1}" in lab and lab[f"a{i + 1}"][1].strip() != "-" for i in range(n)):
            continue
        b = d.get("bin")
        if b in sizes and sizes[b].file_size <= MAX_BIN_BYTES:
            by_bin[b].append({"idx": idx, "bin": b, "addr": addr, "n_params": n,
                              "input": d["input"], "output": d["output"]})
    rng = random.Random(seed)
    bins = sorted(b for b, v in by_bin.items() if len(v) >= 3)
    rng.shuffle(bins)
    chosen = []
    for b in bins:
        ents = by_bin[b]
        rng.shuffle(ents)
        chosen += ents[:MAX_PER_BIN]
        if len(chosen) >= want:
            break
    from mcp_client import ReaMcp
    from collect_pcode import _slim
    done = 0
    for b in sorted({e["bin"] for e in chosen}):
        outp = os.path.join(out, "decomp", b + ".json")
        if os.path.exists(outp):
            continue
        rec = {"binary": b, "procedures": {}, "functions": {}, "errors": []}
        with tempfile.TemporaryDirectory() as d:
            raw = os.path.join(d, b)
            with z.open(sizes[b]) as src, open(raw, "wb") as dst:
                shutil.copyfileobj(src, dst)
            subprocess.run(["strip", "--strip-all", raw], check=True)
            c = ReaMcp(env={"REA_ANALYSIS_PROVIDER": "ghidra"})
            try:
                c.call("open_binary", {"path": raw})
                for e in chosen:
                    if e["bin"] != b:
                        continue
                    try:
                        rec["functions"][e["addr"]] = _slim(
                            c.call("analyze_function", {"procedure": e["addr"]}))
                    except Exception as ex:
                        rec["errors"].append(f"{e['addr']}: {ex}")
            finally:
                c.close()
        json.dump(rec, open(outp, "w"))
        done += 1
        print(f"{b[:16]}  functions {len(rec['functions'])}  errors {len(rec['errors'])}", flush=True)
    with open(os.path.join(out, "selection.jsonl"), "w") as fh, \
            open(os.path.join(out, "ida_prompts.jsonl"), "w") as ip:
        for e in chosen:
            fh.write(json.dumps(e) + "\n")
            # The authors' prompt with the question cut down to the parameters.
            head, code = e["input"].split("\n", 1)
            names = ", ".join(f"`a{i + 1}`" for i in range(e["n_params"]))
            ip.write(json.dumps({
                "bin": e["bin"], "addr": e["addr"], "funname": f"{e['bin']}:{e['addr']}",
                "input": f"What are the original name and data type of variables {names}?\n{code}",
                "output": "a1:", "n_answers": e["n_params"]}) + "\n")
    print(f"selected {len(chosen)} functions from {len({e['bin'] for e in chosen})} binaries")
    return 0


def score(argv):
    out, authors_path = argv[2:4]
    sel = [json.loads(l) for l in open(os.path.join(out, "selection.jsonl"))]
    want = {e["idx"] for e in sel}
    authors = {}
    for i, line in enumerate(open(authors_path)):
        if i in want:
            authors[i] = parse(json.loads(line)["predict"])

    def load(p):
        return {json.loads(l)["funname"]: parse(json.loads(l)["predict"])
                for l in open(p)} if os.path.exists(p) else {}
    ida = load(os.path.join(out, "ida_pred.jsonl"))
    ghi = load(os.path.join(out, "ghidra_pred.jsonl"))
    gprompts = {}
    pp = os.path.join(out, "prompts", "var_prompts.jsonl")
    if os.path.exists(pp):
        for l in open(pp):
            r = json.loads(l)
            gprompts[r["funname"]] = r
    C = collections.Counter()
    ex = []
    for e in sel:
        key = f"{e['bin']}:{e['addr']}"
        lab = parse(e["output"])
        gp = gprompts.get(key)
        C["functions"] += 1
        if gp is None:
            C["functions: Ghidra gave no parameters / no prompt"] += 1
            continue
        if len(gp["params"]) != e["n_params"]:
            C["functions: Ghidra parameter count differs from IDA's"] += 1
            continue
        if key not in ghi or key not in ida:
            C["functions: prediction missing"] += 1
            continue
        C["functions compared"] += 1
        for i in range(e["n_params"]):
            v = f"a{i + 1}"
            if v not in lab or lab[v][1].strip() == "-":
                continue
            t = lab[v][1]
            C["params"] += 1
            for name, pred in (("authors", authors.get(e["idx"], {})), ("ida", ida[key]),
                               ("ghidra", ghi[key])):
                if v not in pred:
                    C[f"{name}: no answer"] += 1
                    continue
                C[f"{name}: exact"] += norm(pred[v][1]) == norm(t)
                C[f"{name}: category"] += category(pred[v][1]) == category(t)
            if v in ida[key] and v in ghi[key] and len(ex) < 14 \
                    and norm(ida[key][v][1]) != norm(ghi[key][v][1]):
                ex.append(f"truth {t!r:28s} ida {ida[key][v][1]!r:28s} ghidra {ghi[key][v][1]!r}")
    n = C["params"] or 1
    for k in ("functions", "functions: Ghidra gave no parameters / no prompt",
              "functions: Ghidra parameter count differs from IDA's",
              "functions: prediction missing", "functions compared", "params"):
        print(f"{C[k]:5d}  {k}")
    print(f"\n{'':34s}{'exact':>8s}{'category':>10s}")
    for name, label in (("authors", "authors (IDA, all variables)"),
                        ("ida", "local, IDA code, params only"),
                        ("ghidra", "local, Ghidra converted, params")):
        print(f"{label:34s}{100 * C[name + ': exact'] / n:7.1f}%{100 * C[name + ': category'] / n:9.1f}%"
              f"   (no answer {C[name + ': no answer']})")
    if ex:
        print("\nwhere the two local runs disagree:")
        for x in ex:
            print("  " + x)
    return 0


if __name__ == "__main__":
    sys.exit({"select": select, "score": score}[sys.argv[1]](sys.argv))
