"""ORACLE hint files from DWARF, for the --type-hints ceiling only.

Writes one hint file per binary (scripts/tracer/hints.py format) with a single
candidate per argument: the DECLARED type. A run with these hints measures the
most --type-hints can buy with perfect types. It is a ceiling, never a result:
DWARF must not feed the tracer in any reported measurement.

Arguments are numbered as the tracer numbers them: integer-class parameters in
order (float/double parameters travel in xmm registers and are skipped).

Usage:
    python3 scripts/rea_eval/hints_from_dwarf.py TRUTH.jsonl OUT_DIR
TRUTH.jsonl: scripts/rea_eval/ground_truth.py output.
"""
import json
import os
import sys


def hint_type(t):
    """ground_truth.py type dict -> hints.py TYPE, or None."""
    k = t.get("kind")
    if k == "pointer":
        p = t.get("pointee") or {}
        pk = p.get("kind")
        if pk == "int" and p.get("char") and p.get("signed") is not False:
            pe = {"kind": "char", "size": 1}
        elif pk in ("int", "enum", "bool"):
            pe = {"kind": "int", "size": p.get("size"), "signed": p.get("signed")}
        elif pk == "float":
            pe = {"kind": "float", "size": p.get("size")}
        elif pk == "pointer":
            pe = {"kind": "pointer", "size": 8}
        elif pk in ("struct", "union"):
            pe = {"kind": "struct", "size": p.get("size")}
        else:
            pe = {"kind": "void"}
        return {"kind": "pointer", "pointee": pe}
    if k in ("int", "enum", "bool"):
        return {"kind": "int", "size": t.get("size"), "signed": t.get("signed")}
    return None


def main(argv):
    truth_path, out_dir = argv[1:3]
    os.makedirs(out_dir, exist_ok=True)
    for line in open(truth_path):
        t = json.loads(line)
        funcs = {}
        for f in t["functions"]:
            ints = [p for p in f["params"] if p["type"].get("kind") != "float"]
            args = {}
            for i, p in enumerate(ints):
                h = hint_type(p["type"])
                if h:
                    args[str(i)] = [h]
            spec = {"args": args}
            r = f.get("return")
            if r and hint_type(r):
                spec["return"] = [hint_type(r)]
            funcs[f["addr"]] = spec
        name = os.path.basename(t["binary"])
        name = name[:-4] if name.endswith(".exe") else name
        with open(os.path.join(out_dir, name + ".hints.json"), "w") as fh:
            json.dump({"source": "DWARF (ORACLE ceiling only)", "functions": funcs},
                      fh, indent=1, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
