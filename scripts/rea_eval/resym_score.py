"""Score local ReSym VarDecoder runs (resym_infer.py output) on TYPES.

Each answer is lines "placeholder: name, type". For every variable asked:
    exact     predicted type == true type (whitespace-normalised)
    category  same coarse class: pointer-to-struct / pointer / struct /
              float / integer of the same width and signedness
    missing   the model gave no line for it
Also, when the authors' predictions (ReSym_data/vardecoder_pred.jsonl) are
given, the share of OUR type predictions identical to THEIRS on the same
entries: a reproduction check of the CPU setup (same prompt, same decoding).

Usage:
    python3 scripts/rea_eval/resym_score.py OURS.jsonl [AUTHORS_PRED.jsonl]
"""
import collections
import json
import re
import sys

INT_W = {"char": 1, "short": 2, "int": 4, "long": 8, "long long": 8, "__int8": 1,
         "__int16": 2, "__int32": 4, "__int64": 8, "_BYTE": 1, "_WORD": 2,
         "_DWORD": 4, "_QWORD": 8, "bool": 1, "_BOOL8": 8, "size_t": 8,
         "int8_t": 1, "int16_t": 2, "int32_t": 4, "int64_t": 8, "uint8_t": 1,
         "uint16_t": 2, "uint32_t": 4, "uint64_t": 8, "ssize_t": 8, "off_t": 8}


def parse(text):
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"\s*([^:]+?)\s*:\s*([^,]*?)\s*,\s*(.+?)\s*$", line)
        if m:
            out.setdefault(m.group(1), (m.group(2), m.group(3)))
    return out


def norm(t):
    t = re.sub(r"\s+", " ", t.strip())
    t = re.sub(r"\s*\*\s*", "*", t)
    return re.sub(r"\b(const|volatile|struct|enum|union)\b\s*", lambda m: "" if m.group(1) in
                  ("const", "volatile") else m.group(1) + " ", t).strip()


INT_WORDS = {"char", "short", "int", "long", "signed", "unsigned", "_Bool", "bool"}


def category(t):
    """Coarse class: pointer depth + one of funcptr / void / named (a struct,
    union or project typedef - which of these the name alone cannot say) /
    float / double / int<width>[u]; a T[N] array counts as a pointer to T."""
    t = norm(t)
    if "(" in t and "*" in t:
        return "funcptr"
    t = re.sub(r"\[\d*\]", "*", t)
    stars = t.count("*")
    base = t.replace("*", "").strip()
    words = base.split()
    if base == "void":
        kind = "void"
    elif base in ("float", "double", "long double"):
        kind = base
    elif base in INT_W:
        kind = f"int{INT_W[base]}{'u' if base.startswith(('uint', 'size')) or base in ('_BYTE', '_WORD', '_DWORD', '_QWORD') else ''}"
    elif words and set(words) <= INT_WORDS:
        unsigned = "unsigned" in words
        if "_Bool" in words or "bool" in words or "char" in words:
            w = 1
        elif "short" in words:
            w = 2
        elif "long" in words:
            w = 8
        else:
            w = 4
        kind = f"int{w}{'u' if unsigned else ''}"
    else:
        kind = "named"
    return ("ptr*" * stars) + kind if stars else kind


def main(argv):
    ours = [json.loads(l) for l in open(argv[1]) if l.strip()]
    authors = {}
    if len(argv) > 2:
        want = {r["idx"] for r in ours}
        for i, l in enumerate(open(argv[2])):
            if i in want:
                authors[i] = json.loads(l)
    C = collections.Counter()
    wrong = collections.Counter()
    secs = []
    for r in ours:
        secs.append(r["seconds"])
        truth, pred = parse(r["output"]), parse(r["predict"])
        theirs = parse(authors[r["idx"]]["predict"]) if r["idx"] in authors else None
        C["capped"] += r.get("capped", False)
        for v, (_, tt) in truth.items():
            if tt.strip() == "-":           # ReSym's "no ground truth" label
                C["unlabelled"] += 1
                continue
            C["vars"] += 1
            if v not in pred:
                C["missing"] += 1
                continue
            pt = pred[v][1]
            ex = norm(pt) == norm(tt)
            C["exact"] += ex
            cat = category(pt) == category(tt)
            C["category"] += cat
            if not cat:
                wrong[(category(tt), category(pt))] += 1
            if theirs is not None and v in theirs:
                C["cmp"] += 1
                C["same_as_authors"] += norm(theirs[v][1]) == norm(pt)
                C["authors_exact"] += norm(theirs[v][1]) == norm(tt)
    n = C["vars"] or 1
    print(f"functions {len(ours)}   variables {C['vars']}   "
          f"median {sorted(secs)[len(secs) // 2] if secs else 0}s/function   capped {C['capped']}   "
          f"(unlabelled vars skipped: {C['unlabelled']})")
    print(f"TYPE exact     {100 * C['exact'] / n:5.1f}%")
    print(f"TYPE category  {100 * C['category'] / n:5.1f}%   "
          f"(pointer depth + void/named/float/double/int width+sign; arrays as pointers)")
    print(f"missing        {100 * C['missing'] / n:5.1f}%")
    if C["cmp"]:
        print(f"reproduction: our type == authors' predicted type on {100 * C['same_as_authors'] / C['cmp']:.1f}% "
              f"of {C['cmp']}; authors' exact on the same vars {100 * C['authors_exact'] / C['cmp']:.1f}%")
    print("most common category errors (truth -> predicted):")
    for (t, p), k in wrong.most_common(8):
        print(f"   {k:4d}  {t} -> {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
