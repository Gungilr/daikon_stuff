import json, csv, collections, os
HERE = os.path.dirname(os.path.abspath(__file__))
t = json.load(open(os.path.join(HERE, "truth.json")))
P = {r["id"]: r for r in csv.DictReader(open(os.path.join(HERE, "preds.tsv")), delimiter="\t")}
missing = sorted(set(t) - set(P)); assert not missing, missing
norm = lambda k: "struct" if k == "union" else k
def elemclass(desc):
    d = desc.replace("[]", "")
    if "{" in d: return "struct"
    if "*" in d: return "pointer"
    if "double" in d or "float" in d: return "double"
    if "char" in d: return "char"
    if "short" in d: return "short"
    if "long" in d: return "long"
    return "int"
for label, keys in [("all", list(t)), ("no-leak", [k for k in t if P[k]["leak"] == "no"])]:
    cm = collections.Counter(); ok = 0
    for k in keys:
        tk, pk = norm(t[k]["kind"]), P[k]["kind"]
        cm[(tk, pk)] += 1; ok += tk == pk
    print(f"== {label}: kind correct {ok}/{len(keys)}")
    kinds = ["scalar", "array", "pointer", "struct"]
    print("truth\\pred " + " ".join(f"{x:>8}" for x in kinds))
    for a in kinds: print(f"{a:>10} " + " ".join(f"{cm[(a,b)]:>8}" for b in kinds))
print("\n== per-global misses")
for k in sorted(t):
    tk = norm(t[k]["kind"])
    if tk != P[k]["kind"]:
        print(k, t[k]["binary"], t[k]["name"], t[k]["type"][:60], "| pred", P[k]["kind"], P[k]["elem"], "|", P[k]["why"])
print("\n== all structs and doubles")
for k in sorted(t):
    if norm(t[k]["kind"]) == "struct" or "double" in t[k]["type"] and t[k]["kind"] in ("scalar", "array"):
        print(k, t[k]["binary"], t[k]["name"], t[k]["kind"], t[k]["type"][:50], "| pred", P[k]["kind"], P[k]["elem"], "leak=" + P[k]["leak"])
# element-type accuracy for scalars/arrays both right on kind
ek = [k for k in t if norm(t[k]["kind"]) == P[k]["kind"] and P[k]["kind"] in ("scalar", "array")]
eok = sum(elemclass(t[k]["type"]) == P[k]["elem"] for k in ek)
print(f"\nelement class correct (scalar/array, kind right): {eok}/{len(ek)}")
for k in ek:
    if elemclass(t[k]["type"]) != P[k]["elem"]:
        print("  ", k, t[k]["binary"], t[k]["name"], t[k]["type"][:40], "pred", P[k]["elem"])
