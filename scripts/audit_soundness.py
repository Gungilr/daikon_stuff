"""Soundness audit: is every fact we emit TRUE on the samples we ourselves recorded?

Usage:  audit_soundness.py DIR      # DIR holds matching *.dtrace and *.tracer.txt

This is the strongest guarantee a dynamic front-end can be held to, and the
only one that is decidable. A violation is unambiguously OUR defect: not
Daikon over-generalising, not the oracle being wrong.

It has already earned its place. The first run reported

    asserted:  arg8 one of { -6076574518398440533L, 0 }
    recorded:  arg8 = 12370169555311111083

- the same bits, read signed and unsigned. `sign_extend` was returning 64-bit
values untouched, so the trace carried values above 2^63 for a variable
declared `int`, which in Daikon is a SIGNED 64-bit long. Daikon wrapped them,
the reports came out right, and every score ever measured was computed from
output that had been silently corrected downstream.

This is the one guarantee a dynamic front-end can actually be held to. Whether
an invariant holds for ALL executions is inductive and unprovable from traces;
whether it holds for the finite sample set we handed Daikon is decidable, and
any violation is a defect in OUR trace, not in Daikon's generalisation.
"""
import os, re, sys, glob, collections
sys.path.insert(0, "scripts")
import score_invariants as S

OUT = sys.argv[1]
NUM = r"-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?"


def parse_samples(path):
    """{ppt: [{var: value}]} from a .dtrace, sequences included."""
    out, ppt, cur = {}, None, {}
    lines = open(path, errors="replace").read().replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ":::" in ln and not ln.startswith((" ", "ppt", "variable")):
            if ppt and cur:
                out.setdefault(ppt, []).append(cur)
            ppt, cur = ln.strip(), {}
            i += 1
            if i < len(lines) and lines[i] == "this_invocation_nonce":
                i += 2
            continue
        if ppt and ln and i + 1 < len(lines) and not ln.startswith(" "):
            val = lines[i + 1]
            if val.startswith("["):
                try:
                    cur[ln] = [int(x) for x in val.strip("[] ").split()]
                except ValueError:
                    cur[ln] = val
            elif val == "nonsensical":
                cur[ln] = None
            else:
                try:
                    cur[ln] = int(val)
                except ValueError:
                    try:
                        cur[ln] = float(val)
                    except ValueError:
                        cur[ln] = val
            i += 3 if (i + 2 < len(lines) and lines[i + 2] in ("0", "1", "2")) else 2
            continue
        i += 1
    if ppt and cur:
        out.setdefault(ppt, []).append(cur)
    return out


def resolve(name, row):
    """Value of a variable name in a sample row; KeyError-free, None if absent."""
    if name in row:
        return row[name]
    m = re.fullmatch(r"size\((.+)\)", name)
    if m:
        v = row.get(m.group(1)) or row.get(m.group(1).replace("[]", "[..]"))
        return len(v) if isinstance(v, list) else None
    if name.endswith("[]"):
        return row.get(name[:-2] + "[..]")
    return None


def check(inv, rows):
    """True / False / None(undecidable) for one invariant over the samples."""
    inv = inv.strip()

    m = re.fullmatch(r"(\S+) == (" + NUM + r")", inv)
    if m:
        want = float(m.group(2))
        seen = [resolve(m.group(1), r) for r in rows]
        seen = [v for v in seen if v is not None and not isinstance(v, (list, str))]
        return (all(float(v) == want for v in seen)) if seen else None

    m = re.fullmatch(r"(\S+) one of \{(.+)\}", inv)
    if m:
        try:
            allowed = {float(x) for x in re.findall(NUM, m.group(2))}
        except ValueError:
            return None
        seen = [resolve(m.group(1), r) for r in rows]
        seen = [v for v in seen if v is not None and not isinstance(v, (list, str))]
        return (all(float(v) in allowed for v in seen)) if seen else None

    m = re.fullmatch(r"(\S+) (==|!=|<|<=|>|>=) (\S+)", inv)
    if m:
        a = [resolve(m.group(1), r) for r in rows]
        b = [resolve(m.group(3), r) for r in rows]
        pairs = [(x, y) for x, y in zip(a, b)
                 if x is not None and y is not None
                 and not isinstance(x, (list, str)) and not isinstance(y, (list, str))]
        if not pairs:
            return None
        op = m.group(2)
        f = {"==": lambda x, y: x == y, "!=": lambda x, y: x != y,
             "<": lambda x, y: x < y, "<=": lambda x, y: x <= y,
             ">": lambda x, y: x > y, ">=": lambda x, y: x >= y}[op]
        return all(f(x, y) for x, y in pairs)

    m = re.fullmatch(r"(\S+) has only one value", inv)
    if m:
        seen = [resolve(m.group(1), r) for r in rows]
        seen = [tuple(v) if isinstance(v, list) else v
                for v in seen if v is not None]
        return (len(set(seen)) <= 1) if seen else None

    return S.invariant_holds(inv, rows)


tally = collections.Counter()
violations = []
for dt in sorted(glob.glob(OUT + "/*.dtrace")):
    n = os.path.basename(dt)[:-7]
    rep = f"{OUT}/{n}.tracer.txt"
    if not os.path.isfile(rep):
        continue
    samples = parse_samples(dt)
    for ppt, invs in S.parse_report(rep).items():
        rows = samples.get(ppt) or samples.get(ppt.replace(":::EXIT", ":::EXIT0"))
        if not rows:
            tally["no samples for that ppt"] += len(invs); continue
        for inv in invs:
            v = check(inv, rows)
            if v is True:
                tally["TRUE on our own samples"] += 1
            elif v is False:
                tally["FALSE - unsound"] += 1
                if len(violations) < 12:
                    violations.append((n, ppt, inv))
            else:
                tally["undecidable by this checker"] += 1

tot = sum(tally.values())
print(f"facts audited: {tot}\n")
for k, v in tally.most_common():
    print(f"{v:6d}  {v*100.0/tot:5.1f}%  {k}")
if violations:
    print("\n--- UNSOUND: we asserted these, our own data refutes them ---")
    for n, p, i in violations:
        print(f"  {n:<22} {p.split(':::')[0][2:]:<18} {i[:56]}")
else:
    print("\nNo violations: every decidable fact is true on the samples we recorded.")
