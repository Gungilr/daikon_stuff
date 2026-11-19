"""Daikon <-> fuzzer loop for argv-driven binaries (black box: no DWARF, no source).

Configurations, compared on the same budget of program executions:

  blind   mutate a seed (AFL-style havoc on integer fields); no feedback
  cov     coverage-guided: keep inputs that reach a new basic-block edge
  covinv  the loop: coverage-guided, plus
            - every ROUND executions, Daikon re-learns invariants from the
              corpus traced so far (one batch trace, one schema)
            - an input that violates a live invariant is kept (InvsCov-style
              "new behaviour"), and the invariant is retired until relearned
            - mutations guided by the invariants: their constants (and +-1),
              and values built to violate a chosen invariant, on the input
              field the invariant's variable is learned to come from
          The variable -> input-field map is itself learned from the traces:
          a variable whose recorded value always equals one field's integer.

Writes one JSON per trial: coverage/violation curve, corpus, timings.

Usage:
    python3 scripts/fuzz/loop.py BINARY --seeds SEEDS.jsonl --config covinv \\
        --budget 1000 --trials 5 --out DIR [--round 100]
SEEDS.jsonl: one JSON list of argv[1..] strings per line.
"""
import argparse
import json
import re
import os
import random
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import invariants as I  # noqa: E402
import runner  # noqa: E402
import splitters as SP  # noqa: E402

INTERESTING = [-2147483648, -32768, -129, -128, -1, 0, 1, 16, 32, 64, 100, 127, 128,
               255, 256, 512, 1000, 1024, 4096, 32767, 65535, 2147483647]
I32 = 1 << 32


def wrap32(v):
    return ((int(v) + (1 << 31)) % I32) - (1 << 31)


class Mapping:
    """Learned variable -> input field: the field whose integer always equals it."""

    def __init__(self, n, min_values=2, min_obs=5):
        self.n = n
        self.cand = {}
        self.vals = {}
        self.obs = {}
        self.min_values, self.min_obs = min_values, min_obs

    def observe(self, fields, rows):
        """A field is a candidate for a variable if, in this run, the variable
        held the field's value at some program point; candidates are
        intersected over runs (so coincidences, like an unset 0, wash out)."""
        seen = {}
        for rs in rows.values():
            for r in rs:
                for v, x in r.items():
                    if isinstance(x, int) and not v.startswith("orig("):
                        seen.setdefault(v, set()).add(x)
        for v, xs in seen.items():
            eq = {i for i in range(self.n) if fields[i] in xs}
            self.cand[v] = self.cand.get(v, eq) & eq
            if eq:
                self.vals.setdefault(v, set()).add(fields[next(iter(eq))] if len(eq) == 1
                                                   else min(xs))
            self.obs[v] = self.obs.get(v, 0) + 1

    def field(self, var):
        v = var[5:-1] if var.startswith("orig(") else var
        c = self.cand.get(v)
        if c and len(c) == 1 and len(self.vals.get(v, ())) >= self.min_values \
                and self.obs.get(v, 0) >= self.min_obs:
            return next(iter(c))
        return None


class Fuzzer:
    def __init__(self, binary, seeds, config, rng, workdir, round_every=100):
        self.binary, self.config, self.rng, self.work = binary, config, rng, workdir
        self.seeds = [[int(x) for x in s] for s in seeds]
        self.n = len(self.seeds[0])
        self.corpus = [list(s) for s in self.seeds]
        self.edges = set()
        self.round_every = round_every
        self.invs = []          # live invariants
        self.dead = set()       # invariant keys violated since the last relearn
        self.found = set()      # every distinct invariant violation ever found
        self.map = Mapping(self.n)
        self.daikon_s = 0.0
        self.rounds = 0
        self.execs = 0
        self.curve = []
        self.executed = []
        self.trusted = set()
        self.final_invs = []
        self.max_rounds = 99

    # ---------------------------------------------------------------- mutation
    def havoc(self, x):
        x = list(x)
        for _ in range(self.rng.randint(1, 4)):
            i = self.rng.randrange(self.n)
            op = self.rng.randrange(5)
            if op == 0:
                x[i] = self.rng.choice(INTERESTING)
            elif op == 1:
                x[i] += self.rng.choice((-1, 1)) * self.rng.randint(1, 35)
            elif op == 2:
                x[i] = self.rng.randint(-5000, 5000)
            elif op == 3:
                x[i] = x[self.rng.randrange(self.n)]
            else:
                x[i] ^= 1 << self.rng.randrange(32)
            x[i] = wrap32(x[i])
        return x

    def inv_guided(self, x):
        """One mutation driven by a live invariant, or None."""
        usable = [v for v in self.invs if v.key not in self.dead]
        if not usable:
            return None
        inv = self.rng.choice(usable)
        x = list(x)
        if inv.kind in ("const", "oneof"):
            f = self.map.field(inv.vars[0])
            f = f if f is not None else self.rng.randrange(self.n)
            c = inv.consts
            if inv.kind == "oneof":
                choices = [min(c) - 1, max(c) + 1, self.rng.choice(c)]
            else:
                c = c[0]
                choices = {"==": [c + 1, c - 1], "!=": [c], "<": [c], "<=": [c + 1],
                           ">": [c], ">=": [c - 1]}[inv.op] + [c]
            x[f] = wrap32(self.rng.choice(choices))
            return x
        if inv.kind == "rel":
            a, b = (self.map.field(v) for v in inv.vars)
            if a is None or b is None:
                return None
            y = x[b]
            x[a] = wrap32({"==": y + 1, "!=": y, "<": y, "<=": y + 1, ">": y,
                           ">=": y - 1}[inv.op])
            return x
        return None

    def _as_row(self, x, inv):
        """The row an input implies for inv's variables, via the field map."""
        row = {}
        for v in inv.vars:
            f = self.map.field(v)
            if f is None:
                return None
            row[v] = x[f]
        return row

    def challenges(self, inv, x):
        """Inputs built to violate `inv` from base input x (empty if its
        variables are not mapped to input fields). For (A) ==> (B): a corpus
        input where A holds, changed so that B breaks and A still holds."""
        out = []
        if inv.kind == "implies":
            a_txt, b_txt = re.fullmatch(r"\((.+)\)\s+(?:==>|<==>)\s+\((.+)\)", inv.text).groups()
            a, b = I.compile_inv(inv.ppt, a_txt), I.compile_inv(inv.ppt, b_txt)
            if a is None or b is None or any(self.map.field(v) is None for v in inv.vars):
                return out
            bases = [x] + self.rng.sample(self.corpus, min(20, len(self.corpus)))
            for base in bases:
                ra = self._as_row(base, a)
                if ra is None or not a.holds(ra):
                    continue
                for y in self.challenges(b, base):
                    ry = self._as_row(y, a)
                    if ry is not None and a.holds(ry):
                        out.append(y)
                if out:
                    break
            return out
        if inv.kind in ("const", "oneof"):
            f = self.map.field(inv.vars[0])
            if f is None:
                return out
            c = inv.consts
            if inv.kind == "oneof":
                vals = [min(c) - 1, max(c) + 1, 0, -1, 1]
                vals = [v for v in vals if v not in c][:3]
            else:
                c = c[0]
                vals = {"==": [c + 1, c - 1], "!=": [c], "<": [c, c + 1], "<=": [c + 1],
                        ">": [c, c - 1], ">=": [c - 1]}[inv.op]
            for v in vals:
                y = list(x)
                y[f] = wrap32(v)
                out.append(y)
        elif inv.kind == "rel":
            a, b = (self.map.field(v) for v in inv.vars)
            if a is None or b is None or a == b:
                return out
            y = x[b]
            for v in {"==": [y + 1, y - 1], "!=": [y], "<": [y, y + 1], "<=": [y + 1],
                      ">": [y, y - 1], ">=": [y - 1]}[inv.op]:
                z = list(x)
                z[a] = wrap32(v)
                out.append(z)
        return out

    def challenge_phase(self, budget):
        """Daikon proposes, the fuzzer tries to refute: each live invariant gets
        inputs built to violate it. Refuted ones are dropped (their refuting
        inputs join the corpus and Daikon relearns); survivors of a direct
        challenge are TRUSTED. Repeats until nothing new is refuted."""
        while self.execs < budget:
            refuted_any = False
            tried = 0
            for inv in list(self.invs):
                if self.execs >= budget:
                    break
                if inv.key in self.dead:
                    continue
                cands = self.challenges(inv, self.rng.choice(self.corpus))
                if not cands:
                    continue
                tried += 1
                broken = False
                for y in cands[:2]:
                    if self.execs >= budget:
                        break
                    before = set(self.dead)
                    self.run_one(y)
                    if inv.key in self.dead:
                        broken = True
                        refuted_any = True
                        break
                    if self.dead - before:
                        refuted_any = True
                if not broken and inv.key not in self.dead:
                    self.trusted.add(inv.key)
            if not refuted_any or not tried or self.rounds >= self.max_rounds:
                break
            self.relearn(conditional=self.config == "loopcond")
            self.trusted = set()
        self.final_invs = [v.key for v in self.invs]

    def challenge_validate(self, budget, min_support=3):
        """For many (conditional) invariants: spend the budget on inputs built to
        break randomly chosen invariants, relearn once on the corpus (which now
        holds every refuting input), and TRUST a final invariant only if it held
        on every challenge run AND had a fair chance to fail: its condition (for
        (A) ==> (B)) or its program point was true/reached in >= min_support of
        those runs. Scales to thousands of invariants; nothing is trusted on
        faith."""
        val = []
        while self.execs < budget:
            pool = [v for v in self.invs if v.key not in self.dead]
            if not pool:
                break
            inv = self.rng.choice(pool)
            cands = self.challenges(inv, self.rng.choice(self.corpus))
            x = self.rng.choice(cands) if cands else self.havoc(self.rng.choice(self.corpus))
            edges, dt, _ = runner.trace_one(self.binary, x, self.work)
            self.execs += 1
            self.executed.append(list(x))
            self.edges |= edges
            rows = I.rows_by_ppt(dt)
            val.append(rows)
            bad = I.violations(pool, rows)
            if bad:
                self.corpus.append(x)
                for v in bad:
                    self.dead.add(v.key)
                    self.found.add(v.key)
            self.curve.append((self.execs, len(self.edges), len(self.found)))
        self.relearn(conditional=True)
        trusted = set()
        for inv in self.invs:
            cond = None
            if inv.kind == "implies":
                cond = I.compile_inv(inv.ppt, re.match(r"\((.+?)\)\s+(?:==>|<==>)", inv.text).group(1))
            support, ok = 0, True
            for rows in val:
                for r in rows.get(inv.ppt, ()):
                    h = inv.holds(r)
                    if h is False:
                        ok = False
                        break
                    if h is None:
                        continue
                    if cond is None or cond.holds(r):
                        support += 1
                if not ok:
                    break
            if ok and support >= min_support:
                trusted.add(inv.key)
        self.trusted = trusted
        self.final_invs = [v.key for v in self.invs]

    def next_input(self):
        if self.config == "blind":
            return self.havoc(self.rng.choice(self.seeds))
        base = self.rng.choice(self.corpus)
        if self.config in ("covinv", "loop", "loopcond") and self.invs \
                and self.rng.random() < 0.5:
            y = self.inv_guided(base)
            if y is not None:
                return self.havoc(y) if self.rng.random() < 0.3 else y
        return self.havoc(base)

    # ---------------------------------------------------------------- loop
    def relearn(self, conditional=False):
        t = time.time()
        dt = runner.trace_batch(self.binary, self.corpus, self.work, tag="corpus")
        spinfo = None
        if conditional:
            # what the fuzzer refuted becomes Daikon's case split
            conds = SP.conditions(I.rows_by_ppt(dt))
            spinfo = SP.write_spinfo(conds, os.path.join(self.work, "corpus.spinfo"))
        txt = runner.daikon(dt, os.path.join(self.work, "corpus"), spinfo=spinfo)
        self.invs, _ = I.load(txt)
        self.invs = [v for v in self.invs if "condition" not in v.ppt and ";" not in v.ppt]
        self.dead = set()
        self.daikon_s += time.time() - t
        self.rounds += 1

    def run_one(self, x):
        edges, dt, _exit = runner.trace_one(self.binary, x, self.work)
        self.execs += 1
        self.executed.append(list(x))
        new_edges = edges - self.edges
        self.edges |= edges
        keep = bool(new_edges)
        if self.config in ("covinv", "loop", "loopcond"):
            rows = I.rows_by_ppt(dt)
            self.map.observe(x, rows)
            if self.invs:
                bad = [v for v in I.violations(
                    [v for v in self.invs if v.key not in self.dead], rows)]
                if bad:
                    keep = True
                    for v in bad:
                        self.dead.add(v.key)
                        self.found.add(v.key)
        if keep and self.config != "blind":
            self.corpus.append(x)
        self.curve.append((self.execs, len(self.edges), len(self.found)))

    def run(self, budget, challenge_share=0.4):
        for s in self.seeds:
            self.run_one(s)
        learning = self.config in ("covinv", "loop", "loopcond")
        if learning:
            self.relearn()
        explore = budget if self.config not in ("loop", "loopcond") \
            else int(budget * (1 - challenge_share))
        while self.execs < explore:
            self.run_one(self.next_input())
            if learning and self.execs % self.round_every == 0:
                self.relearn()
        if self.config == "loop":
            self.relearn()
            self.challenge_phase(budget)
        elif self.config == "loopcond":
            self.relearn(conditional=True)
            self.challenge_validate(budget)


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("--seeds", required=True)
    p.add_argument("--config", choices=("blind", "cov", "covinv", "loop", "loopcond"),
                   required=True)
    p.add_argument("--budget", type=int, default=1000)
    p.add_argument("--trials", type=int, default=5)
    p.add_argument("--round", type=int, default=100)
    p.add_argument("--first-trial", type=int, default=0)
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    seeds = [json.loads(l) for l in open(a.seeds) if l.strip()]
    os.makedirs(a.out, exist_ok=True)
    for t in range(a.first_trial, a.first_trial + a.trials):
        with tempfile.TemporaryDirectory() as work:
            f = Fuzzer(a.binary, seeds, a.config, random.Random(1000 + t), work, a.round)
            t0 = time.time()
            f.run(a.budget)
            dur = time.time() - t0
        res = {"config": a.config, "trial": t, "budget": a.budget, "seconds": dur,
               "daikon_seconds": f.daikon_s, "rounds": f.rounds,
               "edges": len(f.edges), "violations_found": len(f.found),
               "curve": f.curve, "corpus": f.corpus, "executed": f.executed,
               "trusted": sorted(f.trusted), "final_invariants": f.final_invs,
               "mapping": {v: f.map.field(v) for v in sorted(f.map.cand)
                           if f.map.field(v) is not None}}
        json.dump(res, open(os.path.join(a.out, f"{a.config}_{t}.json"), "w"))
        print(f"{a.config} trial {t}: edges {len(f.edges)}  corpus {len(f.corpus)}  "
              f"violations {len(f.found)}  rounds {f.rounds}  {dur:.0f}s "
              f"(daikon {f.daikon_s:.0f}s)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
