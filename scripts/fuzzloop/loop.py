"""The loop: Daikon proposes invariants, the fuzzer attacks them, repeat.

    seeds ──► Kvasir ──► Daikon ──► invariants ─┐
      ▲                                          │ compiled to distance checks
      │                                          ▼
    corpus ◄── keep if: new coverage,      mutate corpus, run batch
               closer to violating an       natively (coverage, crashes)
               invariant, or violating it   and under Kvasir (values)

A round is several fuzzing batches followed by one Daikon run over the whole
corpus. An invariant is REFUTED when Daikon stops reporting it. That is the
only verdict that counts; the fuzzer's own checks only decide what to keep.

The loop stops at a fixed point: `patience` rounds in a row with nothing
refuted and no new coverage. What survives has been attacked for that long
and still holds, which is a statement about the search, not a proof.
"""
import hashlib
import json
import math
import os
import random
import time

from . import dtrace, invariants, runner
from .mutate import Mutator, parse_seed_file


def _bucket(d):
    """Log-scale distance bucket; 0 means violated."""
    if d <= 0:
        return 0
    return 1 + int(math.log2(d + 1))


def _show_input(hexstr):
    """Markdown cell for a counterexample. The empty input is a real, and
    common, counterexample - `n >= 1` falls to it - so it must not render
    like "none"."""
    if hexstr is None:
        return "-"
    return "`%s`" % hexstr if hexstr else "(empty input)"


def _sha(data):
    return hashlib.sha1(data).hexdigest()[:16]


class Entry(object):
    __slots__ = ("data", "samples", "round", "reason", "wins")

    def __init__(self, data, samples, round_, reason):
        self.data, self.samples = data, samples
        self.round, self.reason = round_, reason
        self.wins = 0       # invariants for which this is the closest attacker


class History(object):
    """What happened to every invariant Daikon ever reported."""

    def __init__(self):
        self.inv = {}       # (ppt, text) -> record

    def observe(self, round_, report):
        present = set()
        for ppt, texts in report.items():
            for t in texts:
                key = (ppt, t)
                present.add(key)
                rec = self.inv.setdefault(key, {
                    "ppt": ppt, "text": t, "first_round": round_,
                    "refuted_round": None, "min_distance": None,
                    "violated_by": None, "supported": None})
                if rec["refuted_round"] is not None:
                    # Reported again after being refuted: only possible if
                    # the violating input left the corpus, which it never
                    # does. Record it rather than hide it.
                    rec["reappeared_round"] = round_
        refuted = []
        for key, rec in self.inv.items():
            if key not in present and rec["refuted_round"] is None:
                rec["refuted_round"] = round_
                refuted.append(rec)
        return refuted

    def alive(self):
        return [r for r in self.inv.values() if r["refuted_round"] is None]


class FuzzLoop(object):
    def __init__(self, target_c, out_dir, daikondir, seeds=None, rng_seed=0,
                 batch_size=200, batches_per_round=3, rounds=10, patience=2,
                 max_len=64, keep_is_param=False, conf_limit=0.0,
                 daikon_args=(), guidance=True, coverage=True,
                 frontend="kvasir", tier=7, log=print):
        self.target_c = os.path.abspath(target_c)
        self.out = os.path.abspath(out_dir)
        self.work = os.path.join(self.out, "work")
        self.daikondir = daikondir
        self.seeds = seeds
        self.rng = random.Random(rng_seed)
        self.batch_size = batch_size
        self.batches_per_round = batches_per_round
        self.rounds = rounds
        self.patience = patience
        self.keep_is_param = keep_is_param
        self.conf_limit = conf_limit
        # False gives the ablation baseline: a plain coverage-guided fuzzer
        # whose corpus Daikon re-reads, with invariants steering nothing.
        self.guidance = guidance
        # False gives the opposite ablation: invariants are the only metric,
        # and new coverage alone never keeps an input.
        self.coverage = coverage
        # "kvasir": source build traced under Valgrind, native coverage build.
        # "tracer": stripped build, emulation tracer for values AND coverage.
        if frontend not in ("kvasir", "tracer"):
            raise ValueError("frontend must be 'kvasir' or 'tracer'")
        self.frontend = frontend
        self.tier = tier
        self.daikon_args = list(daikon_args)
        self.log = log
        self.mutator = Mutator(self.rng, max_len=max_len)

        self.corpus = []
        self.seen_inputs = set()
        self.seen_features = set()
        self.best = {}          # inv key -> (bucket, distance, entry index)
        self.violated = {}      # inv key -> input hex, as seen by the fuzzer
        self.compiled = {}      # report ppt -> [Invariant]
        self.unsupported = []
        self.decls = None
        self.history = History()
        self.crashes = []
        self.stats = {"execs": 0, "kvasir_runs": 0, "daikon_runs": 0,
                      "seconds_native": 0.0, "seconds_kvasir": 0.0,
                      "seconds_daikon": 0.0}
        self.round_log = []

    # -- setup -------------------------------------------------------------

    def _load_seeds(self):
        if self.seeds:
            with open(self.seeds) as f:
                return parse_seed_file(f.read())
        beside = os.path.splitext(self.target_c)[0] + ".seeds"
        if os.path.exists(beside):
            with open(beside) as f:
                return parse_seed_file(f.read())
        # Small non-negative words: deliberately narrow, so Daikon starts out
        # overconfident and the loop has something to refute.
        return [b"".join(self.rng.randint(1, 50).to_bytes(4, "little") for _ in range(3))
                for _ in range(16)]

    def _dirs(self):
        for d in ("work", "corpus", "crashes", "rounds"):
            os.makedirs(os.path.join(self.out, d), exist_ok=True)

    # -- execution ---------------------------------------------------------

    def _execute(self, inputs):
        """[(input, features, samples)] for the inputs that ran cleanly."""
        if self.frontend == "tracer":
            return self._execute_tracer(inputs)
        t0 = time.time()
        results, crashes = runner.run_cov(self.cov_exe, inputs, self.work)
        self.stats["seconds_native"] += time.time() - t0
        self.stats["execs"] += len(inputs)
        for i, reason in crashes:
            self._save_crash(inputs[i], reason)
        ok = sorted(results)
        if not ok:
            return []
        t0 = time.time()
        decls, per_input = runner.run_kvasir(self.kv_exe, [inputs[i] for i in ok],
                                             self.work, self.daikondir,
                                             ppt_list=self.ppt_list)
        self.stats["seconds_kvasir"] += time.time() - t0
        self.stats["kvasir_runs"] += 1
        if self.decls is None:
            self.decls = decls
        out = []
        for local, i in enumerate(ok):
            feats, consts = results[i]
            self.mutator.add_constants(consts)
            out.append((inputs[i], feats, per_input.get(local, [])))
        return out

    def _execute_tracer(self, inputs):
        t0 = time.time()
        decls, per_input, feats, bad, _ = runner.run_tracer(
            self.bb_exe, inputs, self.work, tier=self.tier)
        self.stats["seconds_tracer"] = self.stats.get("seconds_tracer", 0.0) \
            + time.time() - t0
        self.stats["tracer_runs"] = self.stats.get("tracer_runs", 0) + 1
        self.stats["execs"] += len(inputs)
        if self.decls is None:
            self.decls = decls
        bad_ids = set()
        for i, reason in bad:
            bad_ids.add(i)
            self._save_crash(inputs[i], reason.split(":")[0])
        out = []
        for i in range(len(inputs)):
            if i in bad_ids:
                continue
            fs, consts = feats.get(i, (frozenset(), []))
            self.mutator.add_constants(consts)
            out.append((inputs[i], fs, per_input.get(i, [])))
        return out

    def _save_crash(self, data, reason):
        name = "%s.%s.bin" % (_sha(data), reason.replace(" ", "_"))
        path = os.path.join(self.out, "crashes", name)
        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(data)
            self.crashes.append({"input": data.hex(), "reason": reason, "file": name})
            self.log("    [crash] %s %s" % (reason, data.hex()))

    def _distances(self, samples):
        """{inv key: min distance} over every evaluable sample of one input."""
        out = {}
        for ppt, row in dtrace.rows(samples):
            for rp in invariants.report_ppts_for(ppt):
                for inv in self.compiled.get(rp, ()):
                    res = inv.check(row)
                    if res is None:
                        continue
                    _, d = res
                    k = inv.key
                    if k not in out or d < out[k]:
                        out[k] = d
        return out

    def _consider(self, data, feats, samples, round_, force=False):
        """Add to the corpus if interesting. Returns the reason, or None."""
        new_feats = feats - self.seen_features
        dists = self._distances(samples)
        progress, violations = [], []
        for k, d in dists.items():
            b = _bucket(d)
            prev = self.best.get(k)
            if d == 0 and k not in self.violated:
                violations.append(k)
            elif prev is None or b < prev[0]:
                progress.append(k)
        reasons = []
        if force:
            reasons.append("seed")
        if new_feats and self.coverage:
            reasons.append("coverage+%d" % len(new_feats))
        if violations and self.guidance:
            reasons.append("violates %d" % len(violations))
        if progress and self.guidance and not force:
            reasons.append("closer to %d" % len(progress))
        if not reasons:
            return None

        idx = len(self.corpus)
        entry = Entry(data, samples, round_, ", ".join(reasons))
        self.corpus.append(entry)
        self.seen_features |= feats
        with open(os.path.join(self.out, "corpus", _sha(data) + ".bin"), "wb") as f:
            f.write(data)
        for k, d in dists.items():
            prev = self.best.get(k)
            if prev is None or d < prev[1]:
                if prev is not None and prev[2] is not None:
                    self.corpus[prev[2]].wins -= 1
                self.best[k] = (_bucket(d), d, idx)
                entry.wins += 1
            if d == 0 and k not in self.violated:
                self.violated[k] = data.hex()
        return entry.reason

    def _pick_parent(self):
        # Inputs closest to violating a live invariant get most of the
        # budget: that is the "attack" in attack-the-invariant.
        if not self.guidance:
            return self.rng.choice(self.corpus)
        weights = [1.0 + 4.0 * max(0, e.wins) for e in self.corpus]
        return self.rng.choices(self.corpus, weights=weights)[0]

    # -- inference ---------------------------------------------------------

    def _write_corpus_trace(self):
        if self.frontend == "tracer":
            # The tracer decides each function's arity from the evidence in
            # ONE run, so batches can declare the same function differently.
            # Re-trace the whole corpus in a single run: one consistent set of
            # declarations, and every entry's samples refreshed to match it.
            decls, per_input, _, _, _ = runner.run_tracer(
                self.bb_exe, [e.data for e in self.corpus], self.work,
                tier=self.tier)
            self.decls = decls
            for i, e in enumerate(self.corpus):
                e.samples = per_input.get(i, [])
        header, blocks = self.decls
        decls_path = os.path.join(self.out, "corpus.decls")
        with open(decls_path, "w") as f:
            f.write(dtrace.render_decls(header, blocks, keep=dtrace.keep_ppt,
                                        is_param=self.keep_is_param))
        dt_path = os.path.join(self.out, "corpus.dtrace")
        nonce = 0
        with open(dt_path, "w") as f:
            f.write("\n".join(header) + "\n\n")
            for e in self.corpus:
                text, nonce = dtrace.render_samples(e.samples, nonce)
                f.write(text)
        return decls_path, dt_path

    def _infer(self, round_):
        decls_path, dt_path = self._write_corpus_trace()
        t0 = time.time()
        text = runner.run_daikon(decls_path, dt_path, self.work, self.daikondir,
                                 conf_limit=self.conf_limit, extra_args=self.daikon_args)
        self.stats["seconds_daikon"] += time.time() - t0
        self.stats["daikon_runs"] += 1
        with open(os.path.join(self.out, "rounds", "round_%02d.txt" % round_), "w") as f:
            f.write(text)
        report = invariants.parse_report(text)
        report = {p: v for p, v in report.items() if ";condition=" not in p}
        refuted = self.history.observe(round_, report)
        self.compiled, self.unsupported = invariants.compile_report(report)
        supported = {inv.key for invs in self.compiled.values() for inv in invs}
        for key, rec in self.history.inv.items():
            if rec["refuted_round"] is None:
                rec["supported"] = key in supported
        # Distances recorded against the previous invariant set no longer
        # mean anything for invariants that changed; recompute them over the
        # corpus so attack effort follows the CURRENT hypotheses.
        self.best = {}
        for e in self.corpus:
            e.wins = 0
        for idx, e in enumerate(self.corpus):
            for k, d in self._distances(e.samples).items():
                prev = self.best.get(k)
                if prev is None or d < prev[1]:
                    if prev is not None:
                        self.corpus[prev[2]].wins -= 1
                    self.best[k] = (_bucket(d), d, idx)
                    e.wins += 1
        for rec in refuted:
            k = (rec["ppt"], rec["text"])
            rec["violated_by"] = self.violated.get(k)
        return report, refuted

    def _update_min_distances(self):
        for k, (_, d, _) in self.best.items():
            rec = self.history.inv.get(k)
            if rec is not None and rec["refuted_round"] is None:
                if rec["min_distance"] is None or d < rec["min_distance"]:
                    rec["min_distance"] = d

    # -- main --------------------------------------------------------------

    def run(self):
        self._dirs()
        if self.frontend == "tracer":
            self.bb_exe = runner.build_blackbox(self.target_c, self.work)
        else:
            self.cov_exe, self.kv_exe = runner.build(self.target_c, self.work)
            self.ppt_list = runner.write_ppt_list(self.kv_exe, self.work,
                                                  self.daikondir)
        seeds = self._load_seeds()
        self.log("[+] target  %s" % self.target_c)
        self.log("[+] seeds   %d" % len(seeds))
        for data, feats, samples in self._execute(seeds):
            self.seen_inputs.add(data)
            self._consider(data, feats, samples, 0, force=True)
        if not self.corpus:
            raise runner.ToolError("no seed ran cleanly; nothing to infer from")
        report, _ = self._infer(0)
        n_inv = sum(len(v) for v in report.values())
        self.log("[+] round 0: %d invariants over %d ppts from %d seeds "
                 "(%d not checkable by the fuzzer)" % (
                     n_inv, len(report), len(self.corpus), len(self.unsupported)))
        self.round_log.append({"round": 0, "invariants": n_inv, "refuted": 0,
                               "corpus": len(self.corpus), "features": len(self.seen_features)})

        quiet = 0
        for r in range(1, self.rounds + 1):
            feats_before = len(self.seen_features)
            added = 0
            for _ in range(self.batches_per_round):
                cands = []
                tries = 0
                while len(cands) < self.batch_size and tries < self.batch_size * 20:
                    tries += 1
                    parent = self._pick_parent()
                    other = self.rng.choice(self.corpus).data
                    child = self.mutator.mutate(parent.data, other)
                    if child in self.seen_inputs:
                        continue
                    self.seen_inputs.add(child)
                    cands.append(child)
                for data, feats, samples in self._execute(cands):
                    if self._consider(data, feats, samples, r):
                        added += 1
                self._update_min_distances()
            report, refuted = self._infer(r)
            self._update_min_distances()
            n_inv = sum(len(v) for v in report.values())
            new_feats = len(self.seen_features) - feats_before
            self.log("[+] round %d: corpus %d (+%d), features +%d, %d refuted, "
                     "%d invariants now" % (r, len(self.corpus), added, new_feats,
                                            len(refuted), n_inv))
            for rec in refuted:
                self.log("      refuted  %-28s %s%s" % (
                    rec["ppt"], rec["text"],
                    "" if rec["violated_by"] is None
                    else "   <- %s" % (rec["violated_by"] or "(empty input)")))
            self.round_log.append({"round": r, "invariants": n_inv, "refuted": len(refuted),
                                   "corpus": len(self.corpus),
                                   "features": len(self.seen_features)})
            quiet = quiet + 1 if (not refuted and (new_feats == 0 or not self.coverage)) else 0
            if quiet >= self.patience:
                self.log("[+] fixed point: %d quiet round(s)" % quiet)
                break
        self._write_summary()
        return self.history

    # -- reporting ---------------------------------------------------------

    def _disagreements(self):
        """Invariants the fuzzer saw violated that Daikon still reports.

        Daikon falsifies on a single counterexample, so every entry here is a
        bug: in the distance evaluator, or in how the sample reached Daikon.
        """
        out = []
        for rec in self.history.alive():
            k = (rec["ppt"], rec["text"])
            if k in self.violated:
                out.append({"ppt": rec["ppt"], "text": rec["text"], "input": self.violated[k]})
        return out

    def _write_summary(self):
        alive = self.history.alive()
        refuted = [r for r in self.history.inv.values() if r["refuted_round"] is not None]
        data = {
            "target": self.target_c,
            "rounds": self.round_log,
            "stats": self.stats,
            "corpus_size": len(self.corpus),
            "crashes": self.crashes,
            "invariants": sorted(self.history.inv.values(),
                                 key=lambda r: (r["ppt"], r["first_round"], r["text"])),
            "disagreements": self._disagreements(),
        }
        with open(os.path.join(self.out, "history.json"), "w") as f:
            json.dump(data, f, indent=1)

        L = ["# Fuzz loop: %s" % os.path.basename(self.target_c), ""]
        L.append("| round | invariants | refuted | corpus | features |")
        L.append("|---|---|---|---|---|")
        for row in self.round_log:
            L.append("| %(round)d | %(invariants)d | %(refuted)d | %(corpus)d | %(features)d |" % row)
        s = self.stats
        if self.frontend == "tracer":
            cost = "%d tracer runs (%.1fs)" % (s.get("tracer_runs", 0),
                                               s.get("seconds_tracer", 0.0))
        else:
            cost = "%d Kvasir runs (%.1fs), native %.1fs" % (
                s["kvasir_runs"], s["seconds_kvasir"], s["seconds_native"])
        L += ["", "Front-end: %s. %d executions; %s; %d Daikon runs (%.1fs)." % (
            self.frontend, s["execs"], cost, s["daikon_runs"], s["seconds_daikon"]), ""]

        L += ["## Refuted (%d)" % len(refuted), "",
              "| ppt | invariant | proposed | refuted | counterexample |", "|---|---|---|---|---|"]
        for r in sorted(refuted, key=lambda r: (r["refuted_round"], r["ppt"])):
            L.append("| `%s` | `%s` | %d | %d | %s |" % (
                r["ppt"], r["text"], r["first_round"], r["refuted_round"],
                _show_input(r["violated_by"])))

        L += ["", "## Survived (%d)" % len(alive), "",
              "Closest approach is the smallest violation distance the fuzzer reached; "
              "`n/a` means the fuzzer could not evaluate the form and only Daikon "
              "re-inference attacked it.", "",
              "| ppt | invariant | proposed | closest approach |", "|---|---|---|---|"]
        for r in sorted(alive, key=lambda r: (r["ppt"], r["text"])):
            md = r["min_distance"]
            L.append("| `%s` | `%s` | %d | %s |" % (
                r["ppt"], r["text"], r["first_round"],
                "n/a" if md is None else ("%g" % md)))

        if self.crashes:
            L += ["", "## Crashes (%d)" % len(self.crashes), ""]
            for c in self.crashes:
                L.append("- %s: `%s` (`crashes/%s`)" % (c["reason"], c["input"], c["file"]))
        dis = self._disagreements()
        if dis:
            L += ["", "## Disagreements (%d)" % len(dis), "",
                  "The fuzzer saw these violated but Daikon still reports them. "
                  "Each one is a bug in the loop.", ""]
            for d in dis:
                L.append("- `%s` `%s` <- `%s`" % (d["ppt"], d["text"], d["input"]))
        with open(os.path.join(self.out, "summary.md"), "w") as f:
            f.write("\n".join(L) + "\n")
