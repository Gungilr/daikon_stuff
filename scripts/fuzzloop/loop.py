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
import subprocess
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
    __slots__ = ("data", "samples", "round", "reason", "wins", "time", "violates")

    def __init__(self, data, samples, round_, reason, time_=0.0):
        self.data, self.samples = data, samples
        self.round, self.reason = round_, reason
        self.wins = 0       # invariants for which this is the closest attacker
        self.time = time_   # seconds since the run started
        self.violates = []  # live rules this input broke when it was kept


class History(object):
    """What happened to every invariant Daikon ever reported."""

    def __init__(self):
        self.inv = {}       # (ppt, text) -> record

    def observe(self, round_, report, now=None):
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
                rec["refuted_time"] = now
                refuted.append(rec)
        return refuted

    def proposed_in(self, round_):
        """Invariants Daikon reported for the first time in this round.

        After round 0 these are almost always WEAKER restatements of a
        refuted one (`x >= 1` falls, `x >= -5` appears), or facts that only
        became justified once the corpus grew."""
        return [r for r in self.inv.values() if r["first_round"] == round_]

    def alive(self):
        return [r for r in self.inv.values() if r["refuted_round"] is None]


class FuzzLoop(object):
    def __init__(self, target_c, out_dir, daikondir, seeds=None, rng_seed=0,
                 batch_size=200, batches_per_round=3, rounds=10, patience=2,
                 max_len=64, keep_is_param=False, conf_limit=0.0,
                 daikon_args=(), guidance=True, coverage=True,
                 frontend="kvasir", tier=7, bug_check=True, learn_once=False,
                 time_limit=None, call_budget=0, trace_sample=1.0, log=print):
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
        # The bug checker needs source (a sanitizer build), so it is
        # source-mode only.
        self.bug_check = bug_check and frontend == "kvasir"
        # learn_once: Daikon learns from the seeds ONCE and the fuzzer attacks
        # that fixed set for the whole run (InvsCov-style). Daikon runs again
        # only at the very end, to score which of those rules were refuted.
        self.learn_once = learn_once
        self.time_limit = time_limit   # seconds, or None
        # Functions averaging more calls per seed input than this are not
        # traced by Kvasir (0 = trace everything). See apply_call_budget.
        self.call_budget = call_budget
        # Fraction of inputs WITHOUT new coverage (or a new bug) that are
        # traced and offered to the invariant checks. Inputs with new coverage
        # are always traced: they join the corpus anyway. 1.0 traces all.
        self.trace_sample = trace_sample
        self.var_list = None
        self.t0 = time.time()
        self.bugs = {}            # (kind, location) -> record
        self._bug_inputs = set()  # inputs that found a NEW bug this batch
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
        self.keep_counts = {}     # per round: why kept inputs were kept

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
        for d in ("work", "corpus", "crashes", "rounds", "bugs"):
            os.makedirs(os.path.join(self.out, d), exist_ok=True)

    # -- execution ---------------------------------------------------------

    def _execute(self, inputs, trace_all=False):
        """[(input, features, samples)] for the inputs that ran cleanly and
        were traced (see trace_sample)."""
        if self.frontend == "tracer":
            return self._execute_tracer(inputs)
        t0 = time.time()
        results, crashes = runner.run_cov(self.cov_exe, inputs, self.work)
        self.stats["seconds_native"] += time.time() - t0
        self.stats["execs"] += len(inputs)
        for i, reason in crashes:
            self._save_crash(inputs[i], reason)
        if self.bug_check:
            t0 = time.time()
            found = runner.run_san(self.san_exe, inputs, self.work,
                                   own_sources=runner.own_sources(self.target_c))
            self.stats["seconds_san"] = self.stats.get("seconds_san", 0.0) \
                + time.time() - t0
            self._record_bugs(inputs, found)
        ok = sorted(results)
        if not trace_all and self.trace_sample < 1.0:
            novel = [i for i in ok if (results[i][0] - self.seen_features)
                     or inputs[i] in self._bug_inputs]
            novel_set = set(novel)
            rest = [i for i in ok if i not in novel_set]
            pick = self.rng.sample(rest, int(round(len(rest) * self.trace_sample)))
            self.stats["untraced"] = self.stats.get("untraced", 0) + len(rest) - len(pick)
            ok = sorted(novel + pick)
        if not ok:
            return []
        t0 = time.time()
        kv_crashed = []
        decls, per_input = runner.run_kvasir(self.kv_exe, [inputs[i] for i in ok],
                                             self.work, self.daikondir,
                                             ppt_list=self.ppt_list, crashed=kv_crashed,
                                             timeout=self._tool_timeout(600),
                                             var_list=self.var_list,
                                             dyncomp=self.decls is None)
        for local in kv_crashed:
            self._save_crash(inputs[ok[local]], "kvasir-crash")
        if kv_crashed:
            dead = set(kv_crashed)
            keep = [i for local, i in enumerate(ok) if local not in dead]
            per_input = {keep.index(ok[local]): v for local, v in per_input.items()
                         if local not in dead}
            ok = keep
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

    def _record_bugs(self, inputs, found):
        """Log and save each bug the first time it is seen.

        A bug is (kind, source location): every input that overflows the same
        subtraction is one bug, counted in `hits`. The first input is kept as
        the reproducer, and it is forced into the corpus so Daikon sees the
        state too.
        """
        self._bug_inputs = set()
        for i, bs in found.items():
            for b in bs:
                rec = self.bugs.get(b.key)
                if rec is None:
                    name = "%s.%s.bin" % (_sha(inputs[i]), b.kind.replace(" ", "_"))
                    with open(os.path.join(self.out, "bugs", name), "wb") as f:
                        f.write(inputs[i])
                    rec = dict(b.as_dict(), input=inputs[i].hex(), file=name,
                               round=self._round, time=self._elapsed(), hits=0)
                    self.bugs[b.key] = rec
                    self._bug_inputs.add(inputs[i])
                    self.log("    [BUG] %s at %s%s <- %s" % (
                        b.kind, b.location,
                        " in %s()" % b.function if b.function else "",
                        inputs[i].hex() or "(empty input)"))
                    self.log("          %s" % b.message)
                rec["hits"] += 1

    def _tool_timeout(self, default):
        """A Kvasir or Daikon run may use the rest of the budget plus a margin,
        never a fixed 10 minutes: under Kvasir an input can run ~50x slower
        than natively, and print_tokens once hung a run for 24 minutes."""
        if self.time_limit is None:
            return default
        return max(30.0, self.time_limit - self._elapsed() + 30.0)

    def _elapsed(self):
        return time.time() - self.t0

    def _out_of_time(self):
        return self.time_limit is not None and self._elapsed() >= self.time_limit

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
        if data in self._bug_inputs:
            reasons.append("bug")
        if new_feats and self.coverage:
            reasons.append("coverage+%d" % len(new_feats))
        if violations and self.guidance:
            reasons.append("violates %d" % len(violations))
        if progress and self.guidance and not force:
            reasons.append("closer to %d" % len(progress))
        if not reasons:
            return None
        for kind, hit in (("bug", data in self._bug_inputs),
                          ("coverage", new_feats), ("violation", violations),
                          ("closer", progress and not force)):
            if hit and not force:
                self.keep_counts[kind] = self.keep_counts.get(kind, 0) + 1

        idx = len(self.corpus)
        entry = Entry(data, samples, round_, ", ".join(reasons), self._elapsed())
        entry.violates = sorted(k for k, d in dists.items() if d == 0)
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
                                 conf_limit=self.conf_limit, extra_args=self.daikon_args,
                                 timeout=self._tool_timeout(1800) + 90)
        self.stats["seconds_daikon"] += time.time() - t0
        self.stats["daikon_runs"] += 1
        with open(os.path.join(self.out, "rounds", "round_%02d.txt" % round_), "w") as f:
            f.write(text)
        report = invariants.parse_report(text)
        report = {p: v for p, v in report.items() if ";condition=" not in p}
        refuted = self.history.observe(round_, report, self._elapsed())
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
            if self.bug_check:
                self.san_exe = runner.build_san(self.target_c, self.work)
        self._round = 0
        seeds = self._load_seeds()
        self.untraced = []
        if self.frontend == "kvasir" and self.call_budget:
            self.ppt_list, self.untraced = runner.apply_call_budget(
                self.kv_exe, seeds, self.work, self.daikondir, self.ppt_list,
                self.call_budget)
            for fn, per in self.untraced:
                self.log("[!] not traced (%.0f calls per seed input > budget %d): %s"
                         % (per, self.call_budget, fn))
        if self.frontend == "kvasir":
            try:
                self.var_list = runner.write_var_list(self.kv_exe, self.work,
                                                      self.daikondir, self.ppt_list)
            except (runner.ToolError, OSError, subprocess.CalledProcessError) as e:
                self.log("[!] tracing every global (no variable list: %s)" % e)
        # The clock starts after compiling, as AFL++'s does.
        self.t0 = time.time()
        self.log("[+] target  %s" % self.target_c)
        self.log("[+] seeds   %d" % len(seeds))
        for data, feats, samples in self._execute(seeds, trace_all=True):
            self.seen_inputs.add(data)
            self._consider(data, feats, samples, 0, force=True)
        if not self.corpus:
            raise runner.ToolError("no seed ran cleanly; nothing to infer from")
        report, _ = self._infer(0)
        # Baseline distances over the seeds, so "closer" in round 1 means
        # closer than the seeds got, not merely "measured for the first time".
        self._update_min_distances()
        n_inv = sum(len(v) for v in report.values())
        self.log("[+] round 0: %d invariants over %d ppts from %d seeds "
                 "(%d not checkable by the fuzzer)" % (
                     n_inv, len(report), len(self.corpus), len(self.unsupported)))
        self.round_log.append({"round": 0, "invariants": n_inv, "refuted": 0,
                               "corpus": len(self.corpus), "features": len(self.seen_features)})

        quiet = 0
        for r in range(1, self.rounds + 1):
            feats_before = len(self.seen_features)
            execs_before = self.stats["execs"]
            crashes_before = len(self.crashes)
            dist_before = {k: rec["min_distance"] for k, rec in self.history.inv.items()
                           if rec["refuted_round"] is None}
            self.keep_counts = {}
            self._round = r
            bugs_before = len(self.bugs)
            added = 0
            for _ in range(self.batches_per_round):
                if self._out_of_time():
                    break
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
            if self.learn_once:
                refuted = []          # rules stay fixed until the final scoring run
            else:
                try:
                    report, refuted = self._infer(r)
                except subprocess.TimeoutExpired:
                    self.log("[!] Daikon did not finish within the budget; stopping")
                    break
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
            proposed = self.history.proposed_in(r)
            closer = []
            for k, before in dist_before.items():
                rec = self.history.inv[k]
                after = rec["min_distance"]
                if (rec["refuted_round"] is None and after is not None
                        and before is not None and after < before):
                    closer.append((rec["ppt"], rec["text"], before, after))
            for rec in proposed:
                self.log("      new      %-28s %s" % (rec["ppt"], rec["text"]))
            for ppt, text, before, after in sorted(closer, key=lambda c: c[3])[:8]:
                self.log("      closer   %-28s %-30s distance %s -> %g" % (
                    ppt, text, "?" if before is None else "%g" % before, after))
            self.log("      kept: %s; executions %d; dictionary %d; crashes +%d; "
                     "bugs +%d" % (
                ", ".join("%s %d" % kv for kv in sorted(self.keep_counts.items()))
                or "nothing", self.stats["execs"] - execs_before,
                len(self.mutator.dictionary), len(self.crashes) - crashes_before,
                len(self.bugs) - bugs_before))
            self.round_log.append({
                "round": r, "invariants": n_inv, "refuted": len(refuted),
                "proposed": len(proposed), "corpus": len(self.corpus),
                "features": len(self.seen_features),
                "executions": self.stats["execs"] - execs_before,
                "kept": dict(self.keep_counts),
                "dictionary": len(self.mutator.dictionary),
                "crashes": len(self.crashes) - crashes_before,
                "bugs": len(self.bugs) - bugs_before,
                "refuted_list": [[x["ppt"], x["text"], x["violated_by"]] for x in refuted],
                "proposed_list": [[x["ppt"], x["text"]] for x in proposed],
                "closer_list": [list(c) for c in closer]})
            quiet = quiet + 1 if (not refuted and len(self.bugs) == bugs_before
                                  and (new_feats == 0 or not self.coverage)) else 0
            if quiet >= self.patience:
                self.log("[+] fixed point: %d quiet round(s)" % quiet)
                break
            if self._out_of_time():
                self.log("[+] time limit reached after %.0fs" % self._elapsed())
                break
        if self.learn_once:
            # Score the fixed round-0 rules against everything the run kept.
            try:
                _, refuted = self._infer(r)
                self.log("[+] learn-once: final Daikon run refutes %d of the round-0 "
                         "rules" % len(refuted))
            except subprocess.TimeoutExpired:
                self.log("[!] final Daikon run did not finish within the budget")
        self.stats["seconds_total"] = self._elapsed()
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
            "bugs": sorted(self.bugs.values(), key=lambda b: (b["round"], b["location"])),
            "untraced": [[fn, per] for fn, per in getattr(self, "untraced", [])],
            "mode": {"learn_once": self.learn_once, "guidance": self.guidance,
                     "coverage": self.coverage, "time_limit": self.time_limit},
            "corpus": [{"input": e.data.hex(), "round": e.round, "time": e.time,
                        "reason": e.reason, "violates": [list(k) for k in e.violates]}
                       for e in self.corpus],
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

        if self.bug_check:
            L += ["", "## Bugs found by the sanitizer build (%d)" % len(self.bugs), "",
                  "Reported by ASan/UBSan on a build without -fwrapv, whether or not "
                  "any Daikon rule predicted them. One row per (kind, location); "
                  "`hits` counts every input that triggered it.", ""]
            if self.bugs:
                L += ["| kind | location | round | hits | first input | message |",
                      "|---|---|---|---|---|---|"]
                for b in sorted(self.bugs.values(), key=lambda b: (b["round"], b["location"])):
                    L.append("| %s | `%s` | %d | %d | %s | %s |" % (
                        b["kind"], b["location"], b["round"], b["hits"],
                        _show_input(b["input"]), b["message"].replace("|", "\\|")))
            else:
                L.append("None.")
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
