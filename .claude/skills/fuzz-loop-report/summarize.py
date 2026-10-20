#!/usr/bin/env python3
"""Numbers for a fuzz-loop report, straight from each run's history.json.

    summarize.py RUN_DIR [RUN_DIR...]        tables for each run
    summarize.py --compare RUN_A RUN_B       what each refuted that the other kept

Everything printed comes from the files; nothing is estimated.
"""
import argparse
import json
import os
import sys


def load(run):
    with open(os.path.join(run, "history.json")) as f:
        return json.load(f)


def frontend(h):
    return "blackbox (tracer)" if "tracer_runs" in h["stats"] else "source (Kvasir)"


def seconds(h):
    s = h["stats"]
    return (s.get("seconds_tracer", 0) + s.get("seconds_kvasir", 0)
            + s.get("seconds_native", 0) + s.get("seconds_daikon", 0))


def refuted(h):
    return [r for r in h["invariants"] if r["refuted_round"] is not None]


def alive(h):
    return [r for r in h["invariants"] if r["refuted_round"] is None]


def results_row(run, h):
    return "| %s | %s | %s | %d | %d | %d | %d | %d | %.0fs |" % (
        os.path.basename(h["target"]), frontend(h), os.path.basename(run.rstrip("/")),
        len(h["rounds"]) - 1, h["rounds"][0]["invariants"], len(refuted(h)),
        len(alive(h)), len(h["disagreements"]), seconds(h))


def show_input(x):
    if x is None:
        return "-"
    return "`%s`" % x if x else "(empty input)"


def detail(run, h):
    print("\n## %s\n" % run)
    print("| round | rules | refuted | corpus | features |")
    print("|---|---|---|---|---|")
    for r in h["rounds"]:
        print("| %(round)d | %(invariants)d | %(refuted)d | %(corpus)d | %(features)d |" % r)
    if any("executions" in r for r in h["rounds"]):
        print("\nper round:")
        for r in h["rounds"][1:]:
            kept = ", ".join("%s %d" % kv for kv in sorted(r.get("kept", {}).items()))
            print("  round %d: %d executions, kept %d (%s), refuted %d, newly proposed %d, "
                  "dictionary %d, crashes %d" % (
                      r["round"], r.get("executions", 0),
                      sum(r.get("kept", {}).values()), kept or "-", r["refuted"],
                      r.get("proposed", 0), r.get("dictionary", 0), r.get("crashes", 0)))
            for ppt, text, by in r.get("refuted_list", []):
                print("      refuted   %-30s %-34s <- %s" % (ppt, text, show_input(by)))
            for ppt, text in r.get("proposed_list", []):
                print("      proposed  %-30s %s" % (ppt, text))
            for ppt, text, before, after in sorted(r.get("closer_list", []),
                                                   key=lambda c: c[3])[:8]:
                print("      closer    %-30s %-34s %s -> %g" % (
                    ppt, text, "?" if before is None else "%g" % before, after))
    s = h["stats"]
    tool = s.get("seconds_tracer", 0) + s.get("seconds_kvasir", 0)
    execs = s["execs"]
    print("\ncost: %d executions, %.1fs tracing (%.1f ms/input incl. start-up), "
          "%.1fs Daikon over %d runs, %.1fs native"
          % (execs, tool, 1000.0 * tool / execs if execs else 0,
             s["seconds_daikon"], s["daikon_runs"], s.get("seconds_native", 0)))
    print("crashes: %d   disagreements: %d   final corpus: %d"
          % (len(h["crashes"]), len(h["disagreements"]), h["corpus_size"]))
    print("\nrefuted (%d):" % len(refuted(h)))
    for r in sorted(refuted(h), key=lambda r: (r["refuted_round"], r["ppt"])):
        print("  r%-2d %-32s %-36s <- %s" % (r["refuted_round"], r["ppt"], r["text"],
                                           show_input(r["violated_by"])))
    print("\nsurvived (%d), with closest approach:" % len(alive(h)))
    for r in sorted(alive(h), key=lambda r: (r["ppt"], r["text"])):
        md = r["min_distance"]
        print("  %-32s %-36s %s" % (r["ppt"], r["text"], "n/a" if md is None else "%g" % md))


def compare(a, b):
    ha, hb = load(a), load(b)
    key = lambda r: (r["ppt"], r["text"])
    ra, rb = {key(r) for r in refuted(ha)}, {key(r) for r in refuted(hb)}
    la, lb = {key(r) for r in alive(ha)}, {key(r) for r in alive(hb)}
    print("| | %s | %s |" % (a, b))
    print("|---|---|---|")
    print("| refuted | %d | %d |" % (len(ra), len(rb)))
    print("| survived | %d | %d |" % (len(la), len(lb)))
    print("| refuted by the other, left standing here | %d | %d |"
          % (len(la & rb), len(lb & ra)))
    for name, keys in ((a, la & rb), (b, lb & ra)):
        if keys:
            print("\nleft standing in %s but refuted by the other:" % name)
            for p, t in sorted(keys):
                print("  %-32s %s" % (p, t))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--compare", action="store_true")
    args = ap.parse_args(argv)
    if args.compare:
        if len(args.runs) != 2:
            ap.error("--compare takes exactly two run directories")
        compare(*args.runs)
        return 0
    hs = [(r, load(r)) for r in args.runs]
    print("| target | front-end | run | rounds | rules proposed (round 0) | refuted "
          "| survived | disagreements | time |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r, h in hs:
        print(results_row(r, h))
    for r, h in hs:
        detail(r, h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
