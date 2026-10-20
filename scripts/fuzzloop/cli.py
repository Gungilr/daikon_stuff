"""Command line for the Daikon/fuzzer loop."""
import argparse
import os
import sys

from . import runner
from .loop import FuzzLoop


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="fuzz_loop.py",
        description="Infer invariants with Kvasir+Daikon, attack them with a "
                    "coverage- and invariant-guided fuzzer, re-infer, repeat.")
    ap.add_argument("target", help="fuzz target source, e.g. fuzz/targets/arith.c")
    ap.add_argument("-o", "--out", help="output directory (default: fuzz-out/<target>)")
    ap.add_argument("--daikon", default=os.environ.get("DAIKONDIR"),
                    help="Daikon tree with Kvasir built (default: $DAIKONDIR)")
    ap.add_argument("--seeds", help="seed file (default: <target>.seeds beside the source)")
    ap.add_argument("--rounds", type=int, default=10, help="max rounds (default 10)")
    ap.add_argument("--batches", type=int, default=3,
                    help="fuzzing batches per round, one Kvasir run each (default 3)")
    ap.add_argument("--batch-size", type=int, default=200,
                    help="inputs per batch (default 200)")
    ap.add_argument("--patience", type=int, default=2,
                    help="stop after this many rounds with nothing refuted and "
                         "no new coverage (default 2)")
    ap.add_argument("--max-len", type=int, default=64, help="max input length in bytes")
    ap.add_argument("--seed", type=int, default=0, help="RNG seed (default 0)")
    ap.add_argument("--keep-is-param", action="store_true",
                    help="keep Kvasir's `flags is_param` (off by default: it makes "
                         "Daikon report false invariants)")
    ap.add_argument("--conf-limit", type=float, default=0.0,
                    help="Daikon --conf_limit (default 0: report every invariant "
                         "the samples do not contradict, justified or not, so the "
                         "fuzzer can attack it; Daikon's own default is 0.99)")
    ap.add_argument("--no-guidance", action="store_true",
                    help="ablation baseline: keep inputs for new coverage only, "
                         "so invariants steer nothing")
    ap.add_argument("--no-coverage", action="store_true",
                    help="ablation: keep inputs for invariant progress only, so "
                         "coverage steers nothing")
    ap.add_argument("--frontend", choices=("kvasir", "tracer"), default="kvasir",
                    help="kvasir: source build traced by Kvasir (default). "
                         "tracer: STRIPPED build traced by the emulation tracer "
                         "(scripts/tracer), which also supplies coverage")
    ap.add_argument("--tier", type=int, default=7,
                    help="tracer heuristic tier for --frontend tracer (default 7)")
    ap.add_argument("--daikon-arg", action="append", default=[],
                    help="extra argument passed to Daikon (repeatable)")
    args = ap.parse_args(argv)

    problems = runner.check_tools(args.daikon, args.frontend)
    if problems:
        for p in problems:
            print("[!] " + p, file=sys.stderr)
        return 1
    out = args.out or os.path.join(
        "fuzz-out", os.path.splitext(os.path.basename(args.target))[0])
    loop = FuzzLoop(args.target, out, os.path.abspath(args.daikon), seeds=args.seeds,
                    rng_seed=args.seed, batch_size=args.batch_size,
                    batches_per_round=args.batches, rounds=args.rounds,
                    patience=args.patience, max_len=args.max_len,
                    keep_is_param=args.keep_is_param, conf_limit=args.conf_limit,
                    daikon_args=args.daikon_arg, guidance=not args.no_guidance,
                    coverage=not args.no_coverage, frontend=args.frontend,
                    tier=args.tier)
    try:
        loop.run()
    except runner.ToolError as e:
        print("[!] %s" % e, file=sys.stderr)
        return 1
    print("[+] summary: %s" % os.path.join(out, "summary.md"))
    return 0
