"""
unicorn_trace_symtab - Symbol-table-based dynamic tracer for Daikon.

Emulates a Linux ELF binary using Unicorn and produces a .dtrace file
compatible with Daikon. Uses the ELF symbol table (not DWARF) to find
functions, and reports invariants over register values rather than
named source parameters.

This is the "realistic" version that works without DWARF debug info,
suitable for stripped/optimized binaries where you only have symbol
addresses (or none at all).

For comparison with Kvasir (which requires DWARF), see unicorn_trace.py.

Example usage:
    # Basic - trace a binary and produce trace.dtrace
    unicorn_trace_symtab ./tests/test02.exe

    # Custom output paths and verbose logging
    unicorn_trace_symtab ./prog -o myprog.dtrace --json-output myprog.jsonl -v

    # Only trace specific functions by name (matched against symbol table)
    unicorn_trace_symtab ./prog --include 'add,multiply'

    # Trace every function (including library/startup) - usually noisy
    unicorn_trace_symtab ./prog --no-default-exclude

    # Merge 5 independent stack layouts into one trace, to break invariants
    # that only held because of one fixed, single-run memory address
    unicorn_trace_symtab ./prog --layouts 5
"""
from __future__ import print_function

import argparse
import os
import sys

from .emulate import Tracer
from .log import Logger


def build_parser():
    p = argparse.ArgumentParser(
        prog="unicorn_trace_symtab",
        description=(
            "Symbol-table-based dynamic tracer that produces Daikon .dtrace files. "
            "Works on binaries that have a symbol table but no DWARF debug info."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("binary", help="Path to ELF binary to trace.")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--output", default="trace.dtrace",
                     help="Daikon trace output path (default: trace.dtrace)")
    out.add_argument("--json-output", default=None,
                     help="Optional JSON trace output for debugging.")

    func = p.add_argument_group("function selection")
    func.add_argument("--start-func", default="main",
                      help="Function name to start emulation at (default: main).")
    func.add_argument("--start-addr", type=lambda x: int(x, 0), default=None,
                      help="Absolute address to start emulation at (overrides --start-func). "
                           "Useful for stripped binaries, e.g. --start-addr 0x401136.")
    func.add_argument("--include", default=None,
                      help="Comma-separated list of function names to trace exclusively.")
    func.add_argument("--exclude", default=None,
                      help="Comma-separated list of function names to skip (in addition to defaults).")
    func.add_argument("--no-default-exclude", action="store_true",
                      help="Don't apply the built-in exclude list (_start, frame_dummy, etc.).")
    func.add_argument("--scan-prologues", action="store_true",
                      help="Force function discovery via prologue scanning, even if symbols exist. "
                           "Useful for testing the stripped-binary code path.")

    emu = p.add_argument_group("emulation")
    emu.add_argument("--max-insns", type=int, default=200_000,
                     help="Stop after this many instructions (default: 200000, 0 = unlimited).")
    emu.add_argument("--timeout", type=int, default=10,
                     help="Emulation timeout in seconds (default: 10, 0 = none).")
    emu.add_argument("--stack-base", type=lambda x: int(x, 0), default=0x7fff00000000,
                     help="Base address of emulated stack (default: 0x7fff00000000).")
    emu.add_argument("--stack-size", type=lambda x: int(x, 0), default=0x100000,
                     help="Size of emulated stack (default: 0x100000).")
    emu.add_argument("--no-skip-unknown-calls", dest="skip_unknown_calls",
                     action="store_false", default=True,
                     help="Don't skip calls to functions outside the trace set (default: skip).")
    emu.add_argument("--stop-on-empty-stack", action="store_true",
                     help="Stop emulation when the call stack becomes empty.")
    emu.add_argument("--layouts", type=int, default=1,
                     help="Re-run the emulation this many times, each with the stack at a "
                          "different address, merging all samples into one trace "
                          "(default: 1). Values >1 break invariants that only held because "
                          "of one fixed memory layout (e.g. a leftover stack address that "
                          "happened to look 'related' to real data), without hiding genuine "
                          "arity-blindness - real arguments are unaffected since they don't "
                          "depend on where the stack sits.")

    # NOTE: deliberately "--tier", not "--layer". "--layers" (plural) above
    # already means stack relocation, and two near-identical flag names with
    # unrelated meanings is a standing trap. Tier selects how much semantic
    # recovery the tracer attempts; layouts selects how many times it runs.
    fz = p.add_argument_group("fuzzing")
    fz.add_argument("--fuzz-batch", default=None,
                    help="Run main once per input in this batch file (u32 LE "
                         "length + bytes per record), writing each input into "
                         "the DAIKON-FUZZ-BLOB buffer of a binary built with "
                         "fuzz/runtime/harness_bb.c. A fuzz_input_begin "
                         "marker sample separates inputs in the trace.")
    fz.add_argument("--fuzz-cov-out", default=None,
                    help="With --fuzz-batch: write one JSON line of edge "
                         "coverage per input to this file.")

    heur = p.add_argument_group("heuristics")
    heur.add_argument("--tier", type=int, default=0, choices=range(0, 10),
                      metavar="0-9",
                      help="Semantic-recovery tier (default: 0). Each tier is "
                           "cumulative and opt-in, so lower tiers keep producing "
                           "byte-identical output. "
                           "0 = raw fixed register/stack window. "
                           "1 = structural alignment with Kvasir (subexit, "
                           "EXIT0, invocation nonce). "
                           "2 = argument detection by use-before-def. "
                           "3 = return value, signed-value correction, "
                           "comparability classes. "
                           "4 = unused (covariance pointer classification; "
                           "measured as a no-op and skipped). "
                           "5 = malloc/calloc/realloc/free model. "
                           "6 = pointer dereference and struct field recovery. "
                           "7 = array bounds from allocation size. "
                           "8 = global variables, recovered from the "
                           "data sections (which survive stripping) plus "
                           "RIP-relative references and observed accesses. "
                           "Globals are 80%% of what Kvasir reports on its "
                           "own test suite. "
                           "9 = floating-point arguments and returns "
                           "(xmm0-xmm7), without which a function taking "
                           "only floats looks nullary.")
    heur.add_argument("--detect-void", action="store_true",
                      help="Tier 3+: omit `return` for functions whose callers "
                           "never read rax afterwards. Behind a flag so its "
                           "effect on the scores is separately measurable.")

    heur.add_argument("--heap-base", type=lambda x: int(x, 0), default=0x20000000,
                      help="Base of the tier-5 emulated heap (default: 0x20000000). "
                           "Kept clear of the image and the stack; shifts per "
                           "--layouts run like the stack does.")
    heur.add_argument("--heap-size", type=lambda x: int(x, 0), default=0x100000,
                      help="Size of the tier-5 emulated heap (default: 1 MiB). "
                           "Exhaustion makes malloc return NULL, degrading to "
                           "the pre-tier-5 behavior rather than corrupting memory.")

    heur.add_argument("--infer-unobserved-fields", action="store_true",
                      help="Tier 6+: when an allocation size is known but the "
                           "function read less than all of it, infer fields for "
                           "the untouched tail. Recovers members the program "
                           "never accessed (heap_read never reads its struct's "
                           "second field), at the cost of guessing their width. "
                           "Behind a flag so its effect is measurable on its own.")

    heur.add_argument("--infer-from-caller", action="store_true",
                      help="Tier 6+: when a pointee has no allocation size, use "
                           "accesses made ANYWHERE in the trace (typically the "
                           "caller initialising the object) to recover its "
                           "fields. Recovers pointees a function never "
                           "dereferences, but nothing bounds a stack object the "
                           "callee did not touch, so it can invent fields from "
                           "neighbouring locals. Off by default for that reason.")

    heur.add_argument("--tile-implies-array", action="store_true",
                      help="Tier 6+: call a uniformly tiled pointee an ARRAY "
                           "even with no length argument to corroborate it. "
                           "The default calls it a struct and emits one .offK "
                           "per element, which on a 6-element array is six "
                           "unmatched facts AND the loss of the one real "
                           "sequence fact. Measured separately because it "
                           "changes what the tool SAYS rather than how much.")

    heur.add_argument("--deref-globals", action="store_true",
                      help="Tier 8+: follow a global that HOLDS a pointer and "
                           "report the object behind it, as Kvasir does for "
                           "`::counters[]`. 65 of the 85 globals in Daikon's "
                           "suite are pointer-shaped. Measured with "
                           "--struct-globals: +171 matched facts but the "
                           "output doubles, so precision falls 22%% -> 14%%. "
                           "Off by default on the standing rule that an "
                           "invented fact costs a fuzzing consumer more than "
                           "an absent one.")

    heur.add_argument("--struct-globals", action="store_true",
                      help="Tier 8+: model a global whose accesses are of "
                           "MIXED WIDTHS as a struct with .offK fields rather "
                           "than an array. Targets the 8 struct globals in "
                           "Daikon's suite, all of which are currently called "
                           "arrays. MEASURED AS HARMFUL and kept only so the "
                           "negative result stays reproducible: it LOSES 123 "
                           "matched facts (802 -> 679) and fixes none of the 8 "
                           "structs, because a statically-initialised struct is "
                           "never written at run time and so leaves no width "
                           "evidence to be heterogeneous. Do not enable.")

    heur.add_argument("--poison-uninitialized", action="store_true",
                      help="Tier 6+: fill fresh stack pages and heap allocations "
                           "with a pattern, and report a field still holding it "
                           "as `nonsensical` rather than a number. Unicorn zeroes "
                           "fresh pages, so without this the tracer reports a "
                           "value for memory the program never wrote - the one "
                           "way its output is untrue rather than incomplete. "
                           "Approximate: a genuine value equal to the pattern is "
                           "misread.")

    debug = p.add_argument_group("debug tracing")
    debug.add_argument("--trace-instructions", action="store_true",
                       help="Log every instruction to JSON (very verbose).")
    debug.add_argument("--trace-memory", action="store_true",
                       help="Log every memory read/write to JSON.")

    log = p.add_argument_group("logging")
    log.add_argument("-q", "--quiet", action="store_true", help="Suppress non-error output.")
    log.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if not os.path.isfile(args.binary):
        print(f"[!] Binary not found: {args.binary}", file=sys.stderr)
        return 1

    log = Logger(quiet=args.quiet, verbose=args.verbose)
    tracer = Tracer(args, log)
    return tracer.run()
