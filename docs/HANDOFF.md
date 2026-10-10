# Hand-off: state of the project, 2026-10-09

For whoever picks this up next, human or model, in a fresh session. Read this
first, then [README.md](../README.md), then [HEURISTICS.md](HEURISTICS.md).

## What the project is

A Unicorn-emulation tracer that turns a **stripped x86-64 ELF binary** into a
Daikon `.dtrace`, so Daikon can infer invariants without debug info. Kvasir,
Daikon's DWARF-reading front end, is the oracle. The long-term goal is a
fuzzing loop in which invariants steer input generation and new inputs refine
the invariants.

Headline scores against Kvasir (README): tcas with 501 inputs **94/90/92**
precision/recall/F1; our 10 fixtures 65/92/76; Daikon's 29 test programs
24/17/20. The gap is almost entirely *description* (types, shapes, pointer
depth), not observation.

## What happened since the last commit (`5e312b6`)

Everything below is in this push.

| area | what | where |
|---|---|---|
| phase 11 | value cap (no crash on huge values), `--gzip` output | `scripts/tracer/writer.py`, `deref.py`, [plans/phase11.md](plans/phase11.md) |
| phase 12 | program input: `--argv`, `--argv-file`, `atoi`/`exit` models, many runs merged | `emulate.py`, [plans/phase12.md](plans/phase12.md) |
| literature review | 46 papers mapped to each open problem; methods proposed | [RELATED-WORK.md](RELATED-WORK.md) |
| rule catalogue | all 42 inference rules, strengths, flaws, verdicts | [HEURISTICS.md](HEURISTICS.md) |
| phase 13 plan | type recovery, rewritten after finding 3 causes, not 1 | [plans/phase13.md](plans/phase13.md) |
| observability | what is observed vs derived, case by case | [OBSERVABILITY.md](OBSERVABILITY.md) |
| new flags | `--dump-inferences PATH` (JSON of every conclusion), `--ignore-globals` | `cli.py`, `emulate.py`, `infer.py` |
| audit tooling | grade every rule against DWARF on a 357-binary corpus | `scripts/audit_heuristics.py`, `scripts/audit_corpus.py` |
| measurement | comparability effect vs Kvasir's DynComp | `scripts/measure_comparability.py` |
| doc corrections | `bc` runtime baseline, oracle configuration, dead parameters, mixed int/float order | README, TOOL, VERIFICATION, EVALUATION-KVASIR-SUITE, FORMAL-METHODS |

No inference rule's behaviour changed. The two new flags are opt-in and the
trace is byte-identical without them. **468 tests** (369 unit + 99 end to end).

## The audit: method and results

`audit/` is gitignored, so the numbers live here. Rebuild with
`python scripts/audit_corpus.py all` (about two hours).

**Corpus.** 119 programs × `-O0/-O1/-O2` = 357 binaries: 68 single-file LLVM
test-suite benchmarks (pinned commit `57fbfe58ed5b`) and 51 C programs from
Daikon's Kvasir suite. Shootout's `hash` did not compile. Ground truth comes from
DWARF plus the System V AMD64 classification, read only by the grader.

**Two passes.** Functions traced with `--ignore-globals` at 300k instructions;
globals in a second run at 40k. Reason: each sample snapshots the data
sections, so Stanford's Towers took 2.5 GB with globals and 72 MB without.

| rule | O0 | O1 | O2 |
|---|---|---|---|
| H5-H8 integer and stack arity | 97.9% | 82.1% | 77.9% |
| H11 float argument count | 91.5% | 92.3% | 90.3% |
| H9 argument width | 95.7% | 97.3% | 95.1% |
| H17 pointer verdict | 85.5% | 75.4% | 73.6% |
| H14 void detection | 79.3% | 84.7% | 72.0% |
| H16 float return | 92.7% | 96.4% | 96.6% |
| H15 unsigned return | 89.9% | 91.4% | 87.0% |
| H30 global extent | 99.9% | 99.6% | 99.6% |
| H32 global shape | 92.8% | 92.7% | 92.7% |
| H1 function discovery, stripped | 100% | 100% | 100% |
| H2 recovering `main` | 117/117 | 117/117 | 117/117 |

Columns grade different function sets (522 / 585 / 345 executed), so read
level-to-level changes as suggestive. 64 of 117 runs hit the budget.

**Findings.**

- **Arity degrades off `-O0`**, as predicted: wrong answers 11, then 104, then 75.
- **Function discovery never degrades**, contrary to HEURISTICS.md H1. The scanner
  keys on `endbr64`, which Ubuntu's gcc emits on every function.
- **Struct globals: 0 of 147 right.** 95 structs or unions, 52 arrays of structs.
  Not one member name recovered. One-run evidence breakdown:
  14 decidable now by a sound rule (straddling access, or periodic layout);
  11 uniform width (some erased by the widest-access bug, some genuine ties);
  75 never touched but referenced by code (coverage: fuzzing or longer runs);
  47 never touched and no instruction references them (unreachable dynamically).
- **H16 confirmed on real code:** 13 integer-returning functions declared to
  return a double at `-O0`.
- **H38 confirmed and cascades:** function-pointer calls into the program are
  skipped. In Shootout `methcall`, skipping `call [rbx+0x10]` zeroes `rax`, so
  the next `call [rax+8]` reads address 8.
- **New bug: argv is missing from the memory map.** `emulate.py:434` maps it in
  Unicorn but never calls `memmap.add_region`, so `main`'s `argv` is typed as an
  integer and its strings are never captured. Affects every `--argv` run.
- **Pointer misses at `-O0`:** 96 total; 63 were NULL on every call, 29 nonzero
  but outside the map (mostly argv), 4 NULL on some calls.
- **Skipped calls dominate fidelity:** 114,197 state-changing skipped calls at
  `-O0` vs 1,460 output-only. Top: `_setjmp`, `ungetc`, `fscanf`, `sin`,
  `longjmp`.
- **`-O2` shows the first tail calls:** 3 return-address mismatches.
- **Comparability is not a precision lever.** Only 56 of 1,955 unmatched facts
  relate variables Kvasir's DynComp kept apart (RELATED-WORK §1a).
- **The `bc` 841 s vs 36 s comparison was not fair.** Kvasir's run used
  `--ignore-globals`; ours declared 112 globals.

## Open work, in suggested order

From HEURISTICS.md's "Order of work", updated by the audit.

1. **Fix the argv memory-map bug.** One line; add a regression test.
2. **Fix H16 and H38.** `tests_py/test_e2e_dump.py` pins both as known-wrong;
   invert those assertions when fixed.
3. **Scorer: ABI-aware argument alignment** (removes tier 9's 12-fact loss) and a
   canonical equality-class leader (scorer limitation 9).
4. **Phase 13 part 1:** store every access instead of the widest (H31), sound
   elimination only, add array-of-struct with the periodicity test.
5. **Model the state-changing libc calls** (memset, memcpy, strdup, strlen,
   toupper, then setjmp/longjmp and file input) plus a value-fidelity check.
6. **Fix the global-snapshot memory cost** so long runs with globals are viable.
7. **Provenance tracking** (RELATED-WORK §2), which unlocks pointer depth, struct
   by value and type sinks.
8. **The fuzzing loop**, with hypothesis-set shrinking as one reward signal.
9. **Update HEURISTICS.md** with the measured rates above; H1's flaw and H32's
   "0 of 8" are now out of date.

## How to run things

The pipeline is Linux-only (Kvasir needs Valgrind). On the original machine it
runs under WSL from `/mnt/c/Users/4nime/Desktop/cybersecurity/research`.

```bash
python3 -m venv venv && ./venv/bin/pip install unicorn capstone pyelftools pytest
./venv/bin/pytest -q </dev/null                 # all tests; stdin MUST be closed
./venv/bin/pytest -q -m "not e2e" </dev/null    # unit only, ~25 s
python scripts/unicorn_dwarf.py prog.exe -o prog.dtrace --tier 9 --detect-void \
       --dump-inferences prog.json
python scripts/audit_heuristics.py --binary prog.exe --dump prog.json --dtrace prog.dtrace
python scripts/audit_corpus.py all --jobs 3     # the whole audit
```

**Not in the repo:** `daikon/` (clone it and build Kvasir for oracle runs and
the Kvasir test programs), `venv/`, compiled `*.exe`, and `audit/`. The 10
fixtures in `tests/` rebuild with `make`.

**Gotchas that cost time:**

- **Close stdin for pytest and the tracer.** An open stdin hung the full suite
  for 30 minutes.
- **Pass arguments that start with a dash as `--argv=-v1 file`.** The spaced form
  makes argparse read them as flags; this broke gzip and bzip2 in the audit.
- **Memory.** Tier 8+ on programs with large, changing globals can exhaust RAM.
  Use `--ignore-globals` or a small `--max-insns`.
- **On Windows via WSL:** `$VAR` in `wsl.exe -- bash -lc '...'` arguments
  expands to empty; pipe scripts through `bash -s <<'EOF'` instead. Doubled
  backslashes in inline scripts arrive halved.
- **`emulate.py` uses CRLF line endings**; the other modules use LF. Keep each
  file's convention.
- **The WSL VM can fail to start** with "insufficient system resources"; it
  recovered on retry.
