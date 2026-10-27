# The fuzzing loop

Daikon proposes invariants, a fuzzer tries to break them, Daikon re-reads the
grown corpus, and the cycle repeats until it reaches a fixed point. This is the
consumer the black-box tracer was always meant to feed. Here it runs on
**source-available** targets, with Kvasir as the front-end, so the loop can be
built and measured without the tracer's open problems (no input mechanism,
~11s per iteration) in the way. Plugging the tracer in later only replaces one
box in the diagram below.

```
 seeds ──► Kvasir ──► Daikon ──► invariants ─┐
   ▲                                          │ compiled to distance checks
   │                                          ▼
 corpus ◄── keep if: new coverage,      mutate corpus, run each batch
            closer to violating an       natively (coverage, crashes)
            invariant, or violating it   and under Kvasir (values)
```

```bash
make -C daikon kvasir                     # once; needs binutils-dev (bfd.h)
export DAIKONDIR=$PWD/daikon
python3 scripts/fuzz_loop.py fuzz/targets/arith.c
#   -> fuzz-out/arith/summary.md, history.json, corpus/, crashes/, rounds/
```

---

## 1. Pieces

```
fuzz/runtime/fuzz.h      target interface + fuzz_take_* byte decoders
fuzz/runtime/harness.c   batch driver: many inputs per process
fuzz/runtime/cov.c       SanitizerCoverage runtime (no libFuzzer, no AFL)
fuzz/targets/*.c         targets, each with a .seeds file

scripts/fuzzloop/
  dtrace.py      pure   Kvasir trace: parse, split by input, renumber, re-emit
  invariants.py  pure   Daikon report -> per-sample (holds, distance) checks
  mutate.py      pure   havoc-style byte mutation, dictionary, seed files
  runner.py             gcc / native runs / Kvasir / Daikon subprocesses
  loop.py               the loop, corpus policy, history, summary
  cli.py                argument parsing
scripts/fuzz_loop.py    entry point
```

A target is one C file that defines `fuzz_target(data, size)`, decodes its
arguments with `fuzz_take_i32` and the other helpers, and calls ordinary
functions with ordinary parameters. Those functions are what Daikon reports on.
The loop compiles every target twice:

| build | flags | cost per batch | gives |
|---|---|---|---|
| `<name>.cov` | `-fsanitize-coverage=trace-pc,trace-cmp` + `cov.c` | milliseconds | edge coverage, comparison constants, crashes |
| `<name>.kv` | `-g -O0 -no-pie` (corpus `Makefile` flags) | ~1s, almost all Valgrind start-up | variable values for Daikon |

Both builds add `-fwrapv`, so signed overflow wraps deterministically. The
overflow the fuzzer finds natively is then the same value Kvasir records,
rather than undefined behaviour that two builds are free to disagree on.

## 2. How each problem was solved

### One Valgrind start-up per batch, not per input

Kvasir is the slow part: a second to start Valgrind and read DWARF, however
little the program does. The harness therefore takes a **batch file** of
length-prefixed records and runs them all in one process. Before each record
it calls `fuzz_input_begin(id)`. That function exists only to be traced: its
ENTER sample carries `fuzz_id`, and `dtrace.split_by_input` assigns every
sample that follows it, up to the next marker, to that input. The corpus is
therefore still traced and stored **per input**, and a round's Daikon run
re-reads exactly the inputs that were kept.

The marker approach requires targets to be stateless across calls, the same
contract libFuzzer imposes. Reset any globals at the top of `fuzz_target`.

### Two Kvasir behaviours that cost a factor of twenty

Both of these were found by measuring, and neither is documented by Kvasir:

1. **Kvasir sizes a pointee by its heap block.** The first harness passed
   `fuzz_target` a pointer into the batch buffer, so every traced pointer to
   the input dumped *the rest of the batch*. Trace size was quadratic: 5 MB
   for 200 inputs, **110 MB for 1000**. Each record now gets its own
   `malloc` of exactly its size.
2. **Kvasir sizes a stack array only while the frame that owns it is
   traced.** Restricting tracing to the target functions
   (`--ppt-list-file`, generated per build from `--dump-ppt-file`) cut the
   trace, and also collapsed `buffer.c`'s 16-byte `buf` to **one element**.
   Every array invariant downstream was then about `buf[0]`. The trace list
   therefore keeps `fuzz_target`, and its samples are dropped in Python
   instead.

With both fixed, a 1000-input batch traces in about a second, and Kvasir time
grows with the inputs rather than with their square.

### Coverage without libFuzzer

The machine had clang's compiler instrumentation but not the libFuzzer
runtime, and the black-box path will never have either. `cov.c` implements
the SanitizerCoverage callbacks directly, in about 150 lines, and works the
same under gcc and clang:

- **edges**, AFL-style `prev ^ cur`, with AFL's hit-count buckets. A loop
  running 9 times is a different feature from one running 3 times, which is
  what pulls `parse_digits` toward ten-digit inputs.
- **value profile** `(cmp site, popcount(a ^ b))`. Each extra matching bit of
  a comparison is a new feature.
- **comparison constants** from `trace_const_cmp*` and `trace_switch`, fed to
  the mutator's dictionary. This is how `lookup`'s `0x5eed1337` is reached in
  the first round. No amount of random mutation finds it.

PCs are taken **relative to a function in the binary**. The first version
used raw return addresses, so ASLR changed every feature in every process,
and each batch "discovered" about 800 features that were only the load address
moving. The loop never reached a fixed point.

### How Daikon steers the fuzzer: invariant distance

`invariants.compile_invariant` turns each reported invariant into a function
from one trace row to `(holds, distance)`. Distance is the search-based-testing
**branch distance** (Korel; Tracey), applied to the invariant instead of a
branch: how far the sample is from *violating* it, and 0 if and only if it
does.

| form | distance to violation |
|---|---|
| `L <= R` | `max(0, R - L + 1)` |
| `L < R` | `max(0, R - L)` |
| `L != R` | `abs(L - R)` |
| `L == R`, `one of`, `(mod m)` | 0 if violated, else 1 (no gradient exists) |
| `A[] elements P` | min over the elements |
| `(P) ==> (Q)` | distance to make P true + distance to make Q false |

Supported: linear and arithmetic expressions over scalars, `orig()`,
`size()`, `x[3]` / `x[n-1]` / `x[return]` element access, `elements`,
`one of`, `(mod m)`, `in`, implications, string and sequence equality.
Anything else compiles to `None`. It then gets no guidance but is still
attacked by Daikon re-inference. The summary reports these as `n/a`.

An input is kept when it reaches new coverage, **lowers the log-bucket of the
best distance to some invariant**, or violates one. Parent selection
weights each corpus entry by the number of invariants it is currently the
closest attacker of. The budget follows the hypotheses Daikon currently
holds, and the distances are recomputed against the new report after every
Daikon run.

### Refutation is Daikon's verdict, not the fuzzer's

An invariant is **refuted** when re-running Daikon on the grown corpus no
longer reports it. The fuzzer's evaluator only decides what to keep, so a
bug in it costs guidance, never correctness. The two are cross-checked:
Daikon falsifies on a single counterexample, so an invariant the fuzzer saw
violated that Daikon still reports is a bug. Every run lists these under
**Disagreements**. There have been none on either target.

### Defaults chosen for a fuzzing consumer

- **`--conf-limit 0`.** At Daikon's default of 0.99, 100 random samples of
  `abs_diff` do *not* produce `return >= 0`: one zero in a hundred is not
  enough to justify the bound. That is exactly the plausible-but-false
  invariant the loop exists to attack. Following this project's standing
  rule, a fuzzer can disprove a bad invariant but cannot recover one that was
  never emitted, so the loop asks Daikon for everything the samples do not
  contradict. Pass `--conf-limit 0.99` for Daikon's behaviour.
- **`flags is_param` is stripped** from Kvasir's declarations, as the tracer
  does at tier 3+. With it set, Daikon drops non-unit coefficients and
  reports invariants false on its own samples
  ([plans/README.md](plans/README.md), "Correctness issues" 1). The fuzzer
  would spend budget "refuting" facts that were never true.
  `--keep-is-param` restores it.

## 3. Results

Each target was run three times (`--seed 0..2`) with up to 10 rounds,
batches of 1000 and patience 2. Each was run again with `--no-guidance`,
which keeps inputs for new coverage only, so invariants steer nothing. That
is a plain coverage-guided fuzzer whose corpus Daikon re-reads. One round costs
about 4s of Kvasir and 0.6s of Daikon. Native execution is under 0.1s.

| target | mode | rounds to fixed point | refuted | survived | false invariants left standing* |
|---|---|---|---|---|---|
| arith | guided | 5 / 8 / 4 | 38 / 38 / 38 | 14 / 14 / 14 | 0 / 0 / 0 |
| arith | coverage only | 7 / 8 / 9 | 36 / 38 / 38 | 16 / 14 / 14 | 2 / 0 / 0 |
| buffer | guided | 5 / 6 / 5 | 46 / 45 / 47 | 50 / 50 / 49 | 0 / 0 / 0 |
| buffer | coverage only | 5 / 3 / 4 | 43 / 27 / 41 | 53 / 59 / 54 | 3 / 16 / 5 |

\* refuted by the other mode on the same seed, so demonstrably false. This
is a lower bound: an invariant that *both* modes failed to refute is not
counted.

Read per seed:

- **Guided never missed anything coverage-only refuted**, on any seed, and
  converged on arith in fewer rounds on two seeds of three.
- What coverage-only leaves standing is exactly the class distance targets:
  `return != size(buf[])-1` (needs `count_upper` to return exactly 15),
  `n >= 1` (needs the empty input), `x != 0`. None of these opens a new edge,
  so a coverage fuzzer has no reason to keep the input that breaks them.
- On buffer seed 1, coverage-only hit its fixed point after **three** rounds
  with 16 false invariants alive, including `parse_digits: return >= 0`.
  Plateauing early is worse than failing slowly, because the summary then
  reports those 16 as having survived.
- There were zero disagreements in all 12 runs: the fuzzer and Daikon never
  differed on whether an invariant had been violated.

### Invariants alone (`--no-coverage`)

The opposite ablation keeps an input only when it moves closer to violating
an invariant, or violates one. New coverage alone never keeps it.

| target | rounds to fixed point | corpus | missed vs. guided | found that guided missed |
|---|---|---|---|---|
| arith | 4 / 4 / 4 | 21 / 18 / 20 | 0 / 0 / 0 | 0 / 0 / 0 |
| buffer | 10 / 5 / 6 | 29 / 35 / 35 | 0 / 0 / 1 | 2 / 0 / 1 |

On these two targets invariants alone are about as good as both metrics
together, with a corpus 3-7x smaller. Both targets flatter it, though:
`fuzz_target` calls every function on every input, so there is no code
reachable only through a branch. Daikon has no invariants about code that
has never run, so invariant distance cannot steer toward it. That case is
untested here and is where coverage should matter.

What the loop finds on `arith.c`, every seed: `abs_diff: return >= 0`
refuted by a wrapping subtraction (a real bug, by `-fwrapv` design here);
`lookup: return >= 0` refuted by `0x5eed1337`, reached through the
trace-cmp dictionary; the seed bias (`x >= 1`, `return == 1`, `key ==
return`) gone in round 1. The control holds: `clamp`'s `lo <= return` and
`hi >= return` survive. On `buffer.c`, `parse_digits: return >= 0` falls to a
run of fifteen `9`s, and `n >= 1` falls to the empty input.

## 3b. The bug checker (source mode)

Daikon can only flag a property it has already proposed. In a single-seed
run it never proposed `abs_diff: return >= 0`, so the 5 inputs that overflowed
`abs_diff` went unreported. The research behind the fix is in
[../reports/Detecting overflows in the fuzz loop.md](../reports/Detecting%20overflows%20in%20the%20fuzz%20loop.md).

Every batch now also runs on a **third build** of the target:
`-O0 -g -fsanitize=address,undefined -fsanitize-recover=undefined`, compiled
with `harness.c -DFUZZ_SAN`. Any ASan or UBSan report becomes a bug,
independent of the invariants.

- **No `-fwrapv`.** With `-fwrapv`, gcc silently drops UBSan's
  signed-overflow check. Verified with gcc 13.3: the overflow prints a wrong
  answer and exits 0. The traced and coverage builds keep `-fwrapv`, so Kvasir
  still records the wrapped value.
- **Attribution.** The harness writes `@@FUZZ-INPUT <id>` to stderr before
  each record, and `fuzzloop/bugs.py` assigns every report to the input
  before it.
  - UBSan reports are recoverable, so the batch continues.
  - An ASan report aborts the process. The runner records the bug and
    re-runs the batch from the next input.
- **Deduplication.** A bug is `(kind, file:line:col)`. Its first input is
  saved to `bugs/` and forced into the corpus, and `hits` counts every input
  that reached it.
- **Reporting.** Each new bug is logged as `[BUG]` the moment it appears, and
  listed in `summary.md` and `history.json`. A round that finds a new bug
  does not count as quiet.
- **Opt-out:** `--no-bug-check`. Not available with `--frontend tracer`,
  because it needs source.

Results (seed 0):

| target | start | bug | location | round | hits |
|---|---|---|---|---|---|
| arith.c | 1 seed | signed overflow, `b - a` in `abs_diff` | `arith.c:35:26` | 1 | 60 |
| buffer.c | 12 seeds | signed overflow, `v * 10` in `parse_digits` | `buffer.c:41:15` | 1 | 12 |

In the single-seed `arith` run the loop never proposed `return >= 0`, yet
the checker reports the overflow in round 1. The *other* subtraction in
`abs_diff`, `a - b` (which overflows when `a` is near INT_MAX and `b` is very
negative), was never triggered in that run. The fuzzer has no guidance
toward it. Overflow "headroom" guidance (step 4 of the report's plan) is what
would aim at it.

## 4. Limits, stated plainly

- **Branch distance is local.** For `parse_digits`, `return >= 0` is
  violated only by an overflow, far from zero. The distance pulls the other
  way, toward `return == 0`, which is the closest *non-violating* point.
  The overflow is found by coverage (loop hit-count buckets reward longer
  digit runs) and by the long-run insert operator, not by distance. Distance
  helps when the violation lies on the near side of the bound.
- **Survival is not proof.** "Survived" means attacked for `patience` rounds
  with nothing refuted and no new coverage. The CERTIFIED / CONJECTURED split
  in [FORMAL-METHODS.md](FORMAL-METHODS.md) §(d) is what would tell the loop
  that attacking `lo <= return` is provably wasted work. The `closest
  approach` column is the honest substitute: it reports how hard each
  survivor was pushed.
- **Some survivors are harness artifacts.** `buf has only one value`, `size(buf[])
  == 16` and `buf != null` are true for every input, because `buf` is
  always the same stack array. They describe the harness, not the function.
- **Conditional program points** (`;condition=...`) are not evaluated by the
  fuzzer, because deciding which samples they cover means re-implementing
  Daikon's splitter. Daikon still re-checks them every round.
- **Targets must be stateless** between `fuzz_target` calls, as above.

## 5. The black-box front-end: your tracer on a stripped binary

```bash
python3 scripts/fuzz_loop.py fuzz/targets/arith.c  --frontend tracer --tier 3
python3 scripts/fuzz_loop.py fuzz/targets/buffer.c --frontend tracer --tier 7
```

The target is compiled once with `fuzz/runtime/harness_bb.c` and stripped with
`strip --strip-all`. From then on the loop only touches the stripped file.
The emulation tracer (`scripts/tracer`, run with `--scan-prologues`) supplies
**both** halves: the variable values Daikon needs, and the edge coverage and
comparison constants the fuzzer needs. No Kvasir, no native build, no
symbols, no DWARF.

### Input mechanism

This was the open item since the phase-5 retrospective. Feeding the program
through a file or stdin would mean emulating libc. Instead the harness owns one
initialized global, which lands in `.data`, and section contents survive
stripping:

```
struct { char magic[16] = "DAIKON-FUZZ-BLOB"; uint32_t len; uint8_t data[4096]; }
```

With `--fuzz-batch FILE`, the tracer scans the loaded image for the magic and
requires exactly one hit. For each input it starts a **fresh emulator**,
writes `len` and the bytes, and runs `main` until it returns. Before each
input it buffers a `fuzz_input_begin` marker sample. That is the same marker
the Kvasir path traces, so `dtrace.split_by_input` works unchanged. A fresh
emulator per input also means targets need not be stateless in this mode.
Arity, footprint and global evidence still accumulate across inputs, exactly
as across `--layouts`, so each function's schema is decided over the whole
batch. Without `--fuzz-batch` nothing changes: the golden traces are
byte-identical.

`--fuzz-cov-out FILE` writes one JSON line per input with:

- **edges**: AFL-style `(prev >> 1) ^ cur` over basic blocks, from
  `UC_HOOK_BLOCK`.
- **consts**: immediates of every executed `cmp`. This is the stripped-binary
  analogue of trace-cmp, and it is how `lookup`'s `0x5eed1337` is reached.
- **status**: `ok`, an emulator error, or `insn-limit`. Anything but `ok` is
  filed as a crash or hang.

### Why the corpus is re-traced every round

Kvasir's declarations come from DWARF and never change. The tracer's come
from evidence: arity, pointees and array bounds are decided per run, so two
batches can declare the same function differently. Mixing their samples would
hand Daikon conflicting declarations. In tracer mode, the loop therefore
re-traces the whole corpus in a single run before every Daikon pass. That
gives one consistent set of declarations, and every entry's samples are
refreshed to match. It costs one extra tracer run per round.

### Results (seed 0, batches of 300, 2 per round)

| target | rounds | refuted | survived | wall time | disagreements |
|---|---|---|---|---|---|
| arith (tier 3) | 5 | 56 | 24 | 80s | 0 |
| buffer (tier 7) | 6 | 117 | 86 | 167s | 0 |

The same bugs fall as with Kvasir, found from the stripped binary:

- `sub_0x401142` (abs_diff): `return >= 0`, by a wrapping subtraction.
- `sub_0x401168` (lookup): `return >= 0`, by the magic key from the cmp
  dictionary. Its survivor is `return >= -1`.
- `sub_0x4011a8` (parse_digits): `return >= 0`, by fifteen `9`s.

The control survives: `sub_0x40118b` (clamp) keeps `arg1 <= return` and
`arg2 >= return`.

### What the loop shows about the tracer

Rules the fuzzer cannot refute are either true or an artifact that is
identical on every input. The second kind points straight at tracer
heuristics:

- **`size(arg0[]) == 64` for a 16-byte buffer.** The tracer bounds a stack
  pointee with no allocation size by guessing, and here it guesses four times
  too large. Every invariant mentioning `size(arg0[])` inherits the error.
  `arg1 < size(arg0[])-1` survives with closest approach 47, because the
  fuzzer cannot push a 16-byte input to 63.
- **`fuzz_target` has a `return`.** It is `void`; tier 3 reports `rax` unless
  `--detect-void` is passed.
- **`arg0 has only one value` / `arg0 != null`** on every function: the buffer
  is always the same stack array. This is a harness artifact, as in the Kvasir
  mode.

### Cost

Measured from the two runs above, after taking out about 2s of tracer
start-up per batch: about **15ms per input at tier 3** (arith) and **33ms at
tier 7** (buffer). The Kvasir mode amortizes to about 1.5ms per input at batch
size 1000. So the tracer is roughly 10-20x slower per execution than the
Kvasir mode, and far slower than native, because every instruction goes
through a Python hook. This is
the speed gap the Binvariants comparison predicted. The fast path would be
unicornafl for coverage, with the full tracer run only on inputs worth
keeping.

### Known gaps

- **Crashes are mostly invisible.** The tracer lazily maps unmapped memory,
  so a wild pointer reads zeros instead of faulting. Only emulator errors and
  the instruction limit are reported.
- **The start function is dropped by name; `fuzz_target` is not.** It cannot
  be recognized without symbols, so its invariants (input length, buffer
  pointer) appear in the report.
- **Calls into libc are skipped.** That is why `fuzz.h` copies with a loop
  instead of `memcpy`. Targets that depend on libc results will be traced
  wrong.

Everything downstream of the front-end (splitting, renumbering, distance,
refutation, the summary) is shared between the two modes.
