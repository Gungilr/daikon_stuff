# Benchmark: Daikon loop vs. learn-once vs. AFL++

```bash
python3 scripts/bench/bench.py --budget 180 --seeds 3 --jobs 3 --out bench-out/full
```

Raw results: `bench-out/full/results.json` (gitignored, reproducible with the
command above).

## Setup

| | |
|---|---|
| targets | `fuzz/targets/{arith,buffer,packet,stack,stats}.c` |
| planted bugs | 10: 3 memory, 4 undefined behaviour (overflow, divide by zero), 3 logic |
| budget | 180 s per run, wall clock, counted after compiling |
| seeds | 3 random seeds per tool and target (45 runs), same seed inputs for every tool |
| machine | 4 cores, 3 runs at a time |

**Tools**

| tool | what it is |
|---|---|
| **loop** | `scripts/fuzz_loop.py`, source mode: Kvasir + Daikon re-learn every round, invariant-distance and coverage guidance, ASan+UBSan bug checker |
| **learn-once** | the same with `--learn-once`: Daikon learns from the seeds once, and the fuzzer attacks that fixed set (InvsCov-style) |
| **AFL++** | 4.21c, `afl-clang-fast`, persistent mode, ASan + UBSan, CmpLog (`-c`): the standard strong configuration |

**Scoring.** Each planted bug is marked `FUZZ_BUG(id, condition)`. The marks
print only in a separate oracle build, so no tool can see them. Every input a
tool kept (its corpus or queue, plus its bug or crash files) is replayed
through the oracle:

- **triggered**: some kept input makes the bug happen, whether or not the
  tool noticed.
- **reported**: the tool flagged it:
  - a sanitizer report or AFL++ crash whose input triggers the bug, or
  - (Daikon modes only) the triggering input broke a live Daikon rule in
    the bug's own function when it was kept.

## Results

Each cell gives runs that found the bug (out of 3), with the median seconds
in brackets.

| target | bug | kind | loop trig. | loop rep. | learn-once trig. | learn-once rep. | AFL++ trig. | AFL++ rep. |
|---|---|---|---|---|---|---|---|---|
| arith | abs_diff_a_minus_b | UB | 3/3 (7) | 3/3 (7) | 3/3 (2) | 3/3 (2) | 3/3 (0) | 3/3 (0) |
| arith | abs_diff_b_minus_a | UB | 3/3 (7) | 3/3 (7) | 3/3 (2) | 3/3 (2) | 3/3 (0) | 3/3 (0) |
| arith | lookup_magic | logic | 3/3 (9) | 3/3 (9) | 3/3 (3) | 3/3 (3) | 3/3 (0) | **0/3** |
| buffer | parse_digits_overflow | UB | 3/3 (2) | 3/3 (2) | 3/3 (2) | 3/3 (2) | 3/3 (0) | 3/3 (0) |
| packet | checksum_negative | logic | 3/3 (4) | 3/3 (4) | 3/3 (4) | 3/3 (4) | 2/3 (1) | **0/3** |
| packet | packet_copy_overflow | memory | 3/3 (4) | 3/3 (4) | 3/3 (4) | 3/3 (4) | 3/3 (0) | 3/3 (0) |
| stack | stack_push_overflow | memory | **2/3 (104)** | **2/3 (104)** | 3/3 (40) | 3/3 (40) | 3/3 (0) | 3/3 (0) |
| stack | stack_pop_underflow | memory | 3/3 (3) | 3/3 (3) | 3/3 (2) | 3/3 (2) | 3/3 (0) | 3/3 (0) |
| stats | mean_div_zero | UB | 3/3 (2) | 3/3 (2) | 3/3 (2) | 3/3 (2) | 3/3 (0) | 3/3 (0) |
| stats | max3_wrong | logic | 3/3 (3) | 3/3 (3) | 3/3 (3) | 3/3 (3) | **0/3** | **0/3** |

| tool | triggered | reported | memory/UB reported | logic reported | median executions |
|---|---|---|---|---|---|
| loop | 29/30 | 29/30 | 20/21 | 9/9 | 93,006 |
| learn-once | 30/30 | 30/30 | 21/21 | 9/9 | 106,006 |
| AFL++ | 26/30 | 21/30 | 21/21 | 0/9 | 1,247,531 |

### Precision of the logic-bug signal

"Reported" for a logic bug only means the triggering input broke a rule in
the right function. Correct inputs break rules too. Counting every kept input
after round 0 that broke a live rule:

| target | tool | inputs breaking a rule | of those, a planted logic bug | false alarms |
|---|---|---|---|---|
| arith | loop | 346 | 7 | 339 |
| buffer | loop | 79 | 0 | 79 |
| packet | loop | 194 | 5 | 189 |
| stack | loop | 92 | 0 | 92 |
| stats | loop | 65 | 7 | 58 |
| **all** | **loop** | **776** | **19** | **757 (precision 2.4%)** |
| **all** | **learn-once** | **861** | **18** | **843 (precision 2.1%)** |

## What it shows

1. **Memory and UB bugs: AFL++ is faster; detection is a tie.** All three
   tools reported all 21 memory/UB bug-runs, except the loop missing
   `stack_push_overflow` once. AFL++ found each within 1 s; the Daikon
   modes took 2-9 s. AFL++ ran 13x more executions (1,247,531 vs 93,006
   median). These bugs come from the sanitizers, not from Daikon, so this is
   a speed contest, and AFL++ wins it.
2. **The bug that needs a long input: AFL++ 0 s, learn-once 40 s, loop
   104 s and 1 miss.** `stack_push_overflow` needs 9 pushes in one input.
   It is the only bug where search effort decides the result, and raw
   throughput wins.
3. **Logic bugs: only the Daikon modes see them, but noisily.** AFL++
   *triggered* `lookup_magic` in 3/3 runs and `checksum_negative` in 2/3,
   and reported neither: there was no crash. It never even kept a
   `max3_wrong` input (0/3), because that input reaches no new code. The
   Daikon modes kept and flagged all 9. Their flags are about 2.4% precise,
   though: 19 true alarms among 776. As a logic-bug *report* this is not
   usable yet. As a *ranking* problem, it is the one Eclat solved (2.3% to
   30% precision by filtering on entry/exit violations).
4. **Re-learning did not help on these targets.** learn-once was as good
   or better everywhere: 30/30 vs 29/30, `arith` bugs at 2 s vs 7 s, and
   `stack_push_overflow` 3/3 at 40 s vs 2/3 at 104 s. It also ran 14% more
   executions (106,006 vs 93,006), since it skips a Daikon run and a corpus
   re-trace every round. Every bug here falls within seconds, before
   re-learned rules could matter, so this says re-learning costs throughput.
   It does not say re-learning never helps.

## Caveats

- **The targets are tiny.** Five programs written alongside the tool, each
  with 1-3 functions. Real programs have deep, gated code, where coverage
  guidance and AFL++'s throughput matter more, and where untested functions
  have no rules.
- **3 seeds per cell.** Medians over 3 runs are rough.
- **Generous logic scoring.** The credit is generous to the Daikon modes;
  the precision table is the correction.
- **Shared cores.** Three runs at a time on 4 cores. Kvasir and Daikon's
  JVM use more than one core, which favours AFL++ slightly.
