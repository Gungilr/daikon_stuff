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

---

# Extended benchmark: 6 real-world-style programs, 33 bugs

The five toy targets above are too small to show where the approach
struggles. This round uses programs nobody wrote for this tool:

```bash
python3 scripts/bench/bench.py --budget 180 --seeds 3 --jobs 3 --max-len 512 \
    --call-budget 20 --targets tcas,tot_info,replace,print_tokens,print_tokens2,juliet \
    --out bench-out/ext
```

| target | source | size | planted bugs |
|---|---|---|---|
| `tcas` | Siemens suite (aircraft collision avoidance) | 9 functions | 4 logic (mutation faults) |
| `tot_info` | Siemens (statistics) | 7 functions | 4 logic |
| `replace` | Siemens (regex search-and-replace) | 21 functions | 4 logic |
| `print_tokens` | Siemens (lexer, table-driven) | 18 functions | 3 logic |
| `print_tokens2` | Siemens (lexer, hand-written) | 19 functions | 4 logic |
| `juliet` | NIST Juliet C 1.3, 14 `_fgets_` cases in one target | 14 cases | 5 UB, 7 memory, 2 logic |

Siemens faults are one-token mutations in the style of the original suite,
made by `scripts/bench/make_siemens.py`. A logic fault counts as triggered
only if the state is infected **and** the program's output changes (checked
against a build with that fault reverted). Juliet flaws carry their exact
misbehaviour condition. Scoring is otherwise as above.

`--call-budget 20` skips tracing any function called more than 20 times per
seed input on average. Kvasir costs about 1.4 ms per traced call, and
without the budget `replace` ran at 0.6 s per input.

## Results

Totals over 99 bug-runs (33 bugs x 3 seeds), 180 s each:

| tool | triggered | reported | reported: memory/UB | reported: logic | alarm precision | median executions |
|---|---|---|---|---|---|---|
| loop | **68/99** | 50/99 | 30/45 | 20/54 | 1.4% (43/3,033) | 6,008 |
| learn-once | 63/99 | **51/99** | 30/45 | **21/54** | 1.8% (56/3,065) | 5,008 |
| AFL++ | 62/99 | 47/99 | 30/45 | 17/54 | – | 540,083 |

Per bug (runs out of 3, median seconds to the first find):

| target | bug | kind | loop trig. | loop rep. | learn-once trig. | learn-once rep. | AFL++ trig. | AFL++ rep. |
|---|---|---|---|---|---|---|---|---|
| tcas | tcas_nozcross_const | logic | 3/3 (18 s) | 3/3 (18 s) | 3/3 (17 s) | 3/3 (17 s) | 1/3 (0 s) | 1/3 (0 s) |
| tcas | tcas_climb_ge | logic | 3/3 (19 s) | 3/3 (19 s) | 3/3 (17 s) | 3/3 (17 s) | 2/3 (0 s) | 0/3 |
| tcas | tcas_above_le | logic | 1/3 (111 s) | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| tcas | tcas_enabled_ge | logic | 3/3 (19 s) | 3/3 (19 s) | 3/3 (18 s) | 3/3 (18 s) | 0/3 | 0/3 |
| tot_info | tot_info_gt | logic | 3/3 (27 s) | 2/3 (19 s) | 3/3 (26 s) | 3/3 (26 s) | 3/3 (1 s) | 3/3 (8 s) |
| tot_info | tot_lgamma_terms | logic | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| tot_info | tot_qgamma_le | logic | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| tot_info | tot_pi_ge | logic | 1/3 (10 s) | 1/3 (10 s) | 1/3 (13 s) | 1/3 (13 s) | 2/3 (3 s) | 0/3 |
| replace | rep_dash_lt | logic | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| replace | rep_closure_ge | logic | 3/3 (3 s) | 3/3 (3 s) | 3/3 (3 s) | 3/3 (3 s) | 3/3 (0 s) | 3/3 (0 s) |
| replace | rep_ditto_le | logic | 3/3 (153 s) | 0/3 | 3/3 (140 s) | 0/3 | 3/3 (0 s) | 0/3 |
| replace | rep_subline_gt | logic | 3/3 (153 s) | 0/3 | 3/3 (140 s) | 0/3 | 3/3 (0 s) | 0/3 |
| print_tokens | pt_unget_le | logic | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| print_tokens | pt_token_len | logic | 0/3 | 0/3 | 0/3 | 0/3 | 1/3 (5 s) | 1/3 (9 s) |
| print_tokens | pt_delim_or | logic | 0/3 | 0/3 | 0/3 | 0/3 | 3/3 (1 s) | 3/3 (5 s) |
| print_tokens2 | pt2_string_nl | logic | 3/3 (4 s) | 3/3 (4 s) | 3/3 (4 s) | 3/3 (4 s) | 3/3 (0 s) | 3/3 (3 s) |
| print_tokens2 | pt2_tokend_semi | logic | 3/3 (82 s) | 0/3 | 3/3 (80 s) | 0/3 | 3/3 (0 s) | 1/3 (6 s) |
| print_tokens2 | pt2_charconst_alpha | logic | 3/3 (82 s) | 2/3 (86 s) | 3/3 (80 s) | 2/3 (85 s) | 3/3 (0 s) | 2/3 (7 s) |
| print_tokens2 | pt2_num_dot | logic | 1/3 (165 s) | 0/3 | 1/3 (163 s) | 0/3 | 2/3 (60 s) | 0/3 |
| juliet | j190_add | UB | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| juliet | j190_mul | UB | 3/3 (9 s) | 3/3 (9 s) | 3/3 (10 s) | 3/3 (10 s) | 3/3 (17 s) | 3/3 (17 s) |
| juliet | j191_sub | UB | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| juliet | j369_div, j369_mod | UB | 3/3 (9 s) | 3/3 (9 s) | 3/3 (9 s) | 3/3 (9 s) | 3/3 (0 s) | 3/3 (0 s) |
| juliet | j121, j122, j124, j126, j127, j195 | memory | 3/3 (9 s) | 3/3 (9 s) | 3/3 (9 s) | 3/3 (9 s) | 3/3 (0 s) | 3/3 (0 s) |
| juliet | j194_signext | memory | 3/3 (63 s) | 3/3 (63 s) | 3/3 (46 s) | 3/3 (46 s) | 3/3 (0 s) | 3/3 (0 s) |
| juliet | j197_char | logic | 2/3 (72 s) | 0/3 | 0/3 | 0/3 | 0/3 | 0/3 |
| juliet | j197_short | logic | 3/3 (66 s) | 0/3 | 1/3 (13 s) | 0/3 | 0/3 | 0/3 |

Where the Daikon modes' time went (seed 0, seconds of the 180 s budget):

| target | loop executions | AFL++ executions | ratio | Daikon rounds | Kvasir | Daikon | untraced (call budget) |
|---|---|---|---|---|---|---|---|
| tcas | 9,012 | 345,753 | 38x | 4 | 88 | 27 | – |
| tot_info | 15,004 | 1,453,990 | 97x | 7 | 110 | 29 | – |
| replace | 2,006 | 1,724,450 | 860x | 2 | 204 | 4 | `amatch`, `omatch`, `in_pat_set` |
| print_tokens | 1,005 | 329,269 | 328x | 2 | 207 | 17 | `next_state`, `get_char` |
| print_tokens2 | 3,005 | 761,595 | 253x | 2 | 200 | 3 | `get_char`, `is_eof_token`, `is_spec_symbol`, `is_token_end` |
| juliet | 20,014 | 202,824 | 10x | 8 | 74 | 28 | – |

Unplanted bugs found by the sanitizers (all three tools): `tcas.c:71`
global-buffer-overflow (the `Positive_RA_Alt_Tresh[4]` index, as long as
`Alt_Layer_Value` is unchecked), `tot_info.c:84` signed overflow,
`replace.c:159/180/229` stack-buffer-overflows, `print_tokens.c:472`
out-of-bounds table read, and 6-8 global-buffer-overflows in
`print_tokens2`. The Daikon modes found more distinct out-of-bounds indexes
at `tcas.c:71` (27 vs 2), but that is the same bug.

### Tool bugs this benchmark exposed (fixed before the numbers above)

The first pass scored loop 56/45 and learn-once 50/38 (triggered/reported).
Four problems were ours, not the method's:

1. **Timeouts did not stop Kvasir.** `kvasir-dtrace` is a shell wrapper; the
   timeout killed the shell while Valgrind held the pipes open, so a 40 s
   limit ran 300 s (replace learn-once took 318-375 s). Tool commands now run
   in their own process group.
2. **print_tokens hung for 15+ minutes a round** (all 6 runs killed at
   1,440 s). 97% of the time was re-checking "elements" rules over two
   360-entry global tables on every call. Checks are now memoized on the
   values they read: identical on 761,954 real checks, 17x faster.
3. **A heap-corrupting input ended a Juliet run at 117 s**: the coverage
   binary died after its last input reported. That input is now blamed and
   the run continues.
4. **Juliet's j194 was never kept (0/3).** ASan reports were keyed to the
   first frame in `juliet.c`, so every memory error in an included case file
   collapsed onto one dispatcher line, and `memcpy(-n)` looked like a repeat
   of `memset(-n)`. Now 3/3.

## What it shows

**1. On bugs reached, the Daikon modes keep up with AFL++ despite 10-860x
fewer executions.** Loop triggered 68/99 against AFL++'s 62/99 and reported
50 against 47. Memory and UB bugs tie at 30/45: the sanitizers do that work,
and every tool reaches the easy Juliet cases within seconds. The difference
is in logic bugs, where Daikon rules make some inputs worth keeping that
coverage does not. tcas is the clearest case: `tcas_enabled_ge` 3/3 vs 0/3,
`tcas_climb_ge` reported 3/3 vs 0/3, and the j197 truncations triggered 5/6
vs 0/6.

**2. The biggest weakness is throughput, and most of it is Kvasir.** On
replace, print_tokens and print_tokens2, Kvasir takes 200-207 of the 180 s
budget (it is cut off mid-batch), leaving two Daikon rounds and 1,000-3,000
executions. That is exactly where AFL++ wins: `pt_delim_or` 3/3 in 1 s vs
0/3, `pt_token_len` 1/3 vs 0/3, `pt2_num_dot` 2/3 vs 1/3, and the replace
ditto/subline faults at 0 s vs 140-153 s. **Fixable:** trace a sample of each
batch rather than every input (coverage needs no trace), trace only the
functions whose rules the input could affect, or replace Kvasir with
compiled-in instrumentation (an LLVM pass that logs entry/exit values runs
natively; Kvasir's 1.4 ms per call is Valgrind's cost, not Daikon's).

**3. The call budget trades reports for speed.** `pt2_tokend_semi` was
triggered 3/3 but never reported: it lives in `is_token_end`, which the
budget left untraced, so it had no rules to break. Same for the replace
matching core. **Fixable** with cheaper tracing (point 2); the budget is a
workaround.

**4. Bugs inside a function's locals are invisible to Kvasir.** The j197
truncations (`(char)data`, `(short)data`) were triggered 5/6 by the loop but
reported 0: the truncated value is a local, never a parameter, return value
or global, so no Daikon rule describes it. **Fundamental to Kvasir's view**
(entry/exit only). It would need program-point instrumentation inside
functions (Daikon supports it, but Kvasir does not emit it).

**5. Some bugs need one exact value, and no tool finds them.** `j190_add`
and `j191_sub` need `INT_MAX`/`INT_MIN` typed as decimal text,
`tot_qgamma_le` needs `x == a + 1.0` exactly, `tcas_above_le` needs two
inputs equal and the output to change, `rep_dash_lt` a dash at one exact
position. 0/3 for all three tools (except one loop run on `tcas_above_le`).
**Partly fixable for everyone:** a dictionary of boundary numbers as text
(`2147483647`, `-2147483648`) would get the Juliet pair. Daikon distances
could help with equalities on parameters, but these values are mostly
locals (point 4).

**6. Some faults never change the output.** `tot_lgamma_terms` drops the
sixth term of a series: the state is wrong on every call, but the printed
result rounds the same. 0/3 everywhere, and correctly so under an
output-based oracle. **Not a tool limitation.**

**7. The logic-bug alarm is still mostly noise.** 1.4% (43/3,033) for loop
and 1.8% (56/3,065) for learn-once: about 1 real bug per 60 alarms, against
2.4% on the toy targets. Bigger programs have more rules (tcas 3,245,
print_tokens 3,727), and most broken rules are just rules the seeds were
too few to rule out. **Fixable in part:** rank alarms (rules that held on
many inputs and broke on one; rules that cover the output), or confirm an
alarm with a second check before reporting it. Eclat-style filtering took
precision from 2.3% to 30% in the literature.

**8. Re-learning every round still does not pay off in 180 s.** Loop and
learn-once are within noise (50 vs 51 reported, 20 vs 21 logic). With 2-8
rounds per run there is little room for re-learned rules to matter, and
each re-learning costs a Daikon run. It would need longer budgets or
cheaper tracing to test fairly.

**9. Real libraries are out of reach today.** Magma's libpng (7 real bugs)
was built as a target (`scripts/bench/make_libpng.py`) but could not be
benchmarked. Full tracing of 4 seed PNGs produced a 59 MB trace and 12 MB
of declarations (1,046 program points, about 65 variables each); Daikon did
not finish reading the declarations in 15 minutes. Cut down (struct depth
1, arrays capped at 8, the call budget), it was 198 program points and 55
variables, and Daikon took 545 s on the 4 seeds alone, producing 42,418
rule lines: three times the whole budget before any fuzzing. **Partly
fundamental:** Daikon's cost grows with variables per program point, and
library code has many. The way out is to learn rules only for a chosen
slice of functions (the ones near the code being attacked), not the whole
program.

### Summary: fixable vs fundamental

| struggle | evidence | verdict |
|---|---|---|
| Kvasir throughput | 200+ of 180 s on 3 targets; 250-860x fewer executions than AFL++ | fixable (sample traces, native instrumentation) |
| untraced hot functions | `pt2_tokend_semi` triggered 3/3, reported 0/3 | fixable with cheaper tracing |
| locals invisible | j197 triggered 5/6, reported 0/6 | fundamental to entry/exit tracing |
| exact-value conditions | 5 bugs at 0/3 for every tool | partly fixable (text dictionaries) |
| output-equivalent faults | `tot_lgamma_terms` 0/3 everywhere | not a tool problem |
| alarm precision | 1.4-1.8% | fixable in part (ranking, confirmation) |
| Daikon scale on libraries | libpng: 545 s for 4 seeds, reduced config | fundamental unless rules are learned for a slice |

### Caveats

- 3 seeds per cell; differences of one run are noise.
- Siemens faults are artificial one-token mutations, like the original suite.
- The Juliet cases are deliberately shallow; every tool finds most in seconds.
- The print_tokens Daikon runs still overshoot to about 285 s: the first
  batch's Kvasir run is cut at the limit, then its partial trace is scored.
  Bugs are capped at 180 s in scoring, so this does not inflate results.

# Speed work: same benchmark, faster Daikon side

Same 6 programs, 33 bugs, 180 s per run, 3 seeds. AFL++ was not re-run
(nothing changed on its side). "Before" is the extended benchmark above.

| setup | triggered | reported | memory/UB | logic | alarm precision | median executions |
|---|---|---|---|---|---|---|
| loop, before | 68/99 | 50/99 | 30 | 20 | 43/3033 (1.4%) | 6,008 |
| learn-once, before | 63/99 | 51/99 | 30 | 21 | 56/3065 (1.8%) | 5,008 |
| loop, speed fixes | 72/99 | 53/99 | 30 | 23 | 57/3382 (1.7%) | 23,504 |
| learn-once, speed fixes | 68/99 | 52/99 | 30 | 22 | 62/3849 (1.6%) | 19,504 |
| loop, speed fixes + `--trace-sample 0.1` | **78/99** | **56/99** | 30 | **26** | 43/3233 (1.3%) | 47,009 |
| learn-once, speed fixes + `--trace-sample 0.1` | 70/99 | 54/99 | 30 | 24 | 72/4431 (1.6%) | 67,005 |
| AFL++ | 62/99 | 47/99 | 30 | 17 | – | 540,083 |

Median executions per program, before -> speed fixes -> + sampling (loop):
tcas 9k -> 18k -> 44k, tot_info 15k -> 28k -> 54k, replace 2k -> 32k -> 69k,
print_tokens 1k -> 13k -> 39k, print_tokens2 3k -> 21k -> 51k,
juliet 20k -> 39k -> 42k.

## What changed

- **No DynComp after the seed run.** Comparability analysis was 3-12x of
  Kvasir's time and only feeds the .decls, which the loop takes from the
  seed run.
- **A var list.** Kvasir traces only the globals a traced function uses.
  print_tokens' four 360-entry tables were in every sample. Kvasir needs
  the parents of `p[].f` / `p->f` listed or Daikon rejects the decls.
- **Fork server** for the native coverage and sanitizer runs: a crashing
  input costs a fork (~1 ms), not a restart (~0.1 s). replace's sanitizer
  time per run went from 63 s to 5 s.
- **Memoized rule checks** (Python), keyed on the values a rule reads,
  turned off automatically when the hit rate is low. 17x on print_tokens.
- **`--trace-sample F`**: inputs that reach new code or a new bug are
  always traced; the rest only with probability F. Over 3 seeds, replace
  kept 4 of 6,000 inputs for invariant reasons alone, and print_tokens2 0
  of 9,000, so most tracing was wasted.

Per 300 inputs, Kvasir went from 8.3 to 0.70 s on replace, 14.8 to 0.84 s on
print_tokens, 2.0 to 0.66 s on tcas, 3.5 to 1.3 s on tot_info, and 2.8 to
0.77 s on print_tokens2.

## What it shows

- **Throughput rose about 8x** (median 6k -> 47k executions), still about
  11x below AFL++.
- **Speed bought bugs, mostly logic ones.** Logic bugs reported went from
  20 to 26 (AFL++ 17). Memory/UB stayed at 30 for every tool: those bugs
  were already all found.
- **print_tokens is no longer blind.** It triggered nothing before (1k
  executions). Now pt_delim_or is reported by the loop in 2 of 3 runs, and
  pt_token_len once by learn-once.
- **New finds with sampling:** tcas_above_le is reported for the first
  time (once each by loop and learn-once); tot_pi_ge goes from 1 to 2 runs;
  rep_subline_gt is reported once.
- **Precision did not improve** (1.3-1.8%). Speed does not fix
  over-specific rules; see the next steps.
- **Juliet barely benefits from sampling** (39k -> 42k): its cost is now
  the sanitizer build (37 of 63 s in a 60 s run), not tracing.
- **The loop beats learn-once more clearly once fast** (78 vs 70
  triggered, 26 vs 24 logic), although learn-once runs more inputs. With
  sampling, re-learning starts to pay.

## Tool bugs found while running it

- **The harness kept its loop counters on the stack.** Juliet's stack
  overflows (index from the input) rewrote them in the Kvasir build, where
  nothing stops them: the batch replayed (80,202 inputs traced for 908) and
  the run died. 10 of 12 Juliet runs were lost. The state is now on the
  heap, behind an integer Kvasir does not follow, and checked after every
  input (exit 86 blames the input that changed it).
- **A first fix made it worse**: a static batch pointer, which Kvasir
  follows, dumped the whole batch at every program point (339 MB per
  batch instead of 10 MB). Caught by Juliet dropping to 6k executions.

# Does invariant guidance help exploration? (`no-guidance` ablation)

Same setup as the sampling row above (`--trace-sample 0.1`, 180 s, 3 seeds).
`no-guidance` is the same loop with `--no-guidance`: inputs are kept only
for new coverage and parents are picked uniformly. Rule-breaking inputs
still raise alarms (recorded, never mutated), so detection is identical and
only the steering differs. The loop and AFL++ rows are the runs above.

| tool | triggered | reported | memory/UB | logic | alarm precision | median executions |
|---|---|---|---|---|---|---|
| loop (guided) | **78/99** | **56/99** | 30 | **26** | 40/3233 | 47,009 |
| no-guidance | 68/99 | 51/99 | 30 | 21 | 38/3202 | 47,014 |
| AFL++ | 62/99 | 47/99 | 30 | 17 | – | 540,083 |

Per bug, reported/triggered runs out of 3 (only bugs where the two differ):

| bug | guided | no-guidance | AFL++ |
|---|---|---|---|
| tcas_enabled_ge | 3/3 | 1/2 | 0/0 |
| tcas_above_le | 1/2 | 1/1 | 0/0 |
| tot_info_gt | 3/3 | 1/2 | 3/3 |
| tot_pi_ge | 2/2 | 0/0 | 0/2 |
| pt_token_len | 0/3 | 1/3 | 1/1 |
| pt2_tokend_semi | 0/3 | 1/3 | 1/3 |
| pt2_charconst_alpha | 2/3 | 1/3 | 2/3 |
| pt2_num_dot | 0/3 | 0/1 | 0/2 |
| j197_char | 0/3 | 0/1 | 0/0 |
| j197_short | 0/2 | 0/1 | 0/0 |

## What it shows

- **Guidance pays on arithmetic code.** On tcas and tot_info, guided runs
  reported 6 more bug-runs (tcas_enabled_ge +2, tot_info_gt +2, tot_pi_ge
  +2). These are boundary bugs (`>=` vs `>`), and guidance keeps inputs
  that move a value toward a rule's boundary. It matches where guidance
  drove the corpus: ~30% of kept inputs on tcas/tot_info were kept for
  invariant reasons alone, against 0-7% on the parsers.
- **On the parsers it is neutral to slightly negative.** no-guidance
  reported pt_token_len and pt2_tokend_semi once each where the guided loop
  did not; guided got pt2_charconst_alpha once more. Text parsers' state is
  mostly control flow, which coverage already sees; invariant-driven picks
  dilute the budget there.
- **Exploration on Juliet:** guided triggered j197 in 5 runs, no-guidance in
  2 (neither can report it: the truncation is in a local).
- **Detection is unchanged** (precision 1.2% both), as designed.
- **The rest of the gap to AFL++ is not guidance.** Without guidance the loop
  still triggers 68 vs AFL++'s 62 at 11x fewer executions, almost all on
  tcas (7 vs 3 triggered): the loop's mutator and value dictionary suit
  tcas's 12 integer arguments.
- Caveat: 3 seeds, so single-bug differences are 1-2 runs. tot_info's
  no-guidance runs also executed fewer inputs (34k vs 54k median), which
  flatters guidance there. The tcas result (equal executions) is the
  cleanest evidence.

# Correction: rules broken in `static` functions were not counted

Kvasir names a file-static function's program point after its file
(`/path/print_tokens2.c.is_token_end()`). The scorer compared that to the
bug's bare function name, so a live rule broken in a static function never
counted as reporting the bug. Fixed in `bench.py` (`ppt_function`), and the
runs above were rescored from their saved histories (nothing re-run).
Triggered counts are unchanged; reported counts move only on print_tokens'
`pt_delim_or`:

| run | tool | reported before | reported after | alarm precision after |
|---|---|---|---|---|
| speed fixes (`ext`) | loop / learn-once | 50 / 51 | 50 / 51 | 65/3033, 66/3065 |
| + sampling (`ext-fast01`) | loop | 56 | **57** | 59/3233 (1.8%) |
| + sampling (`ext-fast01`) | learn-once | 54 | **57** | 105/4431 (2.4%) |
| ablation (`ext-guid`) | no-guidance | 51 | **52** | 71/3202 |

The guidance conclusion stands (57 vs 52). Loop and learn-once are now
level on normal seeds (57 each).

# Weak seeds: one ordinary input per target

Question: with the usual 4-14 seeds, the first rules are already good, so
re-learning (the loop) has nothing to fix. Does it pull ahead of learn-once
when the starting rules are poor? Each target got a single ordinary input
(`*.weak.seeds`; on Juliet it reaches 1 of the 14 cases). Same settings as
above, 180 s, 3 seeds, scored with the corrected scorer.

| tool | triggered | reported | memory/UB | logic | alarm precision | median executions |
|---|---|---|---|---|---|---|
| loop | **71/99** | 62/99 | 30 | 32 | 153/3426 (4.5%) | 45,001 |
| learn-once | 64/99 | **64/99** | 30 | **34** | 405/5126 (7.9%) | 95,001 |
| no-guidance | 66/99 | 62/99 | 30 | 32 | 153/3479 (4.4%) | 44,501 |
| attack (below) | **71/99** | 63/99 | 30 | 33 | 145/3534 (4.1%) | 46,001 |
| AFL++ | 64/99 | 52/99 | 30 | 22 | – | 377,595 |

Bugs where the tools differ (reported/triggered runs out of 3):

| bug | loop | learn-once | no-guidance | attack | AFL++ |
|---|---|---|---|---|---|
| tcas_enabled_ge | 3/3 | 1/1 | 3/3 | 3/3 | 0/0 |
| tot_pi_ge | 0/1 | 0/0 | 0/1 | 0/2 | 0/2 |
| rep_subline_gt | 2/3 | 3/3 | 3/3 | 3/3 | 0/3 |
| pt_token_len | 0/0 | 0/0 | 0/0 | 0/0 | 3/3 |
| pt2_tokend_semi | 2/3 | 3/3 | 2/3 | 1/3 | 1/3 |
| pt2_num_dot | 0/0 | 2/2 | 0/1 | 1/3 | 0/1 |
| j197_char / j197_short | 0/6 | 0/0 | 0/0 | 0/2 | 0/0 |

## What it shows

- **Weak seeds barely hurt anyone.** Triggered: loop 78 -> 71, learn-once
  70 -> 64, AFL++ 62 -> 64. One input is enough to reach most planted bugs
  within seconds; the 6 bugs no tool triggers are the same with either seed
  set. The targets are easy where they are solved and hard, in a way
  invariants do not touch, where they are not (below).
- **Re-learning still does not pay.** Loop 62 vs learn-once 64 reported.
  The loop's triggered lead (+7) is again mostly Juliet j197 (6 runs), which
  neither can report (the truncation is in a local).
- **Reported went up, not down (57 -> 62-64).** One seed gives fewer rules
  (10.8k vs 14.7k in round 0), and many are accidents of that one input
  (`x == 958`). Almost any new behaviour breaks them, so bug inputs get
  flagged more often, and so do correct ones. Learn-once keeps those narrow
  rules all run (hence 5,126 alarms); the loop retires them. "Reported" for
  logic bugs is a suspect flag, so this is cheaper flagging, not better
  detection.
- **Guidance is neutral here** (62 vs 62), unlike on normal seeds (57 vs 52).

## The bugs nobody triggers

| bug | what it needs |
|---|---|
| j190_add / j191_sub | the text `2147483647` / `-2147483648` exactly |
| tot_lgamma_terms, tot_qgamma_le | numeric series behaviour reached only by specific real inputs |
| rep_dash_lt, pt_unget_le | particular syntax sequences (a `-` range at a class edge; an unget at the buffer end) |

None of these is a boundary near a value the rules have seen, so neither
re-learning nor rule-directed mutation reaches them. Type-extreme values
(INT_MAX/INT_MIN in the input's own encoding) and grammar-aware mutation
would.

# Rule-directed mutation (`--attack`)

`--attack F` spends about F of each batch on children built from a live
rule. It finds the rule's variable value in the parent's bytes (LE
32/16/8-bit or decimal text) and writes in the boundary: c-1, c, c+1 for
`x op c`, or y-1, y, y+1 for `x op y` (REDQUEEN-style input-to-state, driven
by rules instead of comparison operands). Benchmarked at 0.25 (about 36% of
candidates, since a rule yields up to 3 children).

| seeds | loop | attack | AFL++ |
|---|---|---|---|
| normal: triggered / reported | 78 / 57 | 73 / 55 | 62 / 47 |
| weak: triggered / reported | 71 / 62 | 71 / 63 | 64 / 52 |

No gain on either seed set. Normal seeds: attack lost tcas_above_le (loop
2/3 triggered, attack 0/3) and was slower on tcas_enabled_ge (median 42 s vs
12 s).

Why, traced on tcas_above_le (`Other_Tracked_Alt <= Own_Tracked_Alt`
where the correct code has `<`):

- The right rule exists from round 0: `::Own_Tracked_Alt !=
  ::Other_Tracked_Alt`. Attacking it on the 12 seeds gives 24 inputs with
  equal altitudes, and **4 of 24 trigger the bug**. The bug also needs the
  right branch elsewhere in the input.
- It is 2 of ~70 attackable rules at its program point (out of ~170), so 1
  pick in ~35. Most of the rest are accidents
  (`High_Confidence < Own_Tracked_Alt`, `Own_Tracked_Alt > Climb_Inhibit`).
- **The loop deletes the rule after the first hit.** The first
  equal-altitude input is kept (it breaks a live rule), the next Daikon round
  learns that equality happens, and `!=` is gone. One shot at ~1 in 6.
- Generation is repetitive: about 65k attack children per tcas run for about
  14k distinct ones executed.

What would make it work: keep a broken rule as an attack target after it is
refuted (or attack against learn-once rules), favour rules between input
variables over rules involving constants and flags, and add type extremes
(INT_MAX/INT_MIN) for the Juliet overflows.

## Tool bugs found while running it

- **Daikon 5.9's `LinearTernary` crashed** ("at end of add_modified") on a
  tot_info value of 39,999,999,999,999,990, killing one run's final pass.
  `run_daikon` now retries once with that invariant off.
- **The static-function scoring bug** above.
