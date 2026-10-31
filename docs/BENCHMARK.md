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
