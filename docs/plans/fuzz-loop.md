# The Daikon ↔ fuzzer loop: each feeding the other, measured

Status: **built and measured (2026-11-19)** on the SIR `tcas` subject: the reference
program, its 41 seeded-fault versions, and its 1,608-test universe.

## Result in one paragraph

Fuzzing makes Daikon's invariants trustworthy: the invariant oracle's false-alarm
rate on the correct program falls from **98% to 0%**. The fall comes from
inputs the loop chose *because* Daikon's invariants said they were informative. A
coverage-guided fuzzer with the same budget keeps 15 inputs, and its invariants
still false-alarm on 95–98% of tests.

Daikon gives the fuzzer an oracle for bugs that never crash. Coverage-guided
fuzzing reports **0** of the 41 faults. With the loop's invariants it surfaces
real output failures in **9–13 of 41** versions within 300 runs, with no
reference binary at check time, 0 false alarms, and every alarm a genuine
behaviour change.

Two things did **not** pan out:
- **Invariant-guided mutation** is not reliably faster at finding faults than
  plain coverage once both have the oracle (sign test p = 0.58 over two
  repetitions).
- **Conditional invariants** find more faults (29–30 of 41), but only with
  replay on the reference, and then plain differential testing (35 of 41) beats
  them.

## What was built

**Tracer (flag-gated; all 498 existing tests pass unchanged without the flags):**
- `--program-arg ARG` (repeatable): a real `argv`/`envp` written above the
  initial stack.
- `--model-libc`: `atoi`/`atol`/`strtol*`/`strlen` are computed from emulated
  memory, and `exit`/`_exit`/`abort` stop the run. Before this, every libc call
  was skipped with RAX = 0 ("empty, equal, zero"), which steered the program down
  paths it never takes.
- `--coverage-out PATH`: the basic-block edges of the binary's own code, for the
  fuzzer.
- `--program-args-file PATH`: many inputs traced into **one** dtrace (one
  evidence pool, one schema), because Daikon rejects files that declare a
  program point differently, and per-run type inference can.
- **Fidelity check on `tcas`:** every program point gets the same call counts
  and return values as under Kvasir running the real program.

**Loop (`scripts/fuzz/`):**
- `runner.py`: the tracer runs resident in-process, 42 ms per input against
  about 1.2 s as a subprocess. Also batch traces and Daikon runs, optionally
  with splitting conditions.
- `invariants.py`: compiles Daikon's scalar invariant forms (constants, one-of,
  relations, linear, and the implications `(A) ==> (B)`) into checks on a trace;
  it never guesses at a form it can't evaluate.
- `loop.py`: the fuzzer, AFL-style havoc over integer fields, in these
  configurations:
  - `blind`: mutates the seeds, no feedback.
  - `cov`: keeps inputs that reach a new edge.
  - `covinv`: `cov`, plus Daikon re-learning invariants every 100 runs from the
    corpus. It also keeps inputs that violate a live invariant, and uses
    invariant-guided mutations: invariant constants, and inputs built to break
    an invariant on the input field its variable is learned to come from.
  - `loop`: `covinv`, plus a **challenge phase** in the last 40% of the budget.
    Every invariant gets inputs built to break it; refuted ones are dropped and
    their refuting inputs kept, and Daikon re-learns. Survivors of a direct
    challenge are **trusted**.
  - `loopcond`: `loop`, with Daikon also given splitting conditions taken from
    what the fuzzing refuted (`splitters.py`), so it reports conditional
    invariants.

  Its **variable → input field map** is learned from the traces alone: a
  variable that, in every run, held that field's integer at some program point.
  No DWARF is used; the map finds all 12 `tcas` fields.
- `fault_eval.py`: invariants learned on the reference v0, then checked on the
  1,608 universe tests for v0 and all 41 faulty versions. Native outputs and
  traces are cached.
- `fault_hunt.py`: fuzz each faulty version for 300 runs with the invariants as
  oracle. A violation counts only if the same input does not violate that
  invariant on v0, and is a **failure** if native outputs differ.

Ground truth (native stdout, and v0's traces) is used only to score, never by the
loop.

## Fuzzer → Daikon: invariants learned on v0, judged on the 1,608-test universe

| invariants trained on (budget 1,000 runs, 5 trials) | training inputs | false alarms on v0 | faults flagged |
|---|---|---|---|
| the 2 seeds | 2 | 1,576 (98%) | 41/41 (flags everything) |
| `cov` corpus | 14–15 | 1,535–1,576 | 41/41 (flags everything) |
| `blind`, every run executed | 1,000 | 0–29 | 14–27 |
| `cov`, every run executed | 1,000 | 1–304 | 12–37 |
| **`loop` corpus** | 107–145 | **0** in 4 of 5 trials, 6 in one | **10–16** |
| `covinv` corpus (same, no challenge phase) | 108–144 | **0** in 5 of 5 | 10 |

Notes on the table:
- Restricting the `loop` oracle to its trusted invariants (49–57 of them) keeps
  exactly the same alarms.
- On faulty versions, **100% of alarms are genuine behaviour changes**: the
  traced values differ from v0's on that test. 9–12% also change the program's
  output; the rest are infected states that never propagate to it.
- The faults flagged are the ones Daikon's unconditional grammar can see:
  v5, v6, v10, v11, v12, v15, v26, v27, v33, v34. The misses change boolean
  conditions (`>=` vs `>`) whose effect "returns 0 or 1" cannot express.

**The loop at work** (corpus prefixes of one trial, in the order the loop kept
them):

| inputs kept | 2 | 25 | 50 | 75 | 100 | 142 |
|---|---|---|---|---|---|---|
| `loop` invariants' false alarms | 1,576 | 1,522 | 1,232 | 754 | 255 | **0** |

`cov` stops keeping inputs at 15, at 1,535 false alarms.

**Why it works.** Almost every false alarm came from `x != y` and `x != 0`
invariants. A fuzzer with random 32-bit values essentially never makes two fields
equal, but the real tests do so constantly (flags set to 0/1, equal altitudes).
The loop's challenge mutations target those invariants directly, setting `x = y`
on the learned fields. Before the field map worked, `covinv` still had 1–101
false alarms per trial; afterwards it had 0.

## Daikon → fuzzer: hunting faults in each version (300 runs, from v0's corpus)

| oracle / strategy | output failures found (of 41) | median runs to failure | reference runs |
|---|---|---|---|
| coverage-guided, no invariants | **0** (no fault crashes) | — | 0 |
| loop's trusted invariants, coverage-guided (3 oracles) | **9–13** | 21–50 | only on violations |
| loop's trusted invariants, invariant-guided (3 oracles) | 11–13 | 8–53 | only on violations |
| conditional invariants, coverage-guided (2 repetitions) | 29–30 | 21–32 | 2,343 |
| conditional invariants, invariant-guided (2 repetitions) | 29 | 23–24 | 2,887 |
| *differential testing (v0 run on every input)* | *35* | *21* | *3,214* |

- **Speed of guidance.** Over the versions both strategies cracked, guided was
  faster on 18 vs 7 in repetition 1 but on 10 vs 16 in repetition 2. Pooled,
  28 vs 23, sign test p = 0.58: **no reliable speed-up**.
- **Conditional invariants and replay.** Alone, their false-alarm rates on v0
  are 43–46%; adding a Daikon-directed equality sweep and requiring 300
  supporting samples still leaves 9% with 33 of 41 flagged. They are usable only with replay on v0, and then they cost about as
  many reference runs as differential testing while finding fewer faults.
  Differential testing is the better tool whenever the reference can be run on
  every input. The plain loop oracle needs no reference at check time.

## Reading

- **Real, measured improvement in both directions, and it is the feedback that
  causes it.**
  - Daikon's invariants decide which inputs the fuzzer keeps and builds:
    violation feedback and targeted challenges.
  - Those inputs make Daikon's invariants trustworthy: 98% → 0% false alarms.
  - The trustworthy invariants are an oracle the fuzzer did not have: 0 → 9–13
    real failures, with 0 false alarms and no reference.
- **What did not help:** invariant-guided mutation for speed, and conditional
  invariants without a reference.
- **The ceiling is Daikon's grammar.** The 28–31 faults the plain oracle misses
  change boolean logic. Recovering them reference-free needs conditional
  invariants that fuzzing can make as trustworthy as the plain ones. That has
  not been reached: the fuzzer's input distribution still differs from the real
  tests'.

## Limits

- **One subject.** `tcas` is small and saturates coverage in under 100 runs, so
  the coverage benefit of guidance cannot show here. The next subjects
  (`replace`, `print_tokens`, `tot_info`) need stdin/file input modelled in
  `--model-libc`.
- **The fault versions are SIR's seeded faults**, not real bugs.
- **Integer `argv` only.** The mutation operators assume integer fields.

## Reproduce

```
gcc -gdwarf-3 -fno-stack-protector -fcommon -std=gnu89 -no-pie -o versions/vN.exe tcas.c   # v0..v41 from SIR
python3 scripts/fuzz/loop.py versions/v0.exe --seeds SEEDS --config loop --budget 1000 --trials 5 --out train
python3 scripts/fuzz/fault_eval.py --versions versions --universe universe --cache cache \
    --train train/loop_*.json --sets corpus,trusted --out score.json
python3 scripts/fuzz/fault_hunt.py --versions versions --loop-result train/loop_0.json --budget 300 --out hunt.json
```

Seeds are `scripts/fuzz/tcas_seeds.jsonl`. The SIR copy used is
`github.com/agroce/fuzz_tcas` (`tcas/versions.alt`, `tcas/testplans.alt/universe`).
