# Phase 11 — surviving a real program

Status: **A and the gzip half of B are done. The variable-count half of B is
not started.** Prerequisite: the first run of the tracer on the Kvasir suite's
large programs, 2026-09-20.

## Done

| | result |
|---|---|
| **A. value cap** | `space` traces instead of crashing. A value outside signed 64-bit is `nonsensical`, guarded in two places: `decode_field` refuses a field wider than one machine word, and `format_value` refuses an out-of-range integer, so no future path can reintroduce it. |
| **gzip output** | `bc` 85.85 MB -> **0.62 MB, 138x**. Compresses when the path ends `.gz`, the same rule Daikon uses to decide to decompress, plus `--gzip` which appends it. Daikon reads what we write, no format errors. |

Verified: **423 tests pass**; own corpus unchanged at **65/92/76**; Kvasir suite
unchanged at **24/17/20, 822 matched**; `./test.sh --tier 8 -- --gzip` at 0
failures over 20 binaries.

Neither changed a single invariant, which is what they were supposed to do -
both acceptance criteria were "do not regress".

**Still open: the 841s.** Bytes were never the constraint, and now they are not
even a nuisance. Daikon's runtime is, and only reducing the variables declared
per program point addresses it - at a cost of matched facts that has been
measured but not yet accepted.

**Corrected 2026-10-03: the Kvasir baseline below is not like for like.** Its
`bc` run used `bc`'s own Makefile, which passes `--ignore-globals`; Daikon's
reference declarations for `bc` contain no globals, 14.9 variables per entry
point. Ours declared all 112 globals. So the 841s-against-36s comparison
measures globals against no globals, and a fair comparison has not been run.
Kvasir also prints file-static variables only in their own file's functions,
where we print every global everywhere. See [../HEURISTICS.md](../HEURISTICS.md),
H34.

Two defects, both found by running the tracer on programs bigger than anything
in either corpus. Neither is about invariant quality; both are about the tool
staying up and producing a file something else can read.

## What the first large-program run showed

| program | LOC | our time | our dtrace | calls we saw | calls Kvasir saw | outcome |
|---|---|---|---|---|---|---|
| tot_info | 406 | 3s | 11 KB | 2 | 2 | ok |
| replace | 564 | 2s | 16 KB | 30 | 756 | ok |
| print_tokens | 565 | 2s | 186 KB | 25 | 5261 | ok |
| wordplay | 1136 | 5s | 47 KB | 8 | 1240 | ok |
| bc | 10348 | 43s | **137 MB** | 7026 | 5392 | ok |
| space | 9126 | 10s | — | 0 | — | **crash** |

**Speed is not the problem.** 10,000 lines in 43 seconds, and the emulation
itself never faltered — five of six ran clean and the sixth died in the
*writer*, after all the work was done.

The gap in the "calls seen" columns is the missing input mechanism, not a
tracer defect: with no argv and no stdin those programs printed a usage
message and exited. That is phase 12, and it is the prerequisite for fuzzing.

---

## A. The oversized-value crash

`space` died in `DaikonTraceWriter.close()`:

```
ValueError: Exceeds the limit (4300 digits) for integer string conversion
  writer.py:49  return str(value)
```

**Cause.** A global larger than a machine word, with no array or struct shape
recovered, is read with `int.from_bytes` over its whole extent and written as
one decimal integer. Past ~1786 bytes that decimal has more than 4300 digits,
and Python 3.11+ refuses to render it.

It is a real bug rather than a Python quirk: **an 1800-byte object is not a
scalar**, and writing it as one enormous number would be useless output even if
Python printed it happily.

**Fix.** A single value never exceeds one machine word. Anything wider is an
array, a struct, or - if neither shape was recovered - `nonsensical`, which is
exactly what that marker is for. `MAX_SCALAR_SIZE = 8` already exists in
`globalvars.py` for the same reason; the writer path simply never consulted it.

Belt and braces: `format_value` should refuse to render an integer wider than
64 bits at all, so no future path can reintroduce this. That check belongs next
to `validate()`, which was added in phase 10 after two format bugs silently
destroyed whole traces.

**Acceptance.** `space` produces a dtrace and Daikon reads it. No golden moves.
A unit test writes a 2000-byte value and asserts it does not become a number.

---

## B. The 137 MB trace

`bc` produced 137 MB where Kvasir produced 865 KB from more or less the same
execution - 160x the bytes. A fuzzing loop does thousands of runs, so this has
to be fixed *before* the input mechanism lands, not after.

### Two obvious fixes are both wrong, and were measured before being rejected

**"Switch globals off", as Kvasir's authors do on `bc`.** Globals took the
suite from 176 matched facts to 802. Turning them off is a return to 4% recall
to save disk. Rejected.

**"Emit only the globals each function touches."** This looked like a place
where we could beat Kvasir: DWARF says a global exists but not who uses it, so
Kvasir has no choice but to emit all of them everywhere - while we observe
every access and *can* attribute them. Measured across the suite:

```
oracle global references at a program point whose function TOUCHES that global:   66
                                                     ...that never touches it:   373

=> 84% of the oracle's global references are at untouched program points
```

So the redundancy is Kvasir's **design**, not an accident: a global is in scope
everywhere, Daikon reports it everywhere, and matching that means emitting it
everywhere. Filtering by touch would discard most of our 626 matched global
facts and land us below the pre-tier-8 score. Rejected.

*(The per-function attribution built to measure this - `Tracer.global_touch` -
is kept. It is the right data for the fuzzer to prioritise with, even though it
is the wrong basis for filtering output.)*

### Where the bytes actually are

```
bc.dtrace, 137 MB:
  ARRAY globals   g_0x..[..]    126.6 MB   92%
  SCALAR globals  g_0x..          9.2 MB    6%
  everything else                 0.6 MB    0%
```

Arrays of 151 to 347 elements, each written out 7,026 to 21,078 times. **The
cost is concentrated in exactly the variables that carry the fewest facts per
byte**, and scalars - which carry most of the matches - are already cheap.

That splits the problem from "globals are expensive" into "whole-array globals
re-serialised at every program point are expensive", which is a much smaller
thing to fix.

### Measured 2026-09-21: the file size is the wrong target

A delta encoding was proposed - print full state at the call, then only what
changed. Checked against Daikon's parser rather than assumed, and the answer
is instructive in three parts.

**1. Delta encoding is impossible in this format.** `FileIO.java:2143` demands
a value line and a modbit line for EVERY variable at EVERY sample; a missing
value is a hard error ("Expected value for variable X"). Nothing may be
omitted.

**2. Daikon computes the modbits itself, so ours are ignored.**

```java
// FileIO.java:2187
if (value_rep.equals(oldvalue_reps[val_index])) {
    mod = ValueTuple.UNMODIFIED;
} else {
    mod = ValueTuple.MODIFIED;
}
```

It compares each printed value with the previous one and overwrites whatever
modbit we wrote. **This retires an open item that has been on the list since
the phase-5 retrospective**, where "modbits hardcoded to 1" was called "the
clearest remaining precision lever". It is not a lever at all.

**3. Daikon reads `.dtrace.gz` natively** (`FileIO.java:1418`), and the
redundancy that motivated the delta idea is exactly what compression eats:

```
bc.dtrace raw       131.5 MB
bc.dtrace.gz          1.09 MB     120x smaller, 4 seconds, zero facts lost
```

So **file size is solved, for free, by one flag**. It is not the constraint.

### The constraint is Daikon's runtime, and it is quadratic in variables per ppt

| | dtrace | samples | vars/ppt | Daikon | invariants |
|---|---|---|---|---|---|
| Kvasir's bc | 865 KB | 5392 | ~16 | **36s** | 3045 |
| ours | 131 MB (1.1 MB gz) | 7026 | **114** | **841s** | 8367 |

Fourteen minutes, exit 0 - slow rather than unscalable. Daikon tests pairs of
variables, so its work grows about with the square of the count at each program
point: ~6,500 pairs for us against ~130 for Kvasir. We declare 112 globals at
every point; that is the whole difference.

**This invalidates candidate 1 below.** Writing an untouched array global as
`nonsensical` shrinks bytes, which no longer matter, and leaves the variable
DECLARED - so Daikon still pairs it and the runtime is unchanged.

Only reducing the declared variable count helps, and that is precisely what was
measured at 84% of global references lost.

### Measured 2026-09-22: it is not the bytes, it is re-checking constant data

A delta encoding was pressed a second time - if the format forbids it, patch
the format. The follow-up measurements settle it.

**The data really is pure repetition.** Every array global, every sample:

```
consecutive appearances of an ARRAY global : 154550
  identical to the previous sample         : 154550  (100%)
  changed                                  :      0  (0%)
```

126 MB of the same 22 arrays, rewritten 7,026 times each, never once differing.

**Delta encoding is possible, and was wrongly called impossible.** It is
impossible in the *unmodified* format; patching `FileIO` to accept a
"same as last" sentinel is about two lines, because `oldvalue_reps[]` - the
previous printed value per variable - is already maintained for the modbit
computation.

**It would still buy nothing.** Bytes are already solved by gzip (120x, stock
Daikon, no fork). And Daikon *derives* "unchanged" itself at `FileIO.java:2187`
and takes 841s anyway, so stating it in the file supplies no information it
lacks.

**The cost is Daikon re-checking invariants over data it knows is constant.**
`PptSlice1.java:202` computes the unmodified flag, passes it to the invariant,
and checks the invariant regardless. Confirmed by removing the arrays:

```
baseline                          841s   8367 invariants
--var-omit-pattern on the arrays   12s    274 invariants
```

**70x, and the 22 array globals are ~98% of the runtime.** (The mirror-image
run, omitting the scalar globals, is not a valid data point: it orphans the
`enclosing-var` of the `[..]` variables and Daikon rejects the trace. Recorded
so it is not re-attempted.)

A Daikon patch to skip unmodified samples is therefore the only version of this
idea that would help - and it is not free: Daikon's confidence in an invariant
depends on how many samples it saw, so skipping changes which invariants are
reported as justified, not merely how fast they appear. That is a semantics
change, and it would make our results irreproducible on stock Daikon.

**Conclusion: do it on our side of the interface.** Not emitting an unchanged
array at every program point gets the same 70x with no fork. That is candidate
2 below, promoted from "measure it" to "the plan".

### The two metrics have diverged, and that is the real decision

Until now "agree with Kvasir more" has been a sound proxy for "be more useful".
Here they point opposite ways:

- **For the oracle comparison**, every global at every point is correct,
  because that is what Kvasir does and matching it is the score.
- **For the fuzzing loop**, 14 minutes per iteration is unusable. A leaner
  variable set that runs in seconds serves the fuzzer better than a complete
  one that does not finish.

The honest resolution is to stop treating one configuration as "the" output:
keep the Kvasir-matching configuration for measurement, and add a lean one for
the loop, with the difference measured rather than asserted.

### Three candidates, to be measured in this order

1. ~~**Array globals as `nonsensical` where the function never touched them.**~~
   **Invalidated by the runtime measurement above** - the variable stays
   declared, so Daikon's pairing cost is unchanged and bytes are no longer the
   constraint.
   The variable stays declared, so the schema is identical at every program
   point and nothing downstream shifts; only the value is replaced by one
   token instead of 347 numbers. Expected saving is most of the 92%. The
   recall cost is confined to facts about whole arrays at untouched points -
   a subset of the 84%, and the subset with the worst facts-per-byte.
2. **Omit array globals entirely**, keeping scalars. Simplest, largest saving,
   largest recall cost. Worth measuring as the lower bound so option 1's cost
   can be attributed.
3. **Cap the printed element count.** Rejected on inspection rather than
   measurement: truncating changes the value, so `size(g[]) == 347` becomes
   false. This tool's one hard rule is that it does not state things that are
   untrue of the run, and this would break it.

Each is a flag, measured on both corpora, kept only if it pays - the standing
rule since `--infer-from-caller`.

**Acceptance, revised.** Gzip output is unconditional (120x, no loss). Beyond
that: `bc` through Daikon in under 120s, matched facts on the Kvasir suite down
by no more than 5% from 822 **in the measurement configuration**, fixture
corpus unchanged at 65/92/76. A separate lean configuration may trade facts for
speed, and states what it traded.

---

## Order

```
A  value cap            hours   unblocks `space`, removes a crash class
B1 nonsensical arrays   days    unblocks fuzzing, needs measuring against B2
```

A first: it is small, it is a correctness fix, and a crash in the writer
invalidates a whole run. B before any input work, because a fuzzer multiplies
the sample count and therefore multiplies 137 MB.

## What this phase explicitly does not address

- **The input mechanism** (phase 12). It is the reason four of the six programs
  barely executed, and the reason the fuzzing loop cannot start.
- **Invariant quality.** Nothing here is meant to move precision or recall;
  both acceptance criteria are "do not regress".
