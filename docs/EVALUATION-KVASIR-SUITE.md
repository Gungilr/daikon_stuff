# Evaluation against Daikon's own Kvasir test suite

The first evaluation on code **not written for this project**. `docs/EVALUATION.md`
measures ten fixtures I wrote, mostly to exercise the heuristic under test;
`TOOL.md` names that as the standing blind spot. `daikon/tests/kvasir-tests/`
is 46 C programs written by the Daikon authors to test *their* front-end, with
expected invariants checked in.

**Result: precision 13%, recall 4%, F1 6%**, against 65/92/76 on my own corpus.

That number is real and it is not the interesting part. The decomposition is.

> **Since fixed.** The decomposition below drove phase 9, which added global
> variables (tier 8) and floating point (tier 9). On the same suite the tracer
> now scores **22% / 17% / 19%** and matches **802 oracle facts instead of
> 176** — see [Phase 9](#phase-9-what-the-decomposition-bought) at the end, and
> [plans/phase9.md](plans/phase9.md). Everything between here and there is the
> original measurement, kept as the evidence that justified the work.

---

## Method

29 of the 46 programs are single-binary, self-contained and need no input.
All 29 were built with the suite's own flags (`-gdwarf-3 -fno-stack-protector
-fcommon`, plus `-no-pie` as the tracer requires), then run through **both**
front-ends and the **same** Daikon invocation, so the comparison is not
contaminated by configuration:

```
tracer:  --tier 7 --infer-unobserved-fields --poison-uninitialized
oracle:  kvasir-dtrace on the same binary
both:    daikon.Daikon with default settings
scoring: scripts/score_invariants.py, unchanged
```

*Oracle configuration, noted 2026-10-03.* Kvasir ran with its defaults: DynComp
on, globals on, default traversal depths. That is not the configuration the
suite's authors use. Their Makefiles pass per-program options to 20 programs,
eight of these 29 (CoercePointerTest, NestedStructTest, NestedStructVarList,
SelectGlobalsTest, SimpleDisambigStructTest, crazy-test-1, local-ptr, md5), such
as `--disambig`, `--var-list-file` and `--nesting-depth=3`. They also turn
DynComp off for every program (Makefile.common). So the oracle here is default
Kvasir: a consistent choice, since the tracer has no per-program knowledge, but
not the suite's intended view of those eight programs. The scaling table near
the end is the exception, and used the Makefile invocations.

The suite's own `.invs.goal` files were **not** used as the oracle. They were
produced with `daikon.derive.Derivation.disable_derived_variables=0`, which
turns on extra derivations; scoring against them while running plain Daikon on
our side would have measured a config difference. They served as a sanity check
that our Kvasir runs reproduce the expected shape.

Program-point names align exactly between the two sides, so nothing below is an
alignment artifact — that was checked first.

---

## Headline

| scope | oracle facts | ours | matched | precision | recall | F1 |
|---|---|---|---|---|---|---|
| **everything** | **4778** | **1352** | **176** | **13%** | **4%** | **6%** |
| non-global | 977 | 1352 | 176 | 13% | 18% | 15% |
| non-global, ≤1 dereference, no strings/floats | 480 | — | 156 | — | 32% | — |
| genuinely plain scalars and returns | 159 | — | 111 | — | **70%** | — |

(The last row excludes by-value struct *members* such as `f.bar_struct.bleh`
and `return.x`, which have no brackets and so look scalar but are a separate
failure counted under cause 3. Including them the figure is 50%; excluding
them, 70%.)

For reference, the same tool on the same day against my own fixtures: **65%
precision, 92% recall, F1 76%**.

Per binary, at full scope:

| binary | oracle | ours | matched | prec | recall |
|---|---|---|---|---|---|
| small-test | 76 | 93 | 42 | 45% | 55% |
| two-statics | 7 | 10 | 6 | 60% | 86% |
| printf-interact | 4 | 8 | 4 | 50% | 100% |
| function-pointer | 4 | 6 | 2 | 33% | 50% |
| string-arrays | 10 | 9 | 3 | 33% | 30% |
| PointerTest | 9 | 20 | 3 | 15% | 33% |
| CoercePointerTest | 77 | 188 | 16 | 9% | 21% |
| md5 | 102 | 135 | 12 | 9% | 12% |
| IntTest | 108 | 58 | 10 | 17% | 9% |
| StructPtrTest | 74 | 6 | 5 | 83% | 7% |
| NestedStructTest | 565 | 2 | 2 | 100% | 0% |
| ArrayTest | 746 | 39 | 1 | 3% | 0% |
| crazy-test-1 | 1079 | 342 | 23 | 7% | 2% |
| *(16 more)* | | | | | |

`small-test` is the only program in the suite whose shape resembles my corpus —
plain int functions, a malloc'd struct, a linked list — and it is also the best
result. That is the finding in one line.

---

## Where the 4778 facts actually are

```
4462  80.5%  global variables
 486   8.8%  two or more levels of dereference  (m[].tiles->a)
 298   5.4%  one level of dereference           (p[], p[].field)
 238   4.3%  plain scalars and returns
  31   0.6%  string contents
  28   0.5%  float / double values
```

**Four percent of this oracle is the shape the tool was built for.** My own
corpus is roughly the inverse.

---

## First: what is NOT wrong

Three checks that could each have explained the number, and none of them does.

**The emulation is exact.** Comparing sample counts per program point between
our dtrace and Kvasir's, across all 29 binaries:

```
program points compared : 198
  identical sample count: 198  (100%)
```

Every function is entered the same number of times under Unicorn as under
Valgrind on real hardware, including a 1000-iteration loop. **We are watching
the same execution.** Whatever is lost is lost in description, not observation.

*Qualified 2026-10-03.* Equal counts are not equal values. An unmodelled
library call is skipped, and nine of these programs call `memcpy`, `memset`,
`strdup`, `strlen` or `toupper`, so where such a call would have changed memory
the samples differ ([RELATED-WORK.md
§1f](RELATED-WORK.md#1f-skipped-library-calls-change-program-state-in-9-of-29-programs)).

**Program point names align.** Checked before anything else; `..makepoint():::ENTER`
on both sides.

**We are not lying.** Of our 1176 unmatched facts, 10 are linear equalities
checkable against Kvasir's own recorded samples. All 10 hold. Zero are false.
(The other 1166 are `has only one value`, `one of {..}`, sequence facts and so
on, which that checker cannot evaluate — so this is weak evidence, but it points
one way.)

So the tracer sees everything, invents nothing, and still scores 4%.

---

## The core of it, in one function

`ArrayTest` has `static int returnIntSum(int a, int* b)`, called once with a
6-element stack array. Side by side:

```
kvasir:  a == 250                          ours:  arg0 == 250          <- matches
         b[] == [61, 61, 62, 63, 65, 68]          arg1[].off0  == [61]
         size(b[]) == 6                           arg1[].off4  == [61]  (as off0 == off4)
                                                  arg1[].off8  == [62]
                                                  arg1[].off12 == [63]
                                                  arg1[].off16 == [65]
                                                  arg1[].off20 == [68]
```

**Every byte is right.** Six 4-byte fields at offsets 0, 4, 8, 12, 16, 20 —
contiguous, uniform, holding exactly the values Kvasir reports. We recovered the
array perfectly and then described it as a struct, so of the three oracle facts
we match one and contribute six unmatched ones.

Why the array model declined is not a bug. Tier 7 needs one of two signals: a
correlated length argument (here `a == 250`, which is not 6) or an allocation
size (`localIntArray` is on the *stack*, so there is no malloc record). Both
discriminators correctly abstained, exactly as designed and exactly as
`TOOL.md`'s known limits say.

**This is the shape of the whole result.** The tracer is usually looking at the
right bytes. What it lacks is the *type*, and Daikon's invariant language is
type-shaped: "an array of six ints" and "a struct with six members" are
different sentences even when they encode identical data. Kvasir does not
out-observe us. It out-*describes* us, from DWARF.

---

## Five causes, in order of size

### 1. Globals — 80% of the oracle, and a claim in our docs was wrong

Kvasir emits every global variable at every program point. We emit none.
`GlobalTest` is the clean case: 13 oracle facts, all of them about globals, and
we produce exactly one fact — `return == 0` — which matches. 100% precision, 8%
recall.

`plans/README.md` has said since phase 1:

> **Do not emit stack locals.** Kvasir reports parameters, pointee views and
> `return` only — `main:::ENTER` has zero variables despite four live locals.

The first sentence is right and the justification is **wrong**. `main:::ENTER`
had zero variables in *my* fixtures because they have no globals. Kvasir reports
parameters, pointee views, `return` **and globals**, and it is not close —
globals are four fifths of everything it says. That claim was derived from a
corpus that could not have disproved it.

Globals are recoverable without DWARF, and the machinery mostly exists: `.data`
and `.bss` bounds come from the section headers, `GlobalAccessMap` (phase 8)
already records every access by address, and a global has the one property a
stack object lacks — **a fixed address and a program-lifetime extent**, so the
temporal-aliasing objection that keeps `--infer-from-caller` off by default does
not apply. Names would stay `data_0x404060`, which the scorer renames from DWARF
exactly as it does `arg0`.

### 2. Functions that never touch their arguments

```c
int bazMapPtr(struct map* m) { return 500; }
```

Kvasir reports 21 facts here: `m[].mapName == [tiles map]`, `m[].tiles->a == [1]`,
`m[].numTiles == [5]`, and so on. We report one: `arg0 has only one value`.

This is `identity_ptr` from my own corpus — where it was one function out of
thirty and cost test12 its score. **Here it is the corpus's entire premise.**
These programs exist to test a type-driven traversal, so their functions
deliberately do nothing. A tracer that dereferences because it *observed an
access* sees an empty body and has nothing to say.

`--infer-from-caller` is the mechanism for this and it is off by default,
because on my corpus it bought 3 points of recall for 22 of precision. Whether
that trade is different here is worth measuring; the objection that drove the
default — nothing bounds a stack object — still applies.

### 3. Structs passed by value — 6 of 6 functions get the wrong arity

This shape does not exist anywhere in my corpus, and it is the one that produced
an actual crash (below).

| function | real params | our arity |
|---|---|---|
| `baz(struct foo f)` | 1 | **18** |
| `createCopy(anonymousStruct a, ROUTEBAGA x)` | 2 | **9** |
| `fcrashint(...)` | 2 | 7 |
| `bar(Buffer actualB)` | 1 | **0** |
| `barMaps(struct map m)` | 1 | **0** |
| `readStruct(...)` | 1 | 2 |

A struct larger than 16 bytes goes on the stack, and the callee reads it a word
at a time. Use-before-def sees each word as a separate argument, so one
252-byte parameter becomes eighteen. A struct the callee never reads goes the
other way and becomes zero. The bytes we report are correct; the *structure* is
not — `arg8 == 4614256650576692846L` is the `double c = 3.14159` of a by-value
struct, reported faithfully and uselessly.

A returned struct has the same problem: `makepoint()` returns a `point` by
value in `rax:rdx`, and Kvasir's `return.x == x` / `return.y == y` have no
counterpart in our single scalar `return`.

### 4. Float and double parameters are invisible — 8 of 8

```c
float floatMultiply(float a, float b) { return a*b; }
```

Our arity: **0**. Floating-point arguments arrive in `xmm0`–`xmm7`, and
`REG_ARG_ORDER` in [infer.py:31](../scripts/tracer/infer.py#L31) lists only the
six integer registers. Every function in `FloatTest` is seen as nullary.

"No floats or SSE at any tier" is already in the known-limits list, so this is
not a surprise — but the list did not say it makes a function's *arguments*
disappear rather than merely mis-typed.

### 5. One level of dereference

`m[].tiles->a` needs two hops. Also already a stated limit; the suite shows it
is 45% of the non-global oracle rather than a corner case.

---

## The precision half: what our 1176 unmatched facts are

Recall explains what we fail to say. Precision explains what we say that the
oracle does not — and it is a different story, worth separating.

Classified by whether Kvasir's `.decls` declares the variables a fact names:

```
750  63.8%  names something the oracle NEVER DECLARES
426  36.2%  every name is a real oracle variable, unstated
```

**The 64% are facts about things that are not program variables.** Two kinds,
both already identified above:

- `arg2`…`arg17` on `ArraysInStructTest`'s `baz` — the eighteen stack words of
  one by-value struct, each reported as an argument. Cause 3.
- `b[].off0`, `b[].off8`, `b[].off12` — the struct-shaped description of an
  array, from the worked example. Right bytes, wrong noun.

So our precision problem is not "we assert things that are false". It is **"we
assert things about the wrong nouns"**, and both nouns come from the same root:
no type information, so the machine's view of memory is the only view available.

The remaining 36% are statements about real variables that Kvasir simply does
not make — including `2*a + -1*b + 3 == 0` on `small-test`, which is
`baa(i, i*2+3)`'s actual contract and which the oracle drops to the `is_param`
coefficient defect documented in `EVALUATION.md`.

### The phase-8 flags are not the cause

Worth checking, since `--infer-unobserved-fields` invents fields by design:

| setting | our facts | matched | precision |
|---|---|---|---|
| `--tier 7`, no flags | 1495 | 176 | 12% |
| + both phase-8 flags | 1352 | 176 | 13% |

The flags *reduce* our output by 143 facts here and match the same 176, so they
are a small net positive on this corpus too. The `off0`/`off8` junk comes from
tier-6 struct recovery itself, not from the speculative flag.

---

## Two bugs this found

Both were invisible to 384 unit tests and a corpus at 0 failures, because
neither shape existed in the corpus.

### A crash on a struct passed by value — fixed

`ArraysInStructTest` traced 1017 instructions cleanly, emitted its samples, and
then died in `_finalize`:

```
IndexError: list index out of range
  emulate.py:1197  v = raw[self._arg_raw_index(i, n_reg)]
```

`baz(struct foo f)` reads about 32 stack slots for its one 252-byte parameter,
so `arity()` reported `n_stack = 32` while the raw vector holds
`MAX_STACK_PROBE = 12`. Nothing bounded the arity by the width of the vector it
indexes.

**Fix:** `MAX_STACK_PROBE` moved into `schema.py` — it is a contract between the
capture path and the inference path, not an emulator detail — and `arity()` now
clamps to it. The clamp states the limit instead of crashing: slots past the
probe were never captured, so there is nothing to emit for them. The earlier
instinct to clamp to `NUM_STACK_ARG_SLOTS` (4) was wrong and would have
truncated `test10`'s legitimate twelve arguments.

This is the same failure class as the four in `plans/review-2026-09-17.md`:
**one component asking another for knowledge it cannot supply.**

### A scorer bug on `static` functions — fixed

Kvasir qualifies a file-scoped function with its source path:

```
oracle:  /abs/path/TypedefTest.c.createCopy():::ENTER
ours:    ..createCopy():::ENTER
```

Eight of the suite's 192 program points are named this way, holding 435 facts.
Unstripped, the function name never reached the DWARF rename map, so every fact
at those points scored as a miss *and* a false positive. `norm_ppt` now strips
the prefix. Worth 4 matched facts here and nothing on my corpus, which has no
static functions — which is exactly why it had never shown up.

That makes **eight** bugs found in the scorer. Every one of them made the tracer
look worse than it is, and every one was found by disbelieving a number.

---

## What holds up

Not everything collapsed, and the parts that held are the parts that were
measured rather than assumed.

- **Robustness: 28 of 29 binaries traced on the first attempt**, and 29 of 29
  after the one-line fix. Never-before-seen code, including a 1000-iteration
  loop (`small-test`, 10006 samples), a linked list, function pointers,
  `setjmp`, unions and 238-line programs.
- **Arity is exact on 81 of 99 functions (82%)** — the core use-before-def
  inference, measured against DWARF directly rather than through Daikon. All 18
  failures are by-value structs (6) or floats (8) or their knock-on effects.
- **Where we speak, we are often right.** `StructPtrTest` 83% precision,
  `NestedStructTest` 100%, `TypedefTest` 100% within scope. The failure mode is
  overwhelmingly silence, not error.
- **My own corpus is unchanged at 65/92/76**, and all 384 tests pass, so
  nothing here was bought by regressing what already worked.

---

## Summary: where the 96% of missing recall goes

Accounting for all 4778 oracle facts, largest first:

| share | cause | is it fixable? |
|---|---|---|
| 80% | **globals not emitted** | yes — section bounds + the existing access map |
| 9% | **2+ levels of dereference** | yes, but each level multiplies the guesswork |
| ~4% | **wrong noun**: array described as struct, by-value struct described as N arguments | needs a type model, not more observation |
| ~2% | **functions that never touch their arguments** | only via `--infer-from-caller`, which costs precision |
| ~1% | floats in `xmm`, strings, multi-level pointers | float registers are mechanical; strings need a type |
| ~4% | matched | — |

And the one-line version: **the tracer's observation is perfect and its
vocabulary is small.** It sees every byte Kvasir sees, at every call Kvasir
sees, and can describe roughly a twentieth of what Kvasir can describe, because
the other nineteen twentieths are statements about *types* — which global this
address is, that six words are an array and not a struct, that these 252 bytes
are one parameter and not eighteen. (Except where a skipped library call would
have changed memory; see the qualification under "The emulation is exact".)

That is the research question restated as a measurement. Stripping does not
destroy the data; it destroys the vocabulary for talking about it.

## What this changes

1. **The corpus was the measurement.** 65/92/76 was never a statement about
   stripped x86-64 binaries in general; it was a statement about ten programs
   written alongside the tool that solves them. The honest summary is now two
   numbers, not one, and the gap between them is the finding.
2. **Globals are the highest-value work left**, ahead of everything in
   `EVALUATION.md`'s open list. Four fifths of a real oracle, a mechanism that
   mostly exists, and no temporal-aliasing objection.
3. **The `identity_ptr` problem is not a corner case.** It was priced as one
   function on one fixture. On a corpus built by someone else it is the norm,
   which changes the calculation behind leaving `--infer-from-caller` off.
4. **For the fuzzing loop this is less bad than it looks.** A fuzzer needs
   invariants that are *true* and that it can try to break. Silence costs
   coverage; it does not mislead. The by-value-struct case is the exception
   worth watching — there the values are right and the *structure* is invented,
   which is the one way to hand a consumer something actively wrong.

## Not yet measured

The 17 remaining programs need input (`argv`, stdin, data files): `bc`, `gzip`,
`bzip2`, `perl`, `space`, `tcas`, `replace`, `print_tokens`, `tot_info`,
`wordplay`. They are the real-program end of the suite and the closest thing
available to the fuzzing target, and they are blocked on the same missing piece
the fuzzing loop is: **no input mechanism**. That item has been on the open list
since the phase-5 retrospective; this is the first measurement that shows what
it costs.


---

## Phase 9: what the decomposition bought

The analysis above said 80% of the oracle was globals and named float
arguments as 8 nullary functions out of 8. Both were built.

| | tracer facts | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| tier 7 (this document) | 1352 | 176 | 13% | 4% | 6% |
| **tier 8 — globals** | 3576 | **802** | **22%** | **17%** | **19%** |
| tier 9 — + floating point | 3569 | 799 | 22% | 17% | 19% |
| **tier 8 + strided-access discriminator** | **3428** | **822** | **24%** | 17% | **20%** |
| tier 8 + `--deref-globals` | 6111 | **978** | 16% | **20%** | 18% |
| tier 8 + `--struct-globals` | 4064 | 679 | 17% | 14% | 15% |

The strided-access discriminator is **on by default** and is the only change
in three phases that cost nothing: it emits 148 fewer facts, matches 20 more,
and leaves the fixture corpus bit-for-bit unchanged. It works by asking which
*instruction* touched which offset — one instruction walking several offsets is
a loop over an array; one instruction per offset is a struct field access.

The two `--...-globals` rows are phase 10's other mechanisms, both **off by default**
because both failed the precision gate set in advance. `--deref-globals`
follows a global that holds a pointer and is a genuine trade: +176 matched
facts for 6 points of precision. `--struct-globals` is a measured failure —
123 facts *lost*, and not one of the 8 struct globals fixed. Full account in
[plans/phase10.md](plans/phase10.md).

**4.6x the matched facts, with precision rising too.** The binaries the
prediction pointed at are the ones that moved:

| binary | recall before | after |
|---|---|---|
| SelectGlobalsTest | 2% | **87%** (F1 85%) |
| two-statics | 56% | **86%** |
| partial-init | 7% | **63%** |
| GlobalTest | 8% | **54%** |
| static-struct | 2% | **50%** |
| IntTest | 9% | **49%** |
| FloatTest | 1% | 24%, and 35% at tier 9 |

On `IntTest` the recovered globals reproduce Kvasir line for line, derived
indexed elements included:

```
::globalX == 5
::globalIntArray[] == [1, 2, ..., 18]
size(::globalIntArray[]) == 18
::globalIntArray[::globalX] == 6
::globalIntArray[::globalX-1] == 5
::globalX in ::globalIntArray[]
```

**Tier 9 is a measured trade rather than a win**, which is why it is a separate
tier and off by default: FloatTest gains 9 facts and everything else loses 12.
The loss is argument ORDER in a mixed parameter list — the ABI numbers integer
and SSE arguments independently and the machine code does not record how they
interleaved, so `f(double a, int b)` recovers both values and assigns them to
each other's names.

*Revised 2026-10-03.* At -O0 the machine code does record the order: the
prologue first reads argument registers in declaration order, on the one mixed
signature in this suite. And the scorer could align by each parameter's ABI
class regardless of order. Either is predicted to turn this trade into a gain;
not yet measured ([RELATED-WORK.md §3.4](RELATED-WORK.md#34-calling-conventions)).

My own corpus is unchanged at 65/92/76 at both tier 7 and tier 8, as it must be:
those ten fixtures contain no globals, which is how this gap stayed invisible
for eight phases.

### What is still missing

The cap is now **types, not addresses**. A `double[5]` global is reported as
five 8-byte integers because nothing distinguishes it from a `long[5]`; a
struct-shaped global gets `.offK` fields rather than named members; a `char*`
global is a pointer where Kvasir prints the string. Those are the same
wrong-noun problem as the array-described-as-struct above, now applied to
globals — which is progress, because at tier 7 the data was not there at all.


---

## How does the ORACLE scale? (measured 2026-09-20)

Worth knowing, because Kvasir is the ground truth this whole project is scored
against, and a ceiling in the oracle is a ceiling on the research.

Run on the suite's larger programs, with the invocations from their own
Makefiles:

| program | source LOC | kvasir | dtrace | ppts | declared vars | samples | daikon | invariants |
|---|---|---|---|---|---|---|---|---|
| tot_info | 406 | <1s | 4.7 KB | 14 | 117 | 2 | 8s | 60 |
| replace | 564 | 2s | 84 KB | 42 | 153 | 756 | 7s | 105 |
| print_tokens | 565 | 5s | **14.5 MB** | 36 | 501 | 5261 | 15s | 2113 |
| wordplay | 1136 | 2s | 1.4 MB | 14 | 464 | 1240 | 20s | 5530 |
| bc | 10348 | 5s | 865 KB | 260 | 4221 | 5392 | 36s | 3045 |
| space | 9126 | ~1s | 1.3 MB | 272 | **21134** | 1074 | 45s | **16741** |

*Noted 2026-10-03:* because these runs used the Makefile invocations, `bc` ran
with `--ignore-globals`. Its 4,221 declared variables and 36s describe a run
with no globals, so they are not a baseline for our runs, which declare every
global.

**It handles them.** A 10k-line program traces in five seconds and Daikon
finishes in well under a minute. Valgrind's overhead is not the problem at this
scale, and neither is Daikon's inference.

**Trace size tracks samples x variables, not source size.** `print_tokens` is
565 lines and produced 14.5 MB — 5261 samples against 501 declared variables —
while `bc`, eighteen times larger, produced one seventeenth of that on a single
small input. Fuzzing multiplies the sample count directly, so this is the axis
that matters for the intended use.

`space` is the interesting one: **21,134 declared variables across 272 program
points**, about 78 per point, from Kvasir's type-driven traversal over a
program with large structs. Daikon still handled it.

### But the suite itself stops asserting above a certain size

The more telling result is what the Daikon authors do with their own biggest
tests:

| program | LOC | expected invariants checked in? | restrictions applied |
|---|---|---|---|
| bc | 10,348 | yes | `--ignore-globals --func-disambig-ptrs` |
| space | 9,126 | yes | two-pass `--disambig` |
| bzip2 | 6,707 | **no** | — |
| gzip | 8,185 | **no** | `SKIP_DTRACE_DIFF`, `SKIP_INVS_DIFF` |
| perl | 97,470 | **no** | `--ignore-globals --nesting-depth=1` |

Thirteen of the suite's tests pass a restricting option. The three largest
programs have **no `.invs.goal` at all** — they are run to check that Kvasir
does not crash, not to check what it produces. `gzip` goes further and
explicitly skips both the trace diff and the invariant diff.

And the restrictions are precisely the two features this project has spent
phases 9 and 10 measuring:

- **`--ignore-globals`** on `bc` and `perl`. Globals are 80% of the oracle on
  the small tests; on a 260-program-point binary the authors turn them off.
- **`--nesting-depth=1`** on `perl` — dereference depth cut to one hop, which
  is exactly where our tracer already sits, and exactly what phase 10's
  mechanism A proposed to increase.

### What that means for this research

1. **Kvasir is a sound oracle at these sizes, but a *configured* one.** Any
   comparison on a large program is against whatever restrictions were applied,
   not against Kvasir's full capability. Our 22%/17%/19% is measured against
   unrestricted Kvasir on small programs — the hardest available setting.
2. **The features we keep finding expensive are the ones its authors also found
   expensive.** That `--nesting-depth=1` is a strong independent signal that
   phase 10's mechanism A should be approached as a cost problem rather than a
   capability problem — the reference implementation reaches for the same
   limit.
3. **Our own scaling is untested and will bite sooner.** `print_tokens`
   executes enough to produce 5261 samples; our emulator currently handles
   corpora of ~650 instructions. Nothing here says the tracer would survive
   these programs, and that is now the obvious next measurement.


---

## tcas, driven properly (2026-09-24)

The 29 programs above are the ones that need no input. Phase 12 added argv, an
`atoi` model and multi-run support, which made the first of the *input-driven*
programs measurable.

`tcas` - a Siemens benchmark, 173 lines, twelve integer arguments - run with the
suite's own 501 input vectors and scored against Kvasir over the same 501:

| | precision | recall | F1 |
|---|---|---|---|
| **tcas** | **94%** | **90%** | **92%** |
| ten fixtures written alongside the tool | 65% | 92% | 76% |
| the 29 no-input programs | 24% | 17% | 20% |

**The best result the project has produced, and on a program nobody here
wrote.** It fits the pattern established earlier rather than contradicting it:
`tcas` is flat - integer globals, integer parameters, no structs, no pointers to
follow - and flat data is exactly where a black-box tracer was measured to do
well. What it adds is that with *enough samples* (501 runs) the agreement on
flat data is near-total, not merely good.

Two things worth recording alongside it:

**We are 30x faster than Kvasir at multi-run.** 501 runs in 11 seconds against
329. Kvasir pays Valgrind startup 501 times; we re-enter one emulator. For a
fuzzing loop this matters more than any single-run figure.

**The 90% is a floor.** `initialize()` alone scores 11% while every other
program point is 91-97%, because both tools state "all globals are zero on
entry" but anchor the equality class on different members - producing disjoint
fact sets that mean the same thing. 80 of the 251 missed facts are pure variable
equalities. See [plans/phase12.md](plans/phase12.md); it is the ninth scorer
limitation found, and like the eight before it, it understates the tracer.
