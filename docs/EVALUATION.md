# Evaluation against Kvasir

Two measurements, both content-based. Everything before them was invariant
*counts*, which conflate precision with recall: `test09` once showed 8 against 8
and agreed on 6.

`scripts/score_invariants.py` renames the tracer's `arg0`, `arg0[].off4` onto
Kvasir's `p`, `p[].b` using DWARF read **at scoring time only**, canonicalizes
both sides, and set-compares. It also validates the oracle against its own
sample data.

| | corpus setting | P | R | F1 |
|---|---|---|---|---|
| baseline, 2026-09-17 | `--tier 7 --infer-unobserved-fields` | 59% | 84% | 69% |
| **after phase 8** | + `--poison-uninitialized` | **65%** | **92%** | **76%** |

> **These numbers are about ten fixtures written alongside the tool.** On
> Daikon's own Kvasir test suite — 29 programs written by other people, for
> another front-end — the same build scores **13% / 4% / 6%**. See
> [EVALUATION-KVASIR-SUITE.md](EVALUATION-KVASIR-SUITE.md), which decomposes
> that gap; 80% of it is global variables, which this corpus has none of.

The baseline row is the number as it was reported on the day. Three further
bugs were found in the scorer afterwards (see below), so part of the gap is the
instrument getting more accurate rather than the tracer getting better; the
ablation separates the two.

---

## Headline — after phase 8

`--tier 7 --infer-unobserved-fields --poison-uninitialized`, 10 binaries.

| binary | oracle facts | false | valid | tracer | matched | precision | recall | F1 | recall was |
|---|---|---|---|---|---|---|---|---|---|
| test02 | 7 | 0 | 7 | 10 | 7 | 70% | **100%** | 82% | 100% |
| test03 | 2 | 0 | 2 | 2 | 2 | 100% | **100%** | 100% | 100% |
| test07 | 15 | 0 | 15 | 36 | 15 | 42% | **100%** | 59% | 100% |
| test08 | 31 | 0 | 31 | 42 | 31 | 74% | **100%** | 85% | 100% |
| test09 | 8 | **2** | 6 | 13 | 6 | 46% | **100%** | 63% | 100% |
| test10 | 14 | 0 | 14 | 25 | 14 | 56% | **100%** | 72% | 100% |
| test11 | 2 | 0 | 2 | 2 | 2 | 100% | **100%** | 100% | 100% |
| test13 | 41 | 0 | 41 | 56 | **41** | 73% | **100%** | 85% | 78% |
| test14 | 36 | 0 | 36 | 43 | **30** | 70% | **83%** | 76% | 72% |
| test12 | 16 | **1** | 15 | 10 | 7 | 70% | 47% | 56% | 44% |
| **TOTAL** | **172** | **3** | **169** | **239** | **155** | **65%** | **92%** | **76%** | 84% |

**Eight of ten binaries reach 100% recall**, including `test08` — the pointer
fixture the entire dereference effort was aimed at — at 31/31, and `test13`,
the array fixture, at 41/41.

Thirteen more oracle facts matched, and **precision rose at the same time**:
the tracer emits one fact *fewer* than at the baseline. Nothing here was bought
by saying more.

"false" counts oracle invariants that Kvasir reports and its own trace data
contradicts. Three exist — two in `skip_middle`, one in `big_unsigned`, all
three from the `is_param` defect (see below). They are excluded from the
denominator because failing to reproduce a false statement is not a recall
failure.

### What each flag is worth

Full ablation, every row measured on the same code and the same corpus, so the
differences are attributable:

| setting | tracer facts | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| `--tier 7`, no flags | 232 | 144 | 62% | 85% | 72% |
| + `--poison-uninitialized` | 232 | 148 | 64% | 88% | 74% |
| + `--infer-unobserved-fields` | 239 | 151 | 63% | 89% | 74% |
| **both (the reported figure)** | **239** | **155** | **65%** | **92%** | **76%** |
| + `--infer-from-caller` | 375 | 161 | 43% | 95% | 59% |

Reading it:

- **Both flags pay for themselves**, and both *raise precision* as well as
  recall. Poisoning does so because a fabricated zero is a false positive:
  removing it deletes a wrong fact and adds a right one, with the emitted
  count unchanged at 232.
- **Neither subsumes the other.** They act on different binaries — poisoning on
  `test14`, unobserved fields on `test08` — so their contributions add.
- **`--infer-from-caller` does not pay.** 136 extra facts bought 6 matches.

The always-on mechanisms (A, C, D) do not appear as a row, because there is no
flag to switch them off; their contribution is the `test13` column going 78% ->
100% and `big_unsigned` becoming a matched fact.

---

## Why 28 facts were missed at the baseline

Root-caused individually, not bucketed by keyword. The last column records
what phase 8 actually did with each — **13 of the 28 closed and a 14th retired
as an oracle defect**, with the reasons the rest were not given below rather
than left as "future work".

| count | cause | binary | outcome |
|---|---|---|---|
| 8 | non-contiguous footprint blocks the array model | test13 `varying_len` | **8 recovered** (C) |
| 5 | pointer argument never dereferenced by the program | test12 `identity_ptr` | needs `--infer-from-caller` |
| 4 | stack pointee: unread field, no size oracle | test14 `maybe` | needs `--infer-from-caller` |
| 4 | **uninitialized memory fabricated as 0** | test14 `fill` | **4 recovered** (E) |
| 3 | pointer **return value** never dereferenced | test12 `identity_ptr` | mechanism built (D); still needs a layout |
| 2 | self-referential sequence trivia | test14 `fill` | not pursued (F) |
| 1 | indexed-element fact (`arr[n-1]`) | test13 `sum_array` | **the tracer already had it** — scorer bug |
| 1 | signedness | test12 `big_unsigned` | **values corrected** (A); the oracle's own invariant is false, so the fact left the denominator |

One of the 28 was never a tracer gap at all: `sum_array`'s `arr[n-1]` had been
emitted correctly since tier 7 and mis-scored. That is the argument for
root-causing from the actual missed-and-extra lists rather than from the
bucket — the bucket said "needs an array model", and the array model was
already there.

### The one that is a correctness problem, not a recall gap — FIXED

`fill(pair_t *p, int v)` is called three times; on the first call `p` points at
an **uninitialized** local.

```
kvasir p[].a at ENTER:  nonsensical  [ 1 ]  [ 2 ]
ours   p[].a at ENTER:  [ 0 ]        [ 1 ]  [ 2 ]     <- before phase 8
ours   p[].a at ENTER:  nonsensical  [ 1 ]  [ 2 ]     <- with --poison-uninitialized
```

Valgrind tracks definedness bit-by-bit and reports `nonsensical`. Unicorn zeroes
fresh pages, so **the tracer fabricates an observation of a value that was never
written**. Two consequences: it pollutes the value set (Kvasir infers
`p[].a one of {1,2}`, we cannot), and in principle it can produce invariants
about memory the program never initialized.

This is the only place the tracer states something untrue about the program
rather than merely failing to state something true. A full fix means shadow
memory — reimplementing memcheck's V-bits. A cheap approximation is poisoning
fresh stack frames and arena allocations with a recognizable pattern and
emitting `nonsensical` on a read of it; imperfect, since a genuine value could
equal the poison, but it converts a silent fabrication into a visible gap.

### `identity_ptr` — the 47% case

```c
int *identity_ptr(int *p) { return p; }
```

**All eight of test12's remaining misses are this one function** — the ninth,
`big_unsigned`, turned out to be an oracle defect rather than a miss. It never
dereferences `p`, so there is no access footprint and no pointee — while
Kvasir dereferences **by type**, reporting `p[] == [7]` and `size(p[]) == 1`
from DWARF alone. It also returns a pointer, and we follow only *arguments*, so
`return[]` and `size(return[])` have no counterpart either.

That is the structural difference between the two tools in one example:
**Kvasir dereferences because the type says pointer; we dereference because we
observed an access.** A pass-through or getter function has no accesses to
observe.

Both halves are fixable, and both were built. The second worked: the capture
path is parameterised by slot index, so following the return was mechanical.
The first did not pay: `p` points at a **stack** `int`, where no allocation size
exists and nothing observable bounds the object, so the speculative
dereference invents fields out of neighbouring locals. test12 is still at 47%
for exactly this reason, and the fix is bounding a stack pointee — open item 2
below — not more speculation.

### `varying_len` — why the array model declined, and what unblocked it

```c
int varying_len(int *arr, int n) { return n > 0 ? arr[n - 1] : 0; }
```

Called with a 5-element and a 3-element array, reading only the last element
each time. The merged footprint is offsets 8 and 16 — non-contiguous, so it
fails the uniform-tiling precondition and stays struct-modelled. Kvasir reports
`arr[] one of { [1,2,3,4,5], [10,20,30] }` and `n == size(arr[])`.

This was the documented limit behaving as designed rather than a defect: the
tracer declines to claim an array it cannot evidence. Worth noting that the
*length correlation* is present here (`n` equals the element count) — only the
footprint test blocked it.

**Resolved in phase 8, without trusting one signal instead of two.** The second
signal turned out to be `n * 4 == malloc size`, which holds on every call and
needs no footprint coverage at all — arguably stronger evidence than tiling
rather than weaker. `varying_len` now yields `[1 2 3 4 5]` and `[10 20 30]`,
sequences of differing length from one program point.

---

## Precision: 65%, and why that is a floor

A large share of "false positives" are **true statements the oracle
suppresses**. On `test02`:

```
ours:    3*a - return == 0        return == 3a. TRUE, and strictly stronger
kvasir:  return % orig(b) == 0    than what the oracle reports.
```

`flags is_param` makes Daikon drop non-unit coefficients and omit relations
entirely. Where it produces an outright falsehood the validator catches it
(3 cases now — `big_unsigned` joined the two in `skip_middle` once the scorer
could parse its constant); where it merely suppresses, our correct extra facts
count against us. 65% is therefore a lower bound.

`big_unsigned` is the cleanest illustration, because both tools saw identical
samples:

```
kvasir:  return - orig(x) - -2147483648 == 0     off by 2^32 on its own data
ours:    return - x - 2147483648 == 0            true on every sample
```

The genuinely spurious extras are one-element-sequence trivia (`p in p[]`,
`p == p[] elements`) and single-run constants that `--layouts` removes.

---

## Seven bugs found in the scorer itself

Every one of them made the tracer look worse than it is, and every one was
found by disbelieving a number rather than by reading code. A measurement
instrument is not exempt from being wrong, and its errors are the hardest kind
to notice, because they arrive looking like results.

Found during the 2026-09-17 evaluation:

| bug | effect |
|---|---|
| no `orig()` substitution | `test03` scored 1/2 where it agrees 2/2 |
| equality not symmetric | `p == return` vs `return == p` counted as miss *and* false positive |
| comparison direction not normalized | `return >= orig(b)` vs `b <= return` likewise |
| `size()` of an unchanged sequence not treated as unchanged | cost `test08` its last 3 facts |

Found after phase 8, by asking why a mechanism that demonstrably worked had
not moved its binary's score:

| bug | effect |
|---|---|
| subscript variables not renamed | `arr[arg1-1]` vs `arr[n-1]`: 4 facts on `test13` scored as miss *and* false positive |
| scientific notation unparsed | `-2.14748e+09` read the `e` as a variable name, so `big_unsigned`'s invariant never canonicalized |
| doubled signs mis-collapsed | `- -2147483648` read as `- 2147483648`, which **validated a false oracle fact** by turning it into our own correct one |

The last is the one worth dwelling on, because it did not look like a bug. It
produced a plausible answer — it just happened to be the answer to a different
question, and the effect was to charge the tracer a point of recall for being
right where Kvasir was wrong.

Cumulative effect: **F1 51% → 69% → 76%**. The scorer now has 25 tests of its
own, and every bug in both tables has one. A measurement instrument without
tests will quietly mis-report the thing it exists to measure.

---

## Can the 28 be recovered? — worked through, then built

Worked through case by case, with the signal checked against the binaries
rather than assumed. **26 of 28 are recoverable; 2 are vacuous and not worth
recovering. None is impossible.** One entry below corrects a claim made earlier
in this document.

All five mechanisms were then implemented ([plans/phase8.md](plans/phase8.md)).
Each subsection below carries its measured outcome. The prediction that stood
up worst was B, whose unbounded form works but costs more precision than the
recall is worth; the one that stood up best was C, which delivered more than
its own estimate because the indexed fact at `sum_array` followed from it.

### A. Signedness — I was wrong to call this unobservable (1 fact) — DONE

The value carries no signedness, but **the operations applied to it do**:

```
unsigned x >> 3   ->  shr      int x >> 3   ->  sar
unsigned x > 100  ->  seta     int x > 100  ->  setg
```

And the signal exists in the exact failing case. `big_unsigned` itself only
ORs, but its caller does:

```
call big_unsigned
shr  $0x1c,%eax      <- LOGICAL shift: the result is unsigned
```

So signedness is recoverable by watching which instructions consume a value -
`shr`/`sar`, `seta`/`setg`, `movzx`/`movsx`. Not universally: a value never
shifted, compared or widened leaves no trace. But "not dynamically observable"
was too strong, and the corpus's one signedness miss is squarely in the
observable set.

**Result:** `big_unsigned` now reports `2147483649, 2147483650, ...`, matching
Kvasir's samples exactly, while `negate` — consumed by signed opcodes — still
reports -1..-5. The "Known limits" entry claiming signedness was unobservable
has been retracted in `TOOL.md`, and the test that deliberately asserted the
wrong answer has been rewritten to assert the right one.

It also turned up a **third false oracle fact**. From identical samples, Daikon
reports `return - orig(x) - -2147483648 == 0` for Kvasir and
`return - x - 2147483648 == 0` for us. Ours is true on the data; Kvasir's is
off by 2^32, the `is_param` defect again. The scorer had been silently
collapsing that doubled sign the wrong way, which made the false one validate
and cost us the point.

### B. The global access map — the highest-leverage change (9 facts) — BUILT, THEN RESTRAINED

Two causes share one root. `identity_ptr(int *p) { return p; }` never
dereferences, and `maybe(pair_t *p)` reads only `p->a`. In both cases **the
callee did not touch the memory, but somebody did**: the caller initialised
`local = 7` and `q = {3,4}` right before the call.

Today the footprint is keyed per (function, argument) and only records accesses
made while that function is the innermost frame. Recording every access by
*address*, and consulting that map when a pointer argument is found, supplies
the layout the callee never revealed.

This is how the tool would approximate what Kvasir gets from types: Kvasir
dereferences because the type says pointer; we would dereference because
*something, somewhere* accessed that memory.

**The risk is temporal aliasing.** A stack address holds different objects at
different times, so the map must be scoped - by frame lifetime, or more simply
by consulting only the *caller's* accesses before the call. Heap addresses have
no such problem, because the arena deliberately never reuses a freed block.

**Result: it works, and it is not worth it by default.** The risk above turned
out to dominate.

```
                       tracer facts   matched   prec   recall   F1
default                         239       155    65%      92%   76%
--infer-from-caller             375       161    43%      95%   59%
```

136 more facts emitted to gain 6. `identity_ptr`'s argument is a stack `int`,
and nothing observable says where a stack object the callee never touched ends,
so the 64-byte window swallowed neighbouring locals and invented three fields.
`test14` went 43 facts -> 98, recall 83% -> 94%, precision 70% -> 35%.

So the default consults the map only where an allocation size bounds it
exactly, and the unbounded form is behind `--infer-from-caller`. **This was the
prediction that survived contact worst, and it is the most useful thing the
scorer has done** — without it, "9 facts recovered" would have looked like a
win.

### C. Array detection without a tiled footprint (9 facts) — DONE, best of the five

`varying_len` reads only `arr[n-1]`, giving offsets 8 and 16 across two calls -
non-contiguous, so the uniform-tiling precondition fails. But a second,
independent signal is available and holds exactly:

```
call 1:  n = 5,  allocation = 20 bytes,  access width 4   ->  5 x 4 == 20
call 2:  n = 3,  allocation = 12 bytes,  access width 4   ->  3 x 4 == 12
```

`length x element_width == allocation_size`, on every call. That is arguably
stronger evidence of an array than contiguous tiling, and it needs no footprint
coverage at all. Adding it as an alternative discriminator recovers the eight
`varying_len` facts, and the indexed fact at `sum_array` should follow once the
sequence exists.

Cost: it rests the array decision on the allocation size, so it applies to heap
arrays only. A stack array with a length parameter stays out of reach.

**Result: test13 went 78% -> 100% recall, all 41 oracle facts.** `varying_len`
now yields `[1 2 3 4 5]` and `[10 20 30]` — sequences of *differing length*
from one program point, which fall out of taking the element count from the
per-call blob rather than from an aggregate. The implementation needed per-call
evidence: the allocation size had been aggregated to a minimum and the integer
arguments to a set, which destroys the pairing that carries the whole signal.

The last four of those 41 were not the tracer's doing. They are Daikon's
derived indexed elements — `arr[n-1]` — which the tracer emitted correctly as
`arr[arg1-1]` and the *scorer* failed to rename inside the bracket. C recovered
eight facts; fixing the scorer revealed the ninth and unmasked three of C's.

### D. Pointer-valued returns (3 facts) — BUILT, blocked downstream

**Result:** the capture path is parameterised by slot index, so following slot
0 at EXIT was mechanical, and `return[..]` is now emitted. `identity_ptr`'s
three facts still do not land, because the *layout* of that pointee is what is
missing, and that is B's problem, not D's.

### E. Uninitialised memory (4 facts) — the only correctness item — DONE

Valgrind tracks definedness bit-by-bit and reports `nonsensical`; Unicorn zeroes
fresh pages, so the tracer fabricates a value. Two routes:

- **Poison** fresh stack pages and arena allocations with a recognisable
  pattern and emit `nonsensical` on reads of it. Cheap. Imperfect - a genuine
  value equal to the poison is misread - but it converts a silent fabrication
  into a visible gap.
- **Shadow memory**, a real V-bit map updated on every write. Correct, and
  essentially reimplementing memcheck.

**Result:** poisoning, behind `--poison-uninitialized`. test14 went 72% -> 83%
recall and 60% -> 70% precision *at an unchanged emitted count*, because a
fabricated zero is not a missing fact — it is a wrong one. `fill`'s ENTER
samples are now byte-identical to Kvasir's. This is the only change in the
phase that made the output more **true** rather than more complete.

### F. Not worth recovering (2 facts)

`p[] == p[] (elementwise)` and `p[] is the reverse of p[]` are vacuous for a
one-element sequence. Kvasir emits them; we do not. Chasing them would add
noise to match noise.

### Summary — predicted against delivered

| mechanism | predicted | delivered | notes |
|---|---|---|---|
| length x width == allocation (C) | 9 | **+8 matched** | the 9th was never a tracer gap — see the scorer row |
| definedness tracking (E) | 4 | **+4 matched** | exactly as predicted |
| signedness from consuming ops (A) | 1 | **0 matched** | the values are now right; the oracle's invariant is false, so there was nothing to match |
| pointer-valued returns (D) | 3 | 0 | built, but the pointee has no layout without B |
| global access map (B) | 9 | 0 by default | works; costs 22 points of precision, so opt-in |
| vacuous (F) | 2 | 0 | not pursued, as planned |
| scorer fixes | — | **+1 matched, −1 valid** | `sum_array`'s fact was always emitted; `big_unsigned`'s oracle fact is false |

Numerator 142 -> 155, denominator 170 -> 169: **recall 84% -> 92%.**

A is the entry worth reading twice. It cost a day's estimate of one fact and
scored zero, because the thing it fixed was the tracer's *values* — and once
those were right, Kvasir's invariant over the same values turned out to be
wrong. A mechanism can be entirely successful and move the metric not at all;
that is a property of scoring against a fallible oracle, not a reason to
distrust the mechanism.

The estimate of "roughly 99% if all of A–E landed" was too optimistic for one
reason worth stating plainly: it counted B's nine facts as recoverable without
pricing the false positives that come with them. Recoverable and *worth
recovering* are different claims, and the scorer is what makes the second one
answerable.

Nothing in the list is blocked by an information-theoretic limit; what remains
unrecoverable in principle is the thing stripping actually destroys — **names**,
which the scorer supplies from DWARF precisely because the tracer never can.

## Recommendations

### Done in phase 8

| # | recommendation | outcome |
|---|---|---|
| 2 | dereference pointer-valued returns | built; blocked on a layout for the pointee |
| 3 | speculatively dereference a never-accessed pointer argument | built as `--infer-from-caller`; measured a bad trade, left opt-in |
| 4 | relax uniform tiling when a length argument correlates | built as `length * width == allocation`; test13 78% -> **100%** |
| 5 | poison fresh stack frames and arena memory | built as `--poison-uninitialized`; the only fabrication in the output is gone |
| — | signedness from consuming opcodes | built; `big_unsigned` matches Kvasir's **samples** exactly — its invariant does not, because Kvasir's is false |

### Open, in value order

1. **Decide whether `--infer-unobserved-fields` and `--poison-uninitialized`
   become tier-7 defaults.** Together they are worth **+11 matched facts and
   +3 points of precision** on this corpus (see the ablation above), and
   neither has a measured downside here. Both remain opt-in because both are
   *approximations* — one guesses the width of memory nothing touched, the
   other misreads a genuine `0xABABABAB` — and the project's standing rule is
   that a speculative heuristic is gated so its contribution stays separately
   measurable. That rule is what made the `--infer-from-caller` finding
   possible. This is a policy call about that trade, not a defect.
2. **Bound a stack pointee.** Every remaining miss that `--infer-from-caller`
   would fix is really one problem: nothing observable says where a stack
   object ends. Frame-lifetime scoping, or consulting only the caller's
   accesses *between its own frame setup and the call*, would make the
   mechanism safe enough to enable by default. That is the single highest-value
   piece of work left — it is worth 6 facts today and costs 136 false ones, and
   it is all that stands between `test12` and the other eight binaries.
3. **Modbits.** Still hardcoded to 1. The clearest remaining precision lever:
   it would suppress the `argN == orig(argN)` class that roughly doubled counts
   when `is_param` was dropped, and those are most of the honest-but-redundant
   extras behind the 65%. Recall is at 92%; precision is where the remaining
   headroom is.
4. **Attribute an access to every matching pointer, not just the first** —
   the two-buffer (`memcpy`) blind spot, confirmed but not yet costing the
   corpus anything.
5. Make `DEREF_WINDOW` configurable; currently a silent 64-byte cliff for
   stack pointees.

### Not a recommendation, but the thing to remember

Seven bugs in the scorer, then one prediction (B) that was right about the
mechanism and wrong about its value. All were caught by measuring rather than
reasoning, and in every case the reasoning had been careful. **The estimate that
all of A–E would reach ~99% recall was not a small miss; it was 92%**, because
it counted facts as recoverable without pricing what comes with them.

Three of the seven scorer bugs were found in a single sitting, by asking one
question of each mechanism that had landed: *did the binary it targets actually
move?* `test13` had moved less than mechanism C should have moved it, and
`test12` had not moved at all despite `big_unsigned` now producing Kvasir's
exact values. Neither discrepancy was visible in the aggregate — both were
visible immediately in the per-binary column. **Aggregate metrics hide
instrument bugs; per-unit ones expose them.**
