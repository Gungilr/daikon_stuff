# Phase 10 — recursive traversal (tier 10), and the last of the type gaps

Status: **B and C implemented and measured; A, D, E not started.** Prerequisite:
the tier-8 measurement in
[../EVALUATION-KVASIR-SUITE.md](../EVALUATION-KVASIR-SUITE.md).

## Outcome so far

Both landed mechanisms are **off by default**, because both failed the
precision gate this plan set in advance.

| setting | tracer facts | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| tier 8 default | 3576 | 802 | **22%** | 17% | **19%** |
| `--deref-globals` (B) | 6111 | **978** | 16% | **20%** | 18% |
| `--struct-globals` (C) | 4064 | 679 | 17% | 14% | 15% |
| both | 7133 | 973 | 14% | 20% | 16% |

**B works and costs what the plan feared.** +176 matched facts, recall 17% ->
20%, and the output nearly doubles so precision falls 22% -> 16%. Its
acceptance criterion passed: `NestedStructVarList` now reports
`size(::counters[]) == 10` where it used to report `536870912 == ::counters`,
the heap address as an integer.

**C does not work.** It is worse on every axis — 123 matched facts *lost* — and
it subtracts even from B, which alone matches 978 against their combined 973.
Kept behind a flag so the negative result stays reproducible, not because it is
recommended.

### Why C failed, in three attempts

The plan predicted that adding `struct` to the alphabet would not be enough and
named heterogeneous access widths as the discriminator. Measured against DWARF
ground truth on 72 globals:

```
baseline (no struct hypothesis)        88% shape accuracy   structs 0/8
+ heterogeneous access widths          87%                  structs 0/8
+ a pointer-shaped value in some slot  86%                  structs 0/8
```

Three discriminators, all below baseline, none fixing a single struct. The
reason is specific and was not anticipated: **a statically-initialised struct
is never written at run time.** `static struct desc foo = {array1, 42}` is set
up by the loader, so there are no accesses to be heterogeneous — the evidence
the discriminator needs does not exist. Meanwhile an int array copied eight
bytes at a time *does* produce mixed widths, so the rule fires where it should
not and stays silent where it should fire.

This is the `--infer-from-caller` lesson repeating: a mechanism can be
correctly motivated, correctly implemented, and still not pay.

### Two format bugs, and a validator so there is no third

Both made Daikon reject **entire traces** while the run exited 0 and produced a
report that merely looked sparse:

- `var-kind field` with no relative name -> "end-of-line found where relative
  name expected". Two binaries to zero.
- (phase 9) `enclosing-var` naming an undeclared variable. Nine binaries to
  8-fact stubs.

`DaikonTraceWriter.validate()` now checks both plus duplicate declarations, and
runs on every `close()`. Writing it immediately caught a **third** issue — in
the validator itself: requiring enclosing variables to be declared *before* use
rejected five binaries Daikon is perfectly happy with, because Daikon resolves
after reading the whole program point. `return[..]` has preceded `return` since
phase 8. The rule is presence, not order.

Every mechanism below was checked against the binaries before being written
down, per the project's standing rule. **One of the five checks failed and the
mechanism was redesigned as a result** — see D.

---

## The finding this phase acts on

Classifying all 3975 remaining oracle misses by the single fact the tracer
lacks:

| count | share | missing fact | observable? |
|---|---|---|---|
| 2142 | 53.9% | a pointer **inside a struct**, 2+ levels deep | yes — range check + access map |
| 809 | 20.4% | a **global** that is a pointer/array → a sequence | yes — same |
| 355 | 8.9% | these bytes are a **struct with members** | yes — access offsets |
| 215 | 5.4% | a local pointer/array → a sequence | yes — same |
| 254 | 6.4% | other / plain scalar | mixed |
| 110 | 2.8% | these 8 bytes are a **double**, not a long | only from a consuming opcode |
| 90 | 2.3% | this `char*` is a **string** | only from its target |

**88.6% of what remains is type information already present in the execution
and not acted on.** Only 5.1% needs a signal the bytes do not carry.

### The top four rows are ONE bug, not four

They all need the same two facts, and the tracer computes both already:

- **is this value a pointer?** — `memmap.classify()`, a range check, since tier 3
- **what is behind it?** — `GlobalAccessMap`, every access by address, since phase 8

What is missing is **recursion**. The dereference path is special-cased per
root: arguments get `_capture_pointees`, the return value got bolted on in
phase 8, globals get nothing. Kvasir walks the type graph transitively from
every root. We walk one hop from one root kind.

So A, B and C below are not three mechanisms. They are **one traversal with
three kinds of root**, and most of the work is deleting the special cases.

---

## Measured before planning

### Depth 2 is the right limit

Dereference hops per oracle fact, across the whole suite:

```
depth 0:  1774  (32.0%)
depth 1:  1706  (30.8%)
depth 2:  1436  (25.9%)
depth 3:   244  ( 4.4%)
depth 4+:  383  ( 6.9%)

a limit of 2 covers 88%; a limit of 3 covers 93%
```

Depth 3 buys 5 points for a level of fan-out, so **depth 2 is the default and
depth is a flag**. This also matches Fjalar's own default, which is not a
coincidence: it is where the cost curve turns for both tools.

### 65 of the 85 globals we emit are pointers

Checked by range against the live memory map. Every one of them is currently
printed as an integer where Kvasir prints a sequence. That is row 2 of the
table, confirmed end to end.

### There are cycles, so a depth limit is not enough

`small-test` builds `n1->next = n2; n2->prev = n1`. A traversal that only
counted depth would still revisit `n1`, and with a `--deref-depth 3` it would
emit `n1[]->next->prev` — a variable naming the object we started from. **A
visited-set keyed by address is mandatory, not a nicety.**

### Kvasir's naming for depth 2

```
bp[]->char_val      cp[]->basic      m[].tiles->a
```

First hop is `[..]`; hops through a pointer FIELD use `->name`. Matching this
exactly is what makes the facts comparable at all — the phase-6 lesson that
representation *is* the interface.

### D FAILED its check, and is redesigned because of it

The plan was to find double-typed globals by scanning for SSE instructions with
RIP-relative operands. Measured:

```
FloatTest    8 SSE-touched data addresses, naming known globals: []
GlobalTest   0 SSE-touched data addresses      (globalDouble exists)
TrivialTest  1 SSE-touched data address,  naming known globals: []
```

**Zero hits.** The addresses found are floating-point literals in the constant
pool, not the globals; and `GlobalTest` never loads `globalDouble` as a double
at all, because `main` only takes its address. Static scanning does not work.

The **dynamic** form does, and is the same technique that overturned
"signedness is not observable" in phase 8: when a `movsd` executes against
address X at run time, X holds a double. `FloatTest` reads `globalDouble[i]` in
a loop, so the evidence is there during execution even though it is not there
in the instruction stream. Where the program never uses the value as a float —
`GlobalTest` — nothing can recover it, and that is the genuine 5%.

---

## A. Recursive traversal from all roots (tier 10) — ~3200 facts

**Not started.** B's result reprices it: B is one hop from one new root kind and
already doubled the output for +176 facts. A is the same operation at depth 2
from three root kinds, so the fan-out is larger and the precision cost should be
expected to be worse, not better. It should be built behind a flag from the
start, with the depth limit as a parameter, and measured at depth 1 before
depth 2.

Replace three special cases with one walker.

```python
def walk(value, name, depth, visited):
    if depth > max_depth or value in visited:
        return
    if memmap.classify(value) is not POINTER:
        return
    visited.add(value)
    layout = layout_for(value)        # alloc size | symbol size | access map
    emit(name, layout)                # sequence, or fields
    for offset, width in layout.pointer_fields():
        walk(read(value + offset, width),
             f"{name}->{field_name(offset)}", depth + 1, visited)
```

Roots: **every parameter, every global, the return value.** That is the whole
change in principle; in practice it means:

1. **Extract the layout decision** already split across `_pointee_layout`,
   `_return_pointee_layout` and `_global_specs` into one function of
   `(address, size_hint)`. They already do the same three things in three
   places, which is why globals silently lost the struct branch.
2. **Make the schema builder recursive**, emitting `VarSpec`s with the
   `enclosing_var` chain Daikon requires. Phase 9's crash — declaring `g[..]`
   without `g` rejects the *entire trace* — is a standing trap here, because
   a recursive builder can emit a child before its parent. The builder must
   emit parents first by construction, not by luck.
3. **Capture must recurse too**, and at capture time, since the bytes behind a
   depth-2 pointer are gone by finalize. Capture broadly, emit narrowly: walk
   to `max_depth + 1` when capturing, decide what to declare later.

**Cost control.** Each level multiplies variables, and Daikon's invariant count
grows worse than linearly in variables per program point. We already emit 3576
facts against an oracle of 4777; an unbounded walk could put us in five figures
and destroy precision. Mitigations, in the order they should be tried:

- depth 2 by default, `--deref-depth N` to change it
- a visited set per sample, keyed by address
- do not follow a pointer whose pointee has no layout evidence — that is the
  `--infer-from-caller` failure mode one level deeper, and it will be worse
  there because the fan-out multiplies the invented fields

**Falsifiable acceptance:** `NestedStructTest` (565 oracle facts, we match 10)
must exceed 150. If it does not, the layout evidence is not reaching depth 2
and the mechanism is not doing what this plan claims.

## B. Globals as traversal roots — 809 facts

Falls out of A once globals are roots. Listed separately only because it can
land first and be measured on its own: it needs no recursion, just the
existing one-hop dereference applied to the 65 pointer-shaped globals.

**Do this one first.** It is the largest single block reachable without any
recursion at all, so it separates "we did not traverse" from "we did not
recurse" in the measurements.

**Falsifiable acceptance:** `NestedStructVarList`, where
`struct counter *counters` points at a malloc'd 10-element array, must report
`size(::counters[]) == 10`. We currently report `536870912 == ::counters`,
the heap address as an integer.

## C. Struct-shaped globals — 355 facts

`objects_from_symbols` produces only scalars and arrays; the struct branch of
`_global_specs` is dead code — **we emit zero `.offK` on any global**.
`globalBoo {int a; int b;}` at 8 bytes becomes one scalar.

The fix is inside the layout function A extracts: when a symbol's extent does
not tile uniformly, fall to fields instead of collapsing to one opaque value.

**Falsifiable acceptance:** at least one `g_0x...offK` variable appears in the
`NestedStructTest` trace. Zero today.

## D. Floating-point typing from RUNTIME access — 110 facts

Redesigned after the static scan measured zero, above.

Tag an address as float-typed when an executing SSE instruction reads or writes
it, recording width from the mnemonic (`movss` 4, `movsd` 8) exactly as tier 9
already does for arguments. A global or field so tagged is emitted with
`rep-type double`.

Not universal, by construction: a `double` the program never loads as a double
is indistinguishable from a `long`. `GlobalTest` is that case and will not be
recovered. **Expected yield is well under 110** for that reason — call it the
subset that FloatTest and crazy-test-1 actually exercise.

## E. Strings — 90 facts

A pointer into `.rodata` whose target is a NUL-terminated run of printable
bytes is a `char*`. Verified present: `.rodata` holds 1 such run in
`GlobalTest`, 7 in `string-arrays`.

Emit `rep-type java.lang.String` with the text, as Kvasir does. Cheap,
self-limiting, and wrong only for a genuine byte array that happens to look
like text — which is the same class of approximation as `--poison-uninitialized`
and should be flag-gated for the same reason.

---

## Order and dependencies

```
B  globals as roots, one hop       809   no dependencies   <- first
C  struct-shaped globals           355   shares B's layout function
A  recursive traversal, depth 2   ~2400  needs B and C's unified layout
D  float typing from runtime SSE   <110  independent
E  strings from .rodata             90   independent, flag-gated
```

B before A deliberately. B is the largest block obtainable **without**
recursion, so measuring it alone tells us how much of the gap was missing
roots versus missing depth — and if A then disappoints, we still know which
half was which. Doing A first would confound the two permanently.

---

## Risks, in the order they are likely to bite

1. **Precision collapse.** This is the `--infer-from-caller` lesson: that
   mechanism recovered real facts and cost 22 points of precision for 3 of
   recall. Recursion has the same shape with a multiplier. Every step below
   is measured on its own and reverted if it does not pay.
2. **Fact-count explosion** slowing Daikon past the point of usefulness. The
   suite already takes ~15 minutes; `crazy-test-1` emits 657 facts at tier 8.
3. **Cycles** — mandatory visited set, see above.
4. **Parent-before-child declaration.** Phase 9's crash rejected entire traces
   and produced 8-fact stub reports that looked like successful runs. A
   recursive builder makes this easy to reintroduce; the acceptance criteria
   must include "Daikon exits 0 on all 29".

---

## Acceptance

- All lower-tier goldens byte-identical; tiers 0-9 unchanged unless `--tier 10`.
- Daikon exits 0 on all 29 suite binaries — no stub reports.
- Our own 10-fixture corpus stays at **65/92/76** or better.
- Suite recall rises from **17%**; each of B, C, A, D, E measured separately so
  its contribution is attributable.
- **Precision must not fall below 20%.** It is 22% now. A mechanism that buys
  recall by dropping precision below that is reverted and flag-gated, on the
  standing rule that for a fuzzing consumer an invented fact is worse than an
  absent one.

## What this phase will NOT recover

- **Names.** Permanently destroyed by stripping; the scorer supplies them from
  DWARF precisely because the tracer never can.
- **A `double` the program never uses as a double** (`GlobalTest`), and by the
  same argument an `unsigned` never shifted or compared. This is the
  information-theoretic residue, measured at roughly 5% of the oracle.
- **The order of a mixed int/float parameter list** — tier 9's stated limit.
- **Depth beyond the limit**: 7% of the oracle sits at depth 3+.
