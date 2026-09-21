# Phase 7 — Tier 7: array bounds

Status: **complete**. Prerequisite: Phase 6 (complete).

## Outcome

327 tests pass; goldens for tiers 0-3, 5 and 6 byte-identical; `./test.sh
--tier 7` at 0 failures. test08 is byte-identical between tiers 6 and 7, so the
discriminator never fires on a struct.

`sum_array(int *arr, int n)` now matches Kvasir's shape exactly - `arg0[..]`
with `rep-type int[]` carrying `[ 1 2 3 4 5 ]`, no field sub-variables - and
Daikon produces sequence facts the struct form could not express:

```
arg1 == size(arg0[])            <- the (pointer, length) contract
size(arg0[]) == arg0[arg1-1]
arg0[] == [1, 2, 3, 4, 5]
size(arg0[]) == 5
```

`arg1 == size(arg0[])` is the most security-relevant invariant the system has
produced. It states the buffer-length contract, and an input that breaks it is
by definition a length/bounds mismatch - exactly the class a fuzzer consuming
these invariants would want to target.

The discriminator behaved as designed on all three fixture shapes:

| function | outcome |
|---|---|
| `sum_array(arr, n)` | array - `n` equals the element count on every call |
| `two_fields(p, 99)` | struct - the int argument never equals the count |
| `stack_read`, `heap_read` | struct - no integer argument at all |

### A bug found and fixed as a prerequisite

Pointee capture consulted `arity()`, which is learned from executed
instructions and is therefore `(0, 0)` at the moment a function is entered.
Every function lost its **first** call's pointee (verified on test08: sample 1
was `nonsensical`, samples 2-10 were fine), and a function called **once** -
like `sum_array` - lost everything. Any array measurement taken before this fix
would have been meaningless.

Capture is now keyed by raw slot index and classifies against the live memory
map, independent of arity. **Capture broadly, emit narrowly.** Two regression
tests guard both forms of the bug.

### A soundness fix the fixture exposed

`varying_len` is called with a 20-byte and then a 12-byte allocation. The
allocation size was stored per (function, argument) with last-write-wins, so
footprints merged across calls could credit a parameter with fields existing in
only one of the objects. It now keeps the **minimum** size seen.

### Known limit, deliberately not papered over

`varying_len` reads only `arr[n-1]`, so its footprint is non-contiguous
(offsets 8 and 16 across two calls) and it stays struct-modelled. It genuinely
is an array, and the tracer cannot tell - the evidence is not there. A
fixed-size array passed without a length parameter is invisible for the same
reason. Both are stated limits rather than wrong guesses, which is the safe
failure mode for a consumer that will act on these invariants.

## Purpose

Tier 6 models every pointee as a struct: one variable per recovered field.
That is right for `pair_t *`, and wrong for `int *` pointing at an array.
Kvasir distinguishes them from DWARF:

```
struct pointee:   p[..]     rep-type hashcode[]   + p[..].a, p[..].b
array pointee:    arr[..]   rep-type int[]        value: [ 1 2 3 4 5 ]
```

The array form gives Daikon a sequence to reason over - sortedness, element
bounds, membership - where the struct form gives only per-offset constants.
For a consumer looking to break invariants, sequence facts about an array are
substantially richer targets than five unrelated field equalities.

---

## Findings from investigation

### 1. The addressing-mode discriminator does not work at -O0

The tier-6 plan suggested distinguishing arrays from structs by addressing
mode - scaled-index (`(%rax,%rdx,4)`) for arrays, constant displacement
(`0x4(%rax)`) for structs. Measured, gcc -O0 does neither:

```
sum_array, for arr[i]:            pair_sum, for p->a:
  lea  0x0(,%rax,4),%rdx            mov  -0x8(%rbp),%rax
  mov  -0x18(%rbp),%rax             mov  (%rax),%edx
  add  %rdx,%rax
  mov  (%rax),%eax                <- both end in a plain dereference
```

The index is scaled and added *arithmetically*, then dereferenced plainly. At
the instruction level `arr[i]` and `p->a` are indistinguishable, so the
discriminator has to come from somewhere else.

### 2. `array 1` means one DIMENSION, not one element

Kvasir declares both `p[..]` (one struct) and `arr[..]` (five ints) with
`array 1`. The element count lives in the *data*, not the declaration -
`[ 0x1ffefffcb0 ]` versus `[ 1 2 3 4 5 ]`. Tier 6 already emits `array 1`, so
the declaration side needs no change; only the value side does.

### 3. A pointee-capture bug, fixed as a prerequisite

Found while probing an array fixture: pointee capture consulted `arity()`,
which is learned from executed instructions and is therefore `(0, 0)` at the
moment a function is entered. Consequences:

- every function lost its **first** call's pointee (verified on test08:
  sample 1 was `nonsensical`, samples 2-10 were fine);
- a function called **once** lost everything - `sum_array` produced
  `nonsensical` for all five fields.

Capture is now keyed by raw slot index and classifies against the live memory
map, independent of arity. Emission still narrows by arity at finalize.
**Capture broadly, emit narrowly.** Any array measurement taken before this fix
would have been meaningless.

### 4. The discriminator: a correlated length argument

`int p[2]` and `struct {int a, b;}` are genuinely indistinguishable from access
patterns - identical footprints, identical widths. No heuristic separates them,
and pretending otherwise would be false precision.

What *is* observable is the dominant C idiom: an array parameter travels with
its length. `sum_array(int *arr, int n)` is called with `n = 5` and the
allocation holds exactly 5 elements. When another integer argument equals the
computed element count on every observed call, the pointee is an array.

This has the right failure mode. No length argument means no array claim, so
`stack_read`, `heap_read` and `pair_sum` stay struct-modelled - which is
correct for all three. A fixed-size array with no length parameter stays
struct-modelled too; that is a known, stated limit rather than a wrong guess.

---

## Design

`deref.py` gains the classification, keeping it pure:

```python
def element_count(fields, object_size)      -> int | None
def looks_like_array(fields, object_size, candidate_lengths) -> bool
```

- **Uniform width** is necessary but not sufficient: every recovered field must
  have the same width, and the fields must tile the object contiguously from
  offset 0.
- **Element count** is `object_size // width`.
- **Length correlation** decides it: some integer argument equals that count on
  every call.

`emulate.py`:
- Collect each call's integer argument values alongside the footprint, so the
  correlation can be checked at finalize.
- When the array model applies, emit `argN[..]` with `rep-type int[]` and the
  whole decoded sequence as its value, and emit **no** `argN[..].offK`
  variables - matching Kvasir, where the two forms are alternatives rather than
  complements.
- Otherwise keep tier 6's struct form unchanged.

Gated on `--tier >= 7`, so all six lower-tier goldens stay frozen.

---

## Issues, ranked by how quietly they fail

**Issue A — a coincidental length match.** A two-field struct whose function
also takes an unrelated argument equal to 2 would be mis-modelled as an array.
*Mitigation:* require the correlation to hold on every observed call, and
require at least two elements; assert `stack_read`/`heap_read` stay structs.

**Issue B — element count from a partially-read object.** If only the first two
elements of a five-element array are read, the footprint covers 8 of 20 bytes.
Using the footprint rather than the allocation size would report 2 elements.
*Mitigation:* prefer `Arena.size_of`; fall back to the footprint only when no
allocation record exists, and say so in the output.

**Issue C — losing struct facts by switching model.** The array form drops the
per-field variables, so a mis-classification costs the `off0 - off4` relations
outright. *Mitigation:* the conservative discriminator above; a test asserting
test08's relations survive at tier 7.

**Issue D — variable-length sequences across calls.** Daikon accepts sequences
of differing length, but our capture window is fixed. *Mitigation:* bound reads
by `size_of` per pointer, which is already per-call.

---

## Test plan

### Unit — `tests_py/test_array_infer.py` (pure)
- uniform contiguous fields plus a matching length ⇒ array.
- non-uniform widths ⇒ not an array.
- a gap between fields ⇒ not an array.
- no candidate length ⇒ not an array (the `pair_t` case).
- length matching on one call but not another ⇒ not an array.
- single element ⇒ not an array.
- element count from allocation size, not footprint (Issue B).

### E2E — `tests_py/test_e2e_tier7.py`
- all six lower-tier goldens byte-identical.
- new fixture `tests/test13.c` with `sum_array(int *arr, int n)`:
  `arg0[..]` is `rep-type int[]`, carries the whole sequence, and has no
  `offK` sub-variables.
- test08's `stack_read`/`heap_read` remain struct-modelled and keep
  `off0 - off4 + 1 == 0` (Issue C).
- **regression guard for finding 3**: a single-call function recovers a real
  pointee, not `nonsensical`.

---

## Acceptance

- Six lower goldens byte-identical; `./test.sh --tier 7` at 0 failures.
- `sum_array` matches Kvasir's shape: `int[]` sequence, no field variables.
- test08 unchanged from tier 6 — the discriminator must not fire on structs.
- Daikon reports at least one sequence-level fact about the array that the
  struct model could not express.
