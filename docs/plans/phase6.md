# Phase 6 — Tier 6: struct recovery by dereference

Status: **complete**. Prerequisite: Phase 5 (complete).

## Outcome

294 tests pass; goldens for tiers 0-3 and 5 byte-identical; `./test.sh --tier 6`
at 0 failures.

Recall rose sharply, which is the criterion this phase was judged by.
`stack_read`'s declarations now mirror Kvasir's structure exactly - pointer,
one-element array, one variable per field - and the recovered relations match:

| Kvasir | tier 6 |
|---|---|
| `p[].a - p[].b + 1 == 0` | `arg0[].off0 - arg0[].off4 + 1 == 0` |
| `p[].a elements < return` | `arg0[].off0 elements < return` |
| `p[].b elements <= return` | `arg0[].off4 elements <= return` |
| `3 * p[].a - p[].b == 0` | `3 * arg0[].off0 - arg0[].off4 == 0` |

test08 invariant counts: **5 (tier 5) -> 67 (tier 6) -> 86 with tail
inference**, against Kvasir's 37. Essentially full recall of Kvasir's facts,
with roughly twice as many extras - mostly trivially-true sequence facts about
a one-element array (`arg0 in arg0[]`, `arg0[] is the reverse of orig(arg0[])`).
Sound but redundant; the same class that real modbits would suppress.

All three findings held up in implementation:

- **Attribution by value was necessary.** The pointer is spilled and reloaded
  into rax before use, so `rdi` is never dereferenced; a register-based hook
  would have recovered nothing.
- **Tail inference is what recovers `heap_read`'s second field.** Without
  `--infer-unobserved-fields` only `off0` appears, because the program never
  reads `off4`. With it, both - and `3 * off0 - off4 == 0` follows. This is the
  larger of tier 5's two payoffs.
- **Matching Kvasir's array representation mattered.** Facts come out as
  `elements < return`, the same form Kvasir produces, rather than the scalar
  equations that no alignment could have matched.

### Implementation note

Helpers initially took the call-stack frame tuple and indexed into it, which
broke because `ret_addr` and `frame_base` are computed *after* the ENTER sample
is taken. They now take `(func_addr, arg_values)` explicitly.

## Purpose

The last and largest gap. Phase 3's breakdown of `tests/test08.c` found Kvasir's
37 facts split 35 / 2: two are reachable without following a pointer and the
tracer already recovers both. **Every remaining miss in the corpus needs
dereference.**

Tier 6 is also the phase that dissolves the packed-word problem: at tier 0 the
tracer accidentally encoded `stack_read`'s true relation as
`4294967297 * rax - 2 * stack0 + 4294967295 == 0`, because the fixed stack
window happened to overlap the caller's frame and captured the whole struct as
one 64-bit word. Splitting by observed access width turns that into
`off0 - off4 + 1 == 0`, matching Kvasir's `p[].a - p[].b + 1 == 0`.

---

## Findings from investigation

### 1. The dereference happens through a COPY, so attribution must be by value

The obvious implementation - watch memory accesses made through the argument
register - does not work. At -O0 the pointer is spilled and reloaded before use:

```
stack_read:
  mov  %rdi,-0x8(%rbp)      <- argument spilled
  mov  -0x8(%rbp),%rax      <- reloaded into a DIFFERENT register
  mov  (%rax),%edx          <- the dereference happens through rax
  mov  -0x8(%rbp),%rax
  mov  0x4(%rax),%eax
```

`rdi` is never dereferenced. Attribution must therefore compare the **effective
address** of each access against the **value** each traced argument held for
this invocation: an access at `A` belongs to argument `N` when
`0 <= A - value(argN) < bound`. That works regardless of which register holds
the copy, and regardless of how many copies the compiler makes.

`UC_HOOK_MEM_READ` supplies the effective address directly, so this needs no
operand decoding.

### 2. Access footprints alone under-report, and the allocator fixes it

The two functions in test08 have deliberately different footprints:

```
stack_read:  reads offset 0 (4 bytes) AND offset 4 (4 bytes)   -> both fields seen
heap_read:   reads offset 0 (4 bytes) ONLY                     -> field `b` invisible
```

`heap_read` computes `p->a * 2` and never touches `b`, so a pure footprint
model recovers one field where Kvasir reports facts about two. Six of Kvasir's
eleven `heap_read` facts mention `p[].b` and would stay out of reach.

But the allocation size is known: `mov $0x8,%edi ; call malloc` gives
`Arena.size_of == 8`, against an observed footprint of 4 bytes. The unobserved
tail can therefore be **inferred**: an 8-byte object with a 4-byte field at
offset 0 has 4 bytes left at offset 4. This is the second, larger payoff from
tier 5 - `size_of` is not just a bound, it is what makes unobserved fields
recoverable at all.

It is a heuristic (the tail could be one 8-byte field whose low half was read),
so it goes behind `--infer-unobserved-fields`, measurable on its own like
`--detect-void`. **Stack pointers have no such oracle** - no allocation record
exists for a caller's local - so there the footprint is the whole story.

### 3. Kvasir models a pointer as a one-element array, and matching that matters

```
variable p[..]          var-kind array    enclosing-var p       rep-type hashcode[]   array 1
variable p[..].a        var-kind field a  enclosing-var p[..]   rep-type int[]        array 1
```

with data written in bracket syntax: `[ 0x1ffefffcb0 ]`, `[ 1 ]`.

This is why Kvasir reports `p[].a elements < return` rather than
`return == p->a + p->b`: the pointee is a sequence, and Daikon does not infer
linear equations between a sequence and a scalar. Emitting flat scalars instead
would produce *different invariant forms* that no amount of scoring alignment
could match. Matching the representation is a precondition for comparability,
not a stylistic choice.

### 4. The writer needs sequence values; the declaration side is already done

`VarSpec` already carries `var_kind`, `enclosing_var`, `array` and the `[]`
rep-types, and `tests_py/test_writer_tier1.py` already covers them. Only the
data path needs work: it currently writes `f"{val}"`, which would render a
Python list as `[1, 2]` rather than Daikon's `[ 1 2 ]`.

Unreadable or null pointees need Daikon's `nonsensical` value with **modbit 2**,
which the writer also does not yet support.

---

## Design

### `deref.py` (pure)

```python
class FootprintTracker:
    def note_access(self, func_addr, arg_index, offset, width)
    def layout(self, func_addr, arg_index, object_size=None) -> [(offset, width), ...]
```

Accumulates `(offset, width)` per argument across every invocation and layout.
`layout()` merges them into non-overlapping fields, and - when `object_size` is
supplied and `--infer-unobserved-fields` is on - pads the tail with slots of the
most common observed width.

Conflict rule: if the same offset is seen at two widths, the **widest** wins,
since a narrow access may be a partial read of a wider field. (Note this is the
opposite of the tier-3 argument-width rule, where *first* wins because the -O0
prologue spill names the true width. Different evidence, different rule.)

### `emulate.py`

- Enable `UC_HOOK_MEM_READ` at tier 6 and attribute each access by value
  (finding 1), using the argument values captured at ENTER and carried on the
  call-stack frame.
- Bound the attribution window by `Arena.size_of` for heap pointers, and by a
  configurable cap for stack/image pointers where no size is known.
- At sample time, read the pointee bytes from the live emulator and decode each
  inferred field.
- Emit `argN`, `argN[..]`, `argN[..].offK` mirroring Kvasir's shape (finding 3).
  Field naming is by offset because source field names are destroyed by
  stripping; the scoring harness aligns `offK` to DWARF field names.

### `writer.py`

- Sequence values render as `[ v1 v2 ]`.
- `nonsensical` with modbit 2 for a null or unreadable pointee.

### Comparability

Fields take a class by inferred scalar type, and `return` must share it - this
is exactly what tier 3 set up, and it is what produces the
`p[].a elements < return` family. Getting it wrong here silently deletes the
most valuable invariants in the phase.

---

## Issues, ranked by how quietly they fail

**Issue A — attributing an unrelated access to an argument.** A stack pointer
and a nearby local differ by a small offset, so an over-wide window swallows
accesses that are not pointee reads, inventing fields. *Mitigation:* use
`size_of` where available; keep the unknown-size cap small (one or two words by
default) and configurable; assert `stack_read` recovers exactly two fields, not
three.

**Issue B — the inferred tail is wrong.** An 8-byte object read only at offset 0
might hold one `long`, not two `int`s. *Mitigation:* behind
`--infer-unobserved-fields`; measure both ways; the acceptance criteria record
the difference rather than assuming.

**Issue C — reading a pointee at EXIT that has been freed.** `test08` frees the
struct inside the loop; reading a dangling pointer would yield whatever the
arena holds. Non-reuse (tier 5) means the bytes are still intact, so this is
currently benign - but it is benign *by accident*. *Mitigation:* consult
`Arena` liveness and emit `nonsensical` for a freed pointee.

**Issue D — infinite depth.** A pointer-to-pointer would recurse. *Mitigation:*
one level only in this phase; note the limit explicitly.

**Issue E — performance.** `UC_HOOK_MEM_READ` fires on every load. The corpus
runs ~650 instructions per binary, so this is irrelevant here, but it is the
first hook that scales with data rather than code.

**Issue F — tiers 0-5 must not move.** Five goldens now. *Mitigation:* all five
checked on every change; add `test08.tier5.dtrace`.

---

## Test plan

### Unit — `tests_py/test_deref.py` (pure)
- merging: accesses at (0,4) and (4,4) give two fields; a repeat of (0,4) still gives two.
- widest-wins on conflicting widths at one offset.
- tail inference: footprint (0,4) with `object_size=8` gives fields at 0 and 4;
  with no size, gives one field.
- overlapping accesses (0,8) and (4,4) resolve without producing overlaps.
- no accesses gives an empty layout, not an error.

### Unit — `tests_py/test_writer_deref.py` (pure)
- sequence values render as `[ 1 2 ]`, single-element as `[ 1 ]`.
- `nonsensical` carries modbit 2, not 1.
- an array variable declares `var-kind array`, `enclosing-var`, `array 1`.

### E2E — `tests_py/test_e2e_tier6.py`
- all five lower-tier goldens byte-identical.
- `stack_read` recovers exactly two fields at offsets 0 and 4.
- `heap_read` recovers one field without `--infer-unobserved-fields`, two with it.
- Daikon on tier-6 output reports the field relation for `stack_read`
  (`off0 - off4 + 1 == 0`, matching Kvasir's `p[].a - p[].b + 1 == 0`).
- the packed-word artifact is gone and replaced by the split-field form.
- a freed pointee emits `nonsensical` rather than stale bytes.
- test08 invariant count rises sharply from 2 toward Kvasir's 37.

---

## Acceptance

- Goldens for tiers 0-5 byte-identical; `./test.sh --tier 6` at 0 failures.
- `stack_read` reaches or approaches parity with Kvasir's 12 facts.
- `heap_read` recovers field `b` only with `--infer-unobserved-fields`, and the
  plan records both numbers rather than reporting the better one.
- **Recall rises for the first time since tier 1.** Tiers 2-5 improved precision
  and correctness while recall stayed flat or dipped; this is the phase that is
  supposed to move it. If recall does not rise materially, the phase failed
  regardless of how clean the output looks.

## Carried into tier 7 and scoring

- `FootprintTracker.layout` plus `Arena.size_of` gives element counts, which is
  all tier 7 (array bounds) needs.
- The scoring harness gains its hardest alignment problem: `argN[..].off0` must
  map to `p[..].a` via DWARF field offsets. Offsets are recoverable and names
  are not, so alignment by offset is the only sound approach.
