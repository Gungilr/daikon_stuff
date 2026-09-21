# Phase 5 — Tier 5: allocator model

Status: **complete**. Prerequisite: Phase 3 (complete).

## Outcome

Both false positives removed; `heap_read`'s program points are now empty rather
than wrong. 254 tests pass, goldens for tiers 0-3 byte-identical, `./test.sh
--tier 5` at 0 failures.

| | tier 3 | tier 5 |
|---|---|---|
| `heap_read` pointer | `0` on all 10 calls | 10 distinct arena addresses |
| pointer typing | `rep-type int` (scalar) | `rep-type hashcode` |
| `arg0 == 0` | reported (false) | gone |
| `return >= orig(arg0)` | reported (false) | gone |
| test08 invariants | 4 | 2 |

`heap_read` still returns `0 2 4 ... 18`, proving the arena is genuinely
writable and readable rather than merely a plausible-looking address.

Tier 5 changed **only** test08 - every other binary is byte-for-byte unchanged,
confirming the tier gating.

### A correction to the phase 3 table

The phase 3 counts under-reported. Daikon's progress output overwrites with
carriage returns and can leave padding on an invariant line; the counting
filter excluded lines beginning with whitespace, silently dropping one
invariant per affected file. Counting with leading whitespace stripped,
**five** binaries are at parity with Kvasir, not three:

| binary | tier 5 | Kvasir |
|---|---|---|
| test02 | 7 | 7 |
| test03 | 2 | 2 |
| test09 | 8 | 8 |
| test10 | 14 | 14 |
| test11 | 2 | 2 |

### Implementation notes

- Byte escapes do not survive the patch pipeline into source text. Escape
  sequences intended as literal source characters were interpreted instead,
  so a two-byte jump opcode became a non-ASCII byte literal and a zero-fill
  constant became an actual NUL byte in the file - the second one made the
  module unparseable. Both are now written arithmetically, as
  `bytes((0xFF, 0x25))` and `bytes(n)`, which no pipeline can mangle.
  Worth remembering for any future generated code containing byte escapes.
- `_layout_index` had to be introduced so the heap base could shift per layout
  the way the stack base already did.

> **Tier 4 was skipped deliberately.** Covariance pointer classification measures
> as a no-op on this corpus: the range-based classifier in `memmap.py` gets
> 5 of 118 variables right as pointers and misclassifies nothing, because no
> integer in the corpus coincidentally lands in a mapped address range. It has
> no acceptance criterion that currently fails. Revisit it if a future fixture
> makes the range test demonstrably wrong.

## Purpose

`heap_read` in `tests/test08.c` is the only function in the corpus the tracer
gets *wrong* rather than merely incomplete, and the cause is that `malloc` is
never executed.

Today, a call to an unresolved import is skipped outright with the return
register forced to zero ([emulate.py:555-577](scripts/tracer/emulate.py#L555-L577)).
So `heap_read` receives a null pointer on every call, the `pair_t` actually
lives on the zero page that the unmapped-memory hook lazily maps, and the
tracer emits two invariants that are true of the emulation and **false of the
program**:

```
..heap_read():::ENTER   arg0 == 0
..heap_read():::EXIT    return >= orig(arg0)
```

Those are the corpus's only false positives against the oracle.

## The sequencing argument

Phase 3's test08 breakdown found Kvasir's 37 facts split 35 / 2: thirty-five
need dereference, two do not, and the tracer already recovers both. So tier 6
is what moves the number — but **tier 6 cannot help the heap half without tier
5 first**. Dereferencing a null pointer reads the zero page, not the struct.
For `stack_read` the pointer is genuine and tier 6 alone would work; for
`heap_read` the ordering is a hard dependency. That constraint was not explicit
in the master plan, and test08 is the fixture that exposes it.

---

## Findings from investigation

### 1. PLT resolution works on fully stripped binaries — verified

`strip --strip-all` removes `.symtab` but cannot remove `.dynsym` or
`.rela.plt`; the dynamic loader needs them. Running the resolution against
`tests/test08_stripped.exe`:

```
.rela.plt (GOT slot -> symbol)      .plt.sec stub -> symbol
  0x404000 -> free                    0x401060 -> free
  0x404008 -> printf                  0x401070 -> printf
  0x404010 -> malloc                  0x401080 -> malloc
```

The mechanism, in two steps and no guesswork about entry ordering:

1. `.rela.plt` gives GOT slot → symbol name directly (pyelftools
   `RelocationSection`, already a dependency).
2. Each PLT entry is scanned for the `ff 25` opcode (`jmp *disp(%rip)`); the
   target is `next_insn_addr + disp`, which is the GOT slot. Composing the two
   maps stub address → symbol name.

Deriving the stub from the relocation *index* would be fragile — this reads the
actual jump target instead.

### 2. Valgrind does not reuse freed blocks, so neither should we

The obvious design question is whether the model should recycle memory on
`free`, as glibc does. Kvasir's own trace answers it: `test08` allocates and
frees an 8-byte struct ten times, and Kvasir observed **ten distinct
addresses**, stepping by 0x50:

```
0x4a7a040  0x4a7a090  0x4a7a0e0  0x4a7a130  0x4a7a180 ...   (10 distinct)
```

Valgrind's allocator adds redzones and delays reuse for error detection, so the
ground truth the tracer is scored against exhibits **non-reuse**. A recycling
model would return the same address every iteration and manufacture a spurious
`arg0 has only one value` that Kvasir does not report.

So: bump-allocate, never recycle. This is the rare case where the simplest
implementation is also the one that matches the oracle — worth recording,
because "be more realistic, reuse freed memory" is the change someone will
later propose as an improvement.

### 3. The interception point is the call site, not the PLT stub

`--skip-unknown-calls` fires on the `call` instruction and rewrites RIP past it,
so the PLT stub never executes and a hook on the stub address would never run.
The allocator check therefore has to sit **before** the generic skip in the same
branch.

### 4. Scope: four functions

`malloc`, `calloc`, `realloc`, `free`. `printf` stays generically skipped —
modelling output has no bearing on invariants.

---

## Design

### `alloc.py` (pure)

```python
class Arena:
    def __init__(self, base, size)
    def malloc(self, n)        -> addr | 0 on exhaustion
    def calloc(self, n, sz)    -> (addr, nbytes_to_zero)
    def realloc(self, p, n)    -> (addr, nbytes_to_copy)
    def free(self, p)          -> bool           # False if unknown/double free
    def size_of(self, p)       -> int | None     # the ptr -> size map
    def live(self)             -> dict
```

Bump pointer, 16-byte aligned (the SysV guarantee for `malloc`). `malloc(0)`
returns a unique non-null address, as glibc does. Freed blocks are marked dead
and never reissued.

`size_of` is the reason this phase matters beyond removing two false positives:
it is the allocation-size oracle **tier 6** needs to bound a dereference and
**tier 7** needs for array element counts.

Pure, so the allocation policy is unit-testable without an emulator.

### `elfload.py` — PLT symbol resolution

`resolve_plt_stubs(elf_path) -> {stub_addr: symbol_name}`, implementing finding
1. Lives here because it is ELF parsing and needs pyelftools only.

### `emulate.py` — interception

- Map the arena into Unicorn and register it with `MemoryMap` as a `"heap"`
  region, so heap pointers classify as POINTER (tier 3 machinery, no change).
- Arena base shifts per `--layouts` run, exactly as the stack does, so a fixed
  heap address cannot masquerade as a program property.
- In the call branch, before the generic skip: if the target is a known
  allocator stub, read arguments from the ABI registers, run the arena
  operation, write the result to RAX, perform any required memory effect
  (`calloc` zeroing, `realloc` copying), and advance RIP past the call.
- Gated on `--tier >= 5`, so all four lower-tier goldens are untouched.

---

## Issues, ranked by how quietly they fail

**Issue A — arena collides with an existing mapping.** Unicorn would raise on
`mem_map`, or worse, silently overlap a lazily-mapped page and corrupt program
state. Base 0x20000000 sits far from the image (~0x400000) and the stack
(0x7fff00000000+, +0x1000000 per layout). *Mitigation:* assert the arena range
intersects no PT_LOAD segment and no stack range at setup, and fail loudly.

**Issue B — arena exhaustion turns into silent corruption.** A bump allocator
that runs off the end would hand out addresses outside the mapped region; writes
then trigger the lazy-map hook and appear to work. *Mitigation:* return 0 on
exhaustion — degrading to exactly today's behavior — and log a warning. Test
with a deliberately tiny arena.

**Issue C — `realloc` semantics.** Returning a new block without copying leaves
the caller reading uninitialized memory, which shows up as garbage values in
invariants rather than as a crash. *Mitigation:* copy `min(old, new)` bytes;
test that the contents survive.

**Issue D — non-reuse looks like a bug.** Freed memory never being recycled is
deliberate (finding 2) and will look wrong to a future reader. *Mitigation:* a
test named for the reason, asserting ten allocations give ten distinct
addresses, citing Kvasir's observed behavior.

**Issue E — double free / free of a foreign pointer.** Real code under test may
do either. *Mitigation:* `free` returns False and logs; never raises. Emulation
must not abort on a program bug.

**Issue F — the zero page stops being written.** Today `heap_read`'s struct
lives at address 0-ish. After this change it lives in the arena, so any test or
assumption keyed to the old behavior breaks. *Mitigation:* this is the point of
the phase; `test_e2e_tier3.py` assertions about `arg0 == 0` are tier-3-gated and
must stay that way.

---

## Test plan

### Unit — `tests_py/test_alloc.py` (pure)
- addresses are 16-byte aligned and strictly increasing.
- blocks never overlap: `addr + size <= next_addr`.
- `malloc(0)` returns a unique non-null address.
- `free` then `malloc` returns a **different** address (Issue D, finding 2).
- `size_of` round-trips; returns None for an unknown pointer.
- exhaustion returns 0 rather than running past the arena (Issue B).
- double free and foreign free return False without raising (Issue E).
- `realloc` reports the correct copy length; growing and shrinking both.

### Unit — `tests_py/test_plt_resolve.py`
- `resolve_plt_stubs` finds malloc/free/printf in **both** `test08.exe` and
  `test08_stripped.exe`, at identical addresses — the claim that stripping does
  not hide the allocator.

### E2E — `tests_py/test_e2e_tier5.py`
- all four lower-tier goldens byte-identical.
- `heap_read`'s `arg0` is non-zero and classified `rep-type hashcode`.
- ten calls yield ten distinct pointer values (matching Kvasir's shape).
- the two false positives are gone: `arg0 == 0` and `return >= orig(arg0)`
  absent from the tier-5 report.
- the program still computes the right answer: `acc = 190` in `test08`, proving
  the arena is genuinely writable and readable.
- `--layouts 3` moves the heap base, so no fixed heap address survives.
- a tiny `--heap-size` degrades to null returns without crashing.

---

## Acceptance

- Goldens for tiers 0-3 byte-identical; `./test.sh --tier 5` at 0 failures.
- `heap_read` loses both false positives and gains a correctly typed pointer.
- `size_of` is populated and queryable — the deliverable tier 6 consumes.
- Invariant *count* on test08 will barely move (roughly 4 → 3, losing two false
  positives and gaining a pointer-typing fact). **That is success, not failure.**
  This phase buys correctness and unblocks tier 6; the 35-fact jump belongs to
  dereference. Judging tier 5 by count would mis-read it as a regression.

## Carried into Phase 6

- `Arena.size_of` bounds every heap dereference and supplies tier 7's element
  counts.
- Heap pointers classified as POINTER give tier 6 its list of what to follow.
- `stack_read` needs none of this — its pointer is already valid, so tier 6 can
  be validated on the stack half first and the heap half second, isolating
  allocator bugs from dereference bugs.
