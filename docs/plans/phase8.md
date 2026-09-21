# Phase 8 — recovering the 28 missed facts

Status: **complete**. Prerequisite: the 2026-09-17 evaluation.

## Outcome

381 tests pass; all six lower-tier goldens byte-identical; `./test.sh --tier 7`
at 0 failures.

| | tracer facts | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| before | 240 | 142 | 59% | 84% | 69% |
| after | **239** | **155** | **65%** | **92%** | **76%** |

Thirteen more facts matched while emitting one *fewer*, so none of the gain was
bought by saying more. Full ablation in
[../EVALUATION.md](../EVALUATION.md#what-each-flag-is-worth).

**Eight of ten binaries at 100% recall**, including test13 at 41/41.

Contributions, measured separately:

| mechanism | result |
|---|---|
| C array via allocation size | test13 78% -> **100%**; `varying_len` yields `[1 2 3 4 5]` and `[10 20 30]`, differing lengths as Kvasir does |
| E definedness poisoning | test14 72% -> 83% recall and 60% -> 70% precision, at an unchanged emitted count; `fill` reports `nonsensical [1] [2]`, byte-identical to Kvasir |
| A signedness from opcodes | `big_unsigned` returns 2147483649.. matching Kvasir's samples exactly, `negate` still -1..-5. Scores zero: with the values right, Kvasir's invariant over them turned out to be false, so the fact left the denominator instead of entering the numerator |
| D pointer-valued returns | `return[..]` and its fields now emitted |
| B global access map | safe half on by default; speculative half gated (below) |

### Four of the thirteen were never the tracer's fault

Three bugs in the **scorer** surfaced while checking each mechanism against the
binary it targeted, and all three had been hiding facts the tracer already
produced: subscript variables left un-renamed (`arr[arg1-1]` vs `arr[n-1]`),
scientific notation parsed as a variable name, and a doubled sign collapsed the
wrong way — which had been *validating a false oracle fact* by turning it into
our own correct one.

The method that found them is worth keeping: for each mechanism that landed,
ask whether the binary it targets actually moved. test13 moved less than C
should have moved it; test12 did not move at all although `big_unsigned` was
now producing Kvasir's exact values. Neither was visible in the aggregate.

### B was measured and then restrained

The unbounded form recovers more but costs far more than it gains:

```
                       tracer facts   matched   prec   recall   F1
default                         239       155    65%      92%   76%
--infer-from-caller             375       161    43%      95%   59%
```

**136 more facts emitted; 6 more matched.** Three points of recall for
twenty-two of precision. On `identity_ptr`, whose
argument is a stack `int`, the 64-byte window swallowed neighbouring locals and
invented three fields that do not exist. Nothing observable bounds a stack
object the callee never touched, so the default now uses the global map only
where an allocation size bounds it exactly, and the speculative form is behind
`--infer-from-caller`. For a consumer acting on these invariants, invented
fields are worse than absent ones.

`test14` shows the shape most clearly: 43 facts -> 98, recall 83% -> 94%, and
precision 70% -> 35%. The extra recall is real; so are the 55 invented facts
that came with it.

### A test that was meant to fail, and did

`test_unsigned_is_knowingly_wrong` asserted the WRONG answer, with a docstring
saying that if it ever started failing, signedness inference had arrived and
the limitation note should go. It failed. It is now
`test_unsigned_return_matches_kvasir`, and the claim that signedness is not
dynamically observable has been retracted in three documents.

### Still missed

test12 remains at 47%, and it is almost the whole of the remaining gap:
`identity_ptr`'s pointee needs the speculative global map, which is off by
default for the reason above. test14's remainder is the two vacuous sequence
facts and `maybe`'s unread stack field. test13 has no remainder.

Each mechanism was validated against the binaries before being planned, so none
of these rests on an assumption about what the compiler emits.

## Order and dependencies

```
C  array via allocation size      9 facts   independent
B  global access map              9 facts   independent
D  pointer-valued returns         3 facts   needs B for the identity_ptr case
E  definedness poisoning          4 facts   independent, behind a flag
A  signedness from consuming ops  1 fact    independent
```

C first: highest value, lowest risk, no dependencies. B before D, because a
pointer-valued return that the callee never dereferences needs the global map
to have any layout at all.

---

## C — array detection via allocation size (9 facts)

**Problem.** `varying_len(int *arr, int n)` reads only `arr[n-1]`, so its merged
footprint is offsets 8 and 16 — non-contiguous, failing `uniform_layout`, so it
stays struct-modelled.

**Signal**, verified on both calls:

```
n = 5,  allocation 20 bytes,  access width 4   ->  5 x 4 == 20
n = 3,  allocation 12 bytes,  access width 4   ->  3 x 4 == 12
```

**Design.** A second discriminator in `deref.py`, tried when uniform tiling
fails: for each observed call, is there an integer argument `L` and an observed
access width `w` with `L * w == allocation_size_for_that_call`? The width must
be the same across calls; the length and size may vary together.

**This needs per-call evidence.** Today the allocation size is aggregated to a
minimum and the integer arguments to a list of sets, which loses the pairing —
for `varying_len` the minimum size is 12 while one call had `n = 5`, so an
aggregated check fails. The Tracer must record `(sizes_by_slot, int_args)` per
call.

Element count then comes from the *captured blob* (`len(blob) // w`), which is
already per-call, so sequences of differing length fall out naturally.

Heap only: it rests on the allocation record.

## B — global access map (9 facts)

**Problem.** `identity_ptr(int *p) { return p; }` never dereferences, and
`maybe(pair_t *p)` reads only `p->a`. The callee revealed nothing, but the
**caller** initialised the object right before the call.

**Design.** Record every memory access by address across the whole trace, not
per (function, argument). When a pointer argument has no local footprint,
consult the map at the pointer's value.

**The risk is temporal aliasing**: a stack address holds different objects at
different times. Mitigations, in order of how much they cost:

- consult the global map only when the per-function footprint is *empty*, so
  it never overrides directly observed evidence;
- bound the lookup by `Arena.size_of` where known, and by `DEREF_WINDOW`
  otherwise;
- heap addresses are safe by construction — the arena never reuses a freed
  block.

Stored per `(func_addr, raw_slot)`: a representative pointer value, so the map
can be queried at finalize time when the per-call values are gone.

## D — pointer-valued returns (3 facts)

**Problem.** Only arguments are followed, so Kvasir's `return[]` and
`size(return[])` have no counterpart.

**Design.** At EXIT, if raw slot 0 (the return) classifies as a pointer,
capture its pointee through the existing path and emit `return[..]` and its
fields. Mechanical; the capture and schema code is parameterised by slot index
already.

## E — definedness poisoning (4 facts)

**Problem.** Valgrind reports `nonsensical` for a read of uninitialised memory;
Unicorn zeroes fresh pages, so the tracer **fabricates** a value. The only place
the output states something untrue rather than merely incomplete.

**Design.** Fill freshly mapped stack pages and arena allocations with a
repeating pattern. When a captured pointee field equals the pattern, emit
`nonsensical` instead of a number.

Approximate by construction — a genuine value equal to the pattern is misread —
so it goes behind `--poison-uninitialized`, measurable on its own. A correct
implementation means shadow memory, which is out of scope.

## A — signedness from consuming operations (1 fact)

**Problem.** A high-bit `unsigned` reads back negative because the tracer
sign-extends everything 32-bit.

**Signal**, verified:

```
unsigned x >> 3   ->  shr      int x >> 3   ->  sar
unsigned x > 100  ->  seta     int x > 100  ->  setg
```

and in the failing case itself, the caller of `big_unsigned` emits
`shr $0x1c,%eax` on the returned value.

**Design.** Extend the existing caller-watch machinery (already used for void
detection) to record the mnemonic that consumes `rax`. `shr`/`seta`/`setae`/
`setb`/`setbe`/`movzx` imply unsigned; `sar`/`setg`/`setl`/`movsx` imply
signed. Skip sign-extension for a slot marked unsigned.

Not universal: a value never shifted, compared or widened leaves no trace, and
stays on the signed default.

---

## Acceptance

- All seven lower-tier goldens byte-identical; tiers 0-7 unchanged unless a
  flag is passed.
- `./test.sh` at 0 failures.
- Recall rises from 84% toward 99% of valid oracle facts; each mechanism
  measured independently so its contribution is attributable.
  **Met in form, not in degree: 84% -> 92%.** The 99% estimate priced B's nine
  facts as free, and they are not — see "B was measured and then restrained".
- New behaviour that could be wrong (E, and C's second discriminator) is
  flag-gated or conservative, per the project's standing preference for a
  stated limit over a wrong guess.
