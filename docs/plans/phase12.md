# Phase 12 — program input: argv, `atoi`, and many runs

Status: **complete**. Prerequisite: the 2026-09-20 large-program run, which
showed that four of six programs barely executed for want of input.

## Outcome

`tcas`, driven with the suite's own 501 input vectors and scored against Kvasir
over the same 501:

```
precision 94%   recall 90%   F1 92%     (2374 of 2625 oracle facts)
```

**The best result the project has produced, on a program nobody here wrote.**
For comparison: 65/92/76 on the ten fixtures written alongside the tool, and
24/17/20 across the 29-program suite.

The acceptance criterion passed exactly as written - on a single vector, our
sample count matches Kvasir's at **17 of 17 program points**. That check failed
for all six large programs before this phase.

### An unplanned result: we are 30x faster than Kvasir at multi-run

```
501 runs, ours    11s
501 runs, kvasir  329s
```

Kvasir pays Valgrind process startup 501 times; we re-enter one emulator. For a
fuzzing loop - which is nothing but "run it again with different input" - that
ratio matters more than any single-run comparison, and it is the first measured
advantage the emulator approach has over the reference tool.

Daikon then takes 12s on either side, so the whole loop is ~25s for 501 inputs.

### `exit` earned its place immediately

Neither side records `main:::EXIT` on `tcas`, because `main` calls `exit()`
rather than returning. Without the model, an unmodelled call returns 0 and
execution continues, so we would have produced a `main:::EXIT` sample from code
the real program never runs - and it would have looked like extra coverage
rather than fiction.

### The golden files caught me breaking the project's own rule

Setting up argv unconditionally moved **15 golden files**: it changes `rsi` at
`main:::ENTER` and maps a region the pointer classifier can see. The standing
rule is that every capability is opt-in and the default path is byte-identical.
Fixed by keeping the old stub exactly when no vector is supplied, which is also
the correct semantics.

### Scorer limitation #9, found here and not fixed

`initialize()` scores 11% recall while every other program point is 91-97%.
Both tools report the same fact - that all globals are zero on entry - but
anchor the equality on different members:

```
ours:    g_0x404040 == g_0x404044,  g_0x404040 == g_0x404048,  ...
kvasir:  ::Cur_Vertical_Sep == ::Positive_RA_Alt_Thresh[...],  ...
```

Daikon picks an arbitrary representative of an equality class and reports the
other members relative to it. Two front ends with different orderings produce
**disjoint fact sets that mean the same thing**. Our canonicalization handles
two-variable symmetry but not equality-class re-anchoring.

Measured: **80 of the 251 missed facts (31%) are pure variable equalities.**
Fixing it would take recall from 90% to about 93% on `tcas`, and it would raise
every number previously reported, all of which are therefore floors. The fix is
to compare equality *partitions* rather than pairs - union-find over the
`X == Y` facts at each program point - which is the "invariant equivalence
wants a decision procedure, not string matching" point from
[../FORMAL-METHODS.md](../FORMAL-METHODS.md) arriving in practice.

This is the gate on everything downstream. It is not only the fuzzing
prerequisite - it is the prerequisite for **any honest evaluation beyond the 29
no-input programs**, because a comparison where Kvasir saw 756 calls and we saw
44 measures the missing input, not the tracer.

## Why `tcas` is the target

Measured across the blocked programs, the libc surface is far smaller than
"model libc" suggests:

```
tcas           atoi
replace        fgets
tot_info       fgets scanf sscanf
print_tokens   fgets fopen open read
wordplay       fgets fopen gets read
space          atoi fgets fopen getc open
```

`tcas` needs **one** function. It is also a Siemens benchmark - a standard
program in testing research, written by other people in the 1990s - 173 lines,
no stdin, no files, twelve integer arguments.

And it exercises three things at once: argv, the `atoi` stub, and **tier 8**,
since it stores every argument into a file-scope global
(`Cur_Vertical_Sep = atoi(argv[1])`, and 12 more).

## The finding that shapes the design

```
$ wc -l tcas/tests.sh
501
```

**The oracle is merged from 501 executions.** `tcas.invs.goal` is not one run;
it is the invariants that survive 501 different input vectors. So argv support
that handles a single vector cannot reproduce it, cannot be scored against it,
and is not the fuzzing interface either.

Multi-run is therefore in scope from the start, not a follow-up.

Fortunately the loop exists. `--layouts N` already re-runs emulation N times
into one trace, shifting the stack base each time; `_finalize` is deliberately
deferred until every run has contributed. Varying argv is the same loop with a
second thing varying.

---

## A. argv

`_setup_memory` currently fakes it:

```python
self.mu.reg_write(UC_X86_REG_RDI, 1)                    # argc = 1
self.mu.reg_write(UC_X86_REG_RSI, stack_top - 0x100)    # argv = never populated
```

So `tcas` reads `argc < 13`, prints its usage text and calls `exit(1)` - exactly
the observed behaviour.

Replacing a stub, not adding a subsystem:

1. Write each argument as a NUL-terminated string into a dedicated page (not
   the stack, so `--layouts` relocation cannot land on it).
2. Build the pointer array, NULL-terminated, `argv[0]` = the binary's path.
3. `rdi` = argc, `rsi` = the array address.

## B. `atoi`, and the interception table it joins

Tier 5 already resolves PLT stubs and implements `malloc`/`calloc`/`realloc`/
`free` in Python against an emulated arena, dispatched at
[emulate.py:1370](../../scripts/tracer/emulate.py#L1370):

```python
if target is not None and self._alloc_enabled() and target in self.alloc_stubs:
    self._handle_allocator(...)
```

`atoi` joins that table. Read the C string at `rdi`, parse a leading integer,
return it in `rax`. A `read_cstring` helper is the only new primitive, and
`fgets` will want it too.

**`exit` should be modelled at the same time.** Today an unmodelled call
returns 0 and execution continues - so an input vector that reaches `tcas`'s
error path would carry on through code the real program never runs, and every
sample after that point is fiction. `exit` must stop the run cleanly. This
matters more under fuzzing than now, because a mutator will hit error paths
constantly.

## C. Many input vectors, one trace

```
--argv "958 1 1 2597 574 4253 0 399 400 0 0 1"     one vector
--argv-file FILE                                   one vector per line
```

`--argv-file` makes the run count `len(vectors)`, generalising the `--layouts`
loop. The stack base should keep shifting per run as it does now: that is free
and it already earns its keep by breaking invariants that only held for one
fixed memory layout.

Interaction to settle explicitly rather than discover: with both `--argv-file`
and `--layouts N`, do we run `vectors x N` or `max`? Proposed: **vectors x N**,
defaulting to N=1, because the two vary independent things and multiplying is
the honest reading of both flags.

---

## Risks

1. **Trace size and Daikon time.** 501 runs multiplies samples by 501. `tcas`
   is small - 12 globals, ~9 functions - so this should be minutes, not the
   841s `bc` took. But it is the first time phase 11's unresolved
   variables-per-ppt problem meets a realistic sample count, and if it bites
   here it will bite the fuzzer harder.
2. **`exit` on the error path.** See B. Without it, fuzzed inputs produce
   fictional samples, and the failure is silent.
3. **`--layouts` and `--argv-file` together** could quietly become a 501xN
   explosion. The log must state the run count up front.
4. **Scoring against the checked-in `.invs.goal` is not valid** - it was
   produced with the suite's own Daikon configuration. Run Kvasir ourselves
   over the same 501 vectors and score against that, as with the other 29.

## Acceptance

- **The comparability check passes for `tcas`**: our sample count per program
  point equals Kvasir's on the same input vector. That check currently fails
  for all six large programs, and it is the one that proves the input mechanism
  works rather than merely runs.
- `tcas` scores against a Kvasir run over the same vectors. No target number is
  set: this is the first honest measurement on a program nobody here wrote, and
  predicting it would be inventing a result.
- 29-program suite unchanged at **24/17/20, 822 matched**; fixture corpus
  unchanged at **65/92/76**. Both must be bit-identical when no argv flag is
  passed.
- All existing tests pass; goldens unmoved.

## Explicitly not in this phase

- **`fgets` and file input.** One function unlocks `replace`; `fopen`+`read`
  add three more. Same pattern, next phase, once argv has proved the
  interception path.
- **Mutation.** This phase makes a program runnable with chosen inputs. Choosing
  them *adversarially* is the fuzzer, and it needs this first.
- **Direct-call harnessing.** An emulator can jump straight into any function
  with fabricated arguments, skipping libc entirely - cheap and uniquely
  available to us. Deferred deliberately: arguments invented from nothing
  describe states the program may never reach, and the invariants that matter
  most are the preconditions that only exist in reachable ones. The sound
  version is to perturb *observed* values, which needs observation first.
