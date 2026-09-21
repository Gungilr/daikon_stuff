# The tracer, in depth

What it is, how it is built, and — the part worth reading — the technique used
to solve each problem, because most of them were not solved the way the plan
said they would be.

---

## 1. What the tool does

It emulates a stripped x86-64 ELF binary and writes a Daikon `.dtrace` file, so
that Daikon can infer program invariants without any debug information.

```
binary ──► unicorn emulation ──► .dtrace ──► daikon ──► invariants
             (scripts/tracer)                 (java)
```

The reference point is **Kvasir**, Daikon's real C front-end, which runs the
binary natively under Valgrind and reads DWARF. Kvasir knows variable names,
types, struct layouts and array bounds. This tool knows none of that and has to
recover the same facts from machine state alone.

Run it:

```bash
./venv/bin/python scripts/unicorn_dwarf.py tests/test08.exe \
    -o out.dtrace --start-func main --tier 7 --infer-unobserved-fields
```

Run the whole corpus against both tools:

```bash
DAIKONDIR=$PWD/daikon ./test.sh --tier 7           # with Kvasir
DAIKONDIR=$PWD/daikon ./test.sh --tier 7 --no-kvasir
```

Outputs are named per tier (`invariants/test08.tracer.t7.txt`), so tiers never
overwrite each other.

---

## 2. Architecture

```
scripts/tracer/
  log.py        25   Logger                                     pure
  schema.py     53   tier-0 variable names, slot counts         pure
  memmap.py     77   address classification                     pure
  alloc.py     123   emulated heap                              pure
  writer.py    161   .dtrace serialization                      pure
  deref.py     175   struct/array layout recovery               pure
  infer.py     268   arity, widths, spills, void detection      pure
  elfload.py   245   ELF parsing, PLT resolution                pyelftools
  emulate.py  1288   Unicorn driver, hooks, orchestration       unicorn+capstone
  cli.py       159   argument parsing
scripts/unicorn_dwarf.py  16  compatibility shim
```

### The purity boundary is load-bearing

Seven of the nine modules import nothing third-party. That is not tidiness — it
is what makes the inference logic testable. `tests_py/test_infer_arity.py` feeds
synthetic `(mnemonic, reads, writes)` tuples and asserts the recovered arity,
with no emulator, no binary, and no 2.5-second startup. About two thirds of the
333 tests run that way.

`tests_py/test_purity.py` enforces it by importing each pure module in a
**subprocess** with a `sys.meta_path` hook that raises on unicorn, capstone and
pyelftools. A subprocess because an in-process check like
`"unicorn" not in sys.modules` passes vacuously the moment any other test
imports it. It also has a negative control asserting `emulate` and `elfload`
*do* fail under the block — otherwise a silently broken blocker would make every
purity test pass for the wrong reason.

One consequence to remember: `tracer/__init__.py` must stay free of re-exports.
Importing `tracer.writer` runs `__init__` first, so a single
`from .emulate import Tracer` there would drag unicorn into every "pure" import
and void the whole boundary.

---

## 3. The tier ladder

Every tier is opt-in via `--tier N` and cumulative. Lower tiers keep producing
**byte-identical** output, pinned by golden files in `tests_py/golden/`.

| tier | adds | test08 invariants |
|---|---|---|
| 0 | fixed 11-slot register/stack window | 177 |
| 1 | `subexit`, `EXIT0`, invocation nonce | 177 |
| 2 | argument detection (use-before-def) | 15 |
| 3 | return value, signed values, comparability | 8 |
| 4 | *skipped — measured no-op* | — |
| 5 | malloc/free model | 5 |
| 6 | dereference, struct fields | 42 |
| 7 | array bounds | 42 |
| 7 | with `--infer-unobserved-fields` | 50 |
| 8 | **global variables** | 50 (test08 has none) |
| 9 | floating-point arguments and returns | 50 (test08 has none) |

Phase 8 added five recovery mechanisms on top of tier 7 rather than a tier 8,
because each is independently gated or conservative rather than cumulative:
array detection from allocation size, signedness from consuming opcodes,
pointer-valued returns, a global access map (`--infer-from-caller`), and
definedness poisoning (`--poison-uninitialized`). Measured in
[EVALUATION.md](EVALUATION.md): **precision 65%, recall 92%, F1 76%**, up from
59/84/69, with eight of ten binaries at 100% recall.

(Kvasir reports 37 on the same binary. Counts measured after the 2026-09-17
review fixes, with leading whitespace stripped before filtering — Daikon's
carriage-return progress output can otherwise leave padding on an invariant
line and corrupt the count, which it did to mine for two phases.)

The shape of that column is the result. Precision climbs steeply through tiers
2–5 as junk variables are pruned; recall only moves at tier 6, when pointees
become visible. Tier 7 does not change test08 because it has no arrays — it is
`tests/test13.c` that exercises it.

**A count going down can mean the output got better.** Fixing the first-call
capture bug dropped tier 6 from 67 to 42, and the 25 that vanished were all
weaker or redundant variants. With complete data Daikon establishes the strong
`arg0[] == orig(arg0[])` and stops reporting the elementwise form alongside
companions like `arg0[] is the reverse of orig(arg0[])`. All three core
relations survived. More evidence refutes more hypotheses, and consolidates the
survivors.

### Why tier 4 was skipped

The plan called for covariance-based pointer classification. Before building it
I measured what the existing range-based classifier gets wrong: **7 of 7
pointers correct, 0 of 118 variables misclassified**, both before and after the
heap arena existed. It had no acceptance criterion that failed. Skipped, with
the evidence recorded so it is not reinstated on principle.

---

## 4. Problems and the techniques that solved them

This is the part that transfers. Each entry is a problem that was not obvious,
and how it was actually resolved.

### 4.1 The recurring bug class: consulting knowledge that does not exist yet

Four separate bugs were the same mistake. Learn this one and the rest follow.

The tracer learns facts *from execution*: arity comes from observing which
registers a function reads, types from observing values, layouts from observing
accesses. So at the moment a function is entered, **nothing is known about it
yet**. Any code that asks a question at entry time gets the answer "zero".

| bug | symptom |
|---|---|
| pointee capture called `arity()` | every function lost its **first** call's pointee; a function called once lost everything |
| allocation size stored last-write-wins | a parameter given a 20-byte then a 12-byte object was credited with fields existing in only one |
| null classified as scalar | one `NULL` argument demoted the slot permanently, killing pointee recovery for *every* call |
| `is_param` rationale | a comment justified behavior by a condition (the malloc stub) that tier 5 had removed two tiers earlier |

**The technique: capture broadly, emit narrowly.**

At capture time, record everything that *might* matter, keyed by something that
needs no inference — the raw slot index, classified against the live memory map.
At finalize time, when all evidence is in, decide what to emit. Concretely,
`_capture_pointees` grabs bytes behind every pointer-shaped slot with no regard
for arity; `_schema_for` later emits only the slots that turned out to be
arguments.

The same shape appears in the **deferred schema**: samples are buffered in
`Tracer.pending` and only converted to variables in `_finalize()`, because a
function's arity is not known until it has finished executing — and with
`--layouts N`, not until all N runs have.

### 4.2 Recovering arguments without debug info

**Problem:** a stripped binary does not say how many arguments a function takes.
Tier 0 captured a fixed window of 11 machine slots, 10 of which were leftovers,
and Daikon dutifully related them all to each other.

**Technique: use-before-def.** A register read before it is ever written must
have been set by the caller. Only the six SysV argument registers count, and
that restriction is what makes it sound — they are caller-saved, so unlike `rbx`
a callee never reads one merely to preserve it.

Two details that are the difference between working and silently returning
nothing:

- **Sub-register canonicalization.** Capstone reports the register the
  instruction *names*. At -O0 an `int` argument arrives in `rdi` and is read as
  `edi`; the sixth arrives in `r9` and is read as `r9d`. Matching on `rdi` finds
  nothing and reports arity 0 for every integer function — a failure that *looks
  like a precision win* because the output gets smaller and cleaner.
- **`call` clobbers caller-saved registers.** Without this, a caller reading
  `rdi` after a nested call looks like it received an argument.

**Technique: contiguity, not set membership.** Trailing dead arguments are
invisible, so arity is `highest index observed + 1`, not the count of indices
observed. `stack8` in `tests/test07.c` reads its 8th argument and never touches
its 7th (dead, and being a stack argument it is never spilled). A set rule gives
`{1..6, 8}` — a hole, and arity 7. The ABI allocates contiguously, so observing
the 8th proves the 7th exists.

### 4.3 Values that were simply wrong

**Problem:** the tracer reported `4294967295` where the truth was `-1`. An `int`
occupies the low 32 bits and writes to `eax` zero-extend, so `rax` holds
`0x00000000FFFFFFFF`. Daikon then infers `> 0` where the truth is `< 0` — not a
phrasing difference, a wrong answer.

It was **invisible in the corpus**: a scan of every baseline trace found zero
negative values, because every fixture used non-negative loop counters. It had
been latent since tier 0 and would have stayed latent.

**Technique: the width was already being observed and thrown away.** Tier 2's
canonicalization sees `edi` versus `rdi`; it just discarded the distinction.
Tier 3 records it (first read wins — at -O0 that is the prologue spill, which
names the parameter's true width) and sign-extends.

**Technique: write the counter-case into the corpus.** `big_unsigned` in
`tests/test12.c` returns a high-bit `unsigned`, where sign-extending is *wrong*.
`test_unsigned_is_knowingly_wrong` asserted the wrong answer deliberately, with
a docstring saying that if it ever began failing, signedness inference had
arrived and this paragraph should be rewritten. Phase 8 made it fail.

**Technique: the value carries no signedness, but the operations on it do.**
A compiler must pick an opcode, and the choice encodes the type:

```
unsigned x >> 3   ->  shr      int x >> 3   ->  sar
unsigned x > 100  ->  seta     int x > 100  ->  setg
unsigned widened  ->  movzx    int widened  ->  movsx
```

The caller-watch machinery already built for `--detect-void` walks forward from
each `call` looking for the instruction that consumes `rax`; it now also records
that instruction's mnemonic ([emulate.py:445](../scripts/tracer/emulate.py#L445)).
`big_unsigned`'s caller emits `shr $0x1c,%eax`, so the return is masked to its
observed width instead of sign-extended, and the values now match Kvasir
exactly. `negate` is consumed by signed opcodes and still reports -1..-5.

Not universal: a value never shifted, compared or widened leaves no trace and
keeps the signed default, which is the common case and the safer one.

### 4.4 Arguments are garbage at function exit

**Problem:** `skip_middle(a, b, c)` reported `arg0 == arg2`. gcc -O0 emits
`mov -0x4(%rbp),%edx`, reloading `a` into `edx`, so at `ret` the third argument
register holds the first argument.

No input disproves this — the clobber is deterministic — so it is permanent
noise, not the underscoped kind that more testing corrects.

**Technique: read the spill slot, not the register.** The -O0 prologue stores
each argument to a known frame offset; that slot still holds the parameter (and
reflects assignment to it, which the register would not).

**The subtlety:** at `ret` the epilogue has already executed `pop %rbp`, so
`rbp` points at the *caller's* frame and can no longer locate the slots. The
frame base is therefore computed at **entry** as `rsp - 8` — where the standard
prologue will put `rbp` — and carried on the call-stack frame. The slot memory
is still intact at exit; only the register pointing at it is gone.

### 4.5 Making Daikon and Kvasir comparable

Several format facts were established by reading Kvasir's actual output and
Daikon's parser, not the documentation. Getting any of them wrong corrupts
output silently.

- **`this_invocation_nonce` is a sample prefix, not a variable.** It appears in
  every sample and in *zero* declarations, and carries **no modbit** — two
  lines, not three. Daikon peeks exactly one line past the ppt name. Declaring
  it shifts every following name/value/modbit triple by one and desyncs the
  whole sample block.
- **`orig(v)` is derived by Daikon**, not emitted. Kvasir emits zero `orig(` and
  Daikon still reports orig() invariants.
- **`ppt-type subexit` versus `exit`** is tier 1's actual deliverable. Daikon
  only synthesizes a combined `:::EXIT` when exit sites are declared `subexit`.
  Declaring `exit` produces `:::EXIT1`, which cannot be matched against Kvasir's
  `:::EXIT` — blocking any scoring at exit points.
- **`array 1` means one dimension, not one element.** The element count lives in
  the data: `[ 0x1ffefffcb0 ]` versus `[ 1 2 3 4 5 ]`.
- **A pointee is a one-element sequence.** That is why Kvasir reports
  `p[].a elements < return` rather than `return == p->a + p->b`. Emitting flat
  scalars would produce invariant *forms* that no scoring alignment could ever
  match, so matching the representation is a precondition, not a style choice.

### 4.6 The oracle is not always right

**Problem found late:** Kvasir reported `return - orig(a) - 1 == 0` for a
function returning `2a + 1`. False on all six of its own samples, and
contradicting its other reported invariant.

**Technique: binary-search the cause with synthetic traces.** Hand-write a
minimal `.dtrace` where the answer is known, run Daikon, and add Kvasir's
declaration ingredients one at a time until the output flips.

```
without is_param:  2 * a - return + 1 == 0     correct
with is_param:     return - orig(a) - 1 == 0   false on the same data
```

`flags is_param` is the sole trigger, and it manifests only when the true linear
relation has a **non-unit coefficient**. It also *suppresses* correct
invariants: `trailing_dead`'s relation vanishes entirely.

We had copied the flag from Kvasir. Dropping it makes our output diverge from
the oracle and agree with reality. That is the right trade when the consumer is
a fuzzer — a fuzzer can disprove a bad invariant, but cannot recover one that
was never emitted. Cost: counts roughly doubled, because the flag was also
suppressing a large class of true-but-trivial `argN == orig(argN)` facts.

### 4.7 Following pointers

**Problem:** the biggest recall gap. Of Kvasir's 37 facts on `test08`, 35 need
dereference.

**Technique: attribute by value, not by register.** The obvious implementation —
watch accesses made through the argument register — recovers *nothing*, because
at -O0 the pointer is spilled and reloaded into a scratch register first:

```
mov  %rdi,-0x8(%rbp)      argument spilled
mov  -0x8(%rbp),%rax      reloaded into a DIFFERENT register
mov  (%rax),%edx          the dereference happens through rax
```

`rdi` is never dereferenced. Instead, compare each access's **effective
address** against the **value** each argument held: an access at `A` belongs to
argument `N` when `0 <= A - value(argN) < bound`. `UC_HOOK_MEM_READ` supplies
the address directly, so no operand decoding is needed — and this works
regardless of how many copies the compiler makes.

**Technique: hook writes too.** An out-parameter (`void fill(pair_t *p, int v)`)
is written and never read, so a read-only hook leaves it with no footprint and
recovers nothing at all. A written offset is field evidence exactly as a read
one is.

**Technique: use the allocator as a size oracle.** `heap_read` computes
`p->a * 2` and never touches the second field, so a pure footprint recovers one
field where Kvasir reports facts about two. But `malloc(8)` against a 4-byte
footprint leaves 4 bytes unaccounted for, and the tail can be *inferred*. This
is the larger of tier 5's two payoffs — `Arena.size_of` is not just a bound, it
is what makes unobserved fields recoverable at all. Behind
`--infer-unobserved-fields` because it is a heuristic (the tail could be one
wider member).

### 4.8 Modelling the heap

**Problem:** `malloc` is an unresolved import, so the call was skipped with the
return register forced to zero. Every heap pointer in the trace was null, the
object lived on the zero page, and the tracer asserted two invariants that were
true of the emulation and **false of the program**.

**Technique: PLT resolution survives stripping.** `strip --strip-all` removes
`.symtab` but cannot remove `.dynsym` or `.rela.plt` — the loader needs them.
Two steps, neither assuming entry ordering: `.rela.plt` gives GOT slot → symbol
name; each PLT entry is scanned for `ff 25` (`jmp *disp(%rip)`) and its target
computed as `next_addr + disp`, which is that GOT slot. Verified identical on
stripped and unstripped builds.

**Technique: let the oracle settle the design question.** Should the model
recycle freed blocks, as glibc does? Kvasir's own trace answers it: ten
malloc/free cycles of an 8-byte struct produced **ten distinct addresses**,
because Valgrind adds redzones and delays reuse. A recycling model would return
one address ten times and manufacture a constant-pointer invariant the oracle
never reports. Non-reuse is both simpler and closer to ground truth — worth
recording, because "be realistic, reuse memory" is the improvement someone will
later propose.

Interception happens at the **call site**, not the PLT stub, because
`--skip-unknown-calls` rewrites RIP past the call and the stub never executes.

### 4.9 Telling an array from a struct

**Problem:** `int p[2]` and `struct {int a, b;}` are genuinely
indistinguishable. Identical offsets, identical widths.

**The technique that did not work:** the addressing mode. The plan proposed
scaled-index (`(%rax,%rdx,4)`) for arrays versus constant displacement for
structs. Measured, gcc -O0 does neither — it computes `arr[i]` arithmetically
with `lea`/`add` and then dereferences plainly, so the instruction forms are
identical.

**The technique that did, found three phases later.** The addressing MODE is
identical; the *instruction identity* is not. `p->a; p->b` compiles to two
different instructions, each at its own constant displacement. `arr[i]` in a
loop is ONE instruction that walks many offsets. So record which program
counter touched which offset, and ask whether any single instruction touched
two or more:

```
test08  pair_t struct   2 instructions, 1 offset each   -> struct
test13  sum_array       1 instruction,  5 offsets       -> ARRAY
test13  two_fields      2 instructions, 1 offset each   -> struct
```

This is **positive evidence only** — silence means the program never iterated
the object, not that it is a struct — so it can promote a struct guess to an
array but never the reverse. It is the first change in three phases that cost
nothing: on Daikon's suite it emits 148 FEWER facts and matches 20 more
(precision 22% -> 24%), and the fixture corpus is bit-for-bit unchanged at
65/92/76.

**Why it matters more than the numbers suggest.** Before it, the default was a
coin flip whose correct side depended on the corpus: calling a uniformly tiled
pointee an array scores better on Daikon's tests (+2 matched) and destroys the
fixtures (155 matched -> 98), because `pair_t {int a; int b;}` and `int[2]` are
identical in extent, offsets and widths. Measuring both defaults proved neither
dominates. The fix was not a better guess — it was finding the evidence that
makes it not a guess.

**The technique that did:** a correlated length argument. An array parameter
conventionally travels with its length. When some integer argument equals the
computed element count on **every** observed call, the pointee is an array.

The failure mode is the reason to prefer it: no length argument means no array
claim, so a lone struct pointer stays a struct. `two_fields(p, 99)` in
`tests/test13.c` is the deliberate trap — an int argument that never equals the
count.

Payoff: `arg1 == size(arg0[])`, the buffer-length contract, recovered
automatically. It is the most security-relevant invariant the tool produces.

**The technique that came later:** `length * width == allocation size`. The
first discriminator still requires the footprint to *tile* — contiguous
same-width accesses covering the object. `varying_len(int *arr, int n)` reads
only `arr[n-1]`, so its merged footprint is offsets 8 and 16, which does not
tile, and it stayed struct-modelled. But a second signal holds exactly:

```
call 1:  n = 5,  malloc(20),  access width 4   ->  5 * 4 == 20
call 2:  n = 3,  malloc(12),  access width 4   ->  3 * 4 == 12
```

This needs **no footprint coverage at all**, which is what makes it the
stronger of the two. It is heap-only, because it rests on the allocation record.

**The trap in implementing it: aggregation destroyed the signal.** The
allocation size had been reduced to a minimum and the integer arguments to a
set, and the whole signal is in the *pairing* — for `varying_len` the minimum
size is 12 while one call had `n = 5`, so an aggregated check fails on data that
agrees perfectly per call. The fix was to keep `(sizes_by_slot, int_args)` per
call. Element count then comes from the per-call blob, so `[1 2 3 4 5]` and
`[10 20 30]` fall out of one program point naturally.

### 4.10 Memory the program never wrote

**Problem:** Valgrind tracks definedness bit by bit and prints `nonsensical`.
Unicorn zeroes fresh pages, so a read of uninitialized memory returns 0 and the
tracer reports it as an observation. `fill(pair_t *p, int v)` is called first
with an uninitialized local:

```
kvasir p[].a at ENTER:  nonsensical  [ 1 ]  [ 2 ]
ours:                   [ 0 ]        [ 1 ]  [ 2 ]
```

This was the one place the output stated something **untrue** rather than
merely incomplete. It also pollutes the value set: Kvasir infers
`p[].a one of {1,2}`; with a phantom 0 in the samples, we cannot.

**Technique: poison, then recognise the poison.** Fill fresh stack pages and
arena allocations with `0xAB`; a captured field still holding the pattern is
emitted as `nonsensical`. Approximate by construction — a genuine `0xABABABAB`
is misread — so it sits behind `--poison-uninitialized` and is measured on its
own. Exact definedness means shadow memory, i.e. reimplementing memcheck.

### 4.11 The callee did not touch it, but somebody did

**Problem:** `identity_ptr(int *p) { return p; }` never dereferences `p`, and
`maybe(pair_t *p)` reads only `p->a`. Footprints are keyed per (function,
argument), so both pointees are invisible — while Kvasir dereferences **by
type** and reports them from DWARF alone. That is the structural difference
between the two tools in one line: *Kvasir dereferences because the type says
pointer; we dereference because we observed an access.*

**Technique: record every access by address, trace-wide.** The caller
initialised the object right before the call, so the layout exists somewhere in
the trace even when the callee reveals nothing.

**And the technique's limit, which is the more useful half.** Measured, the
unbounded form is a bad trade:

```
                       tracer facts   matched   prec   recall   F1
default                         239       155    65%      92%   76%
--infer-from-caller             375       161    43%      95%   59%
```

The risk is **temporal aliasing**: a stack address holds different objects at
different times, and nothing observable says where an object the callee never
touched ends. On `identity_ptr`, whose argument is a stack `int`, the 64-byte
window swallowed neighbouring locals and invented three fields. So the default
consults the map only where an allocation size bounds it exactly, and the
speculative form is opt-in. Four points of recall are not worth twenty of
precision to a consumer that acts on these invariants — **invented structure is
worse than absent structure.**

---

## 5. Process techniques

### Falsifiable acceptance criteria

Each phase plan stated what *must* happen and what *must not*, as predictions
that could fail. Tier 2's said "recall must not move — if it does, tier 2 is
deleting real information rather than noise."

**It failed, and that was the phase's most valuable result.** Tiers 0–1 had
accidentally encoded `stack_read`'s true relation twice — once as a packed
64-bit word (`4294967297 * rax - 2 * stack0 + ... == 0`), once via a scratch
register — because the fixed window happened to overlap the caller's frame.
Tier 2 correctly pruned those non-argument slots and the semantic facts went
with them. Correct behavior, and a genuine dip in the recall curve that would
otherwise have looked like a regression to a future reader.

A criterion that cannot fail teaches nothing.

### Measure before planning

Every phase plan contained corrections to the master plan, found by measurement
before writing code. Several would have shipped bugs: the nonce format, the
`orig()` emission, the addressing-mode discriminator, the claim that dead
parameters are unrecoverable (false at -O0, where gcc spills every parameter).

### Golden files plus tier gating

`tests_py/golden/test08.tier{0,1,2,3,5,6}.dtrace` are byte-compared on every
change. This is what makes it safe to restructure the sample path repeatedly —
and it caught a real crash where a rename left a dangling reference in the
summary line, producing a *correct* dtrace and then exiting nonzero. Manual
runs with redirected stdout looked fine; only a test asserting
`returncode == 0` found it.

### 4.12 Finding globals without a symbol table

**Problem:** measured on Daikon's own test suite, **80.5% of everything Kvasir
says is about global variables**, and the tracer emitted none. That single gap
capped recall at 4% however well the rest worked.

**Technique: section headers outlive the symbol table.** `strip --strip-all`
removes `.symtab`, so the names are gone — but it does not touch section
headers, so `.data`, `.bss` and `.rodata` still declare exactly which address
ranges hold globals. That is the haystack. Three signals find the objects in it:

| signal | gives | limitation |
|---|---|---|
| `.symtab` objects | address **and size** | absent when stripped |
| RIP-relative operands | object starts | 64% of them; misses arrays only touched at an offset |
| observed accesses | what was read/written | says nothing about boundaries |

Size is the fact that matters and the one no dynamic signal supplies: **an
`int[18]` and eighteen adjacent `int`s produce identical access evidence.** So
the symbol table is used when present, exactly as function discovery already
uses it, with `--scan-prologues` forcing the stripped path for both.

**Technique: a guess must not change the noun.** An 8-byte global that nothing
read became `int[2]`, because the fallback width was 4 and 8/4 = 2. That
invents `size(g[]) == 2` and reports the halves of a `double` as integers. The
width now carries *whether it was observed*, and a guessed width can never
create an array — only confirm one.

**The bug that ate nine binaries:** declaring `g_0x404060[..]` with
`enclosing-var g_0x404060` while never declaring `g_0x404060` itself makes
Daikon reject **the entire trace**, not just that variable. The output looked
like a successful run producing 8 facts. The pointee path had always declared
the base; the globals path had to be taught the same rule.

### Audit the instrument through the thing it measured

Seven bugs have been found in `score_invariants.py`, every one of them making
the tracer look worse than it is. Three surfaced in one sitting, from a single
question asked of each mechanism that had just landed: **did the binary it
targets actually move?**

- `test13` was the target of the array work and moved 78% -> 90%, when the
  signal the mechanism rests on holds on every call and should have taken it
  to 100%. The residue was four `arr[n-1]` facts the tracer emitted correctly
  and the scorer failed to rename inside the bracket. It is 41/41 now.
- `test12` did not move at all, although `big_unsigned` was by then producing
  Kvasir's exact values. Its invariant carried a constant printed as
  `-2.14748e+09`, which the parser read as a variable named `e`.

Neither was visible in the aggregate — both were obvious in the per-binary
column. **An aggregate metric hides instrument bugs; a per-unit one exposes
them**, which is a reason to keep the per-binary table even once the headline
number is what gets quoted.

The third bug was found by pulling on the second: with the constant finally
parsed, Kvasir's invariant turned out to be false on its own samples, and the
scorer had been silently mis-collapsing `- -2147483648` into `- 2147483648` —
turning the oracle's false fact into our true one and charging us for the
difference. **A parser bug that produces a plausible answer is the worst kind**,
because nothing downstream looks wrong.

### Probe with shapes the corpus omits

The 2026-09-17 review found two bugs in minutes by writing small C programs
using idioms no fixture contained — a NULL argument, an out-parameter. Reading
the code found nothing. **The corpus is the blind spot**: ten tiny files,
mostly written to exercise the heuristic under test, all -O0.

### Then borrow somebody else's corpus

Writing probe programs still means imagining what you left out. Daikon ships 46
C programs in `daikon/tests/kvasir-tests/` to test *its* front-end, and running
29 of them took an afternoon and produced more than every probe combined: a
crash (a struct passed by value, which no fixture contains), a scorer bug
(`static` functions, which no fixture contains), and the discovery that **80% of
a real Kvasir oracle is global variables** — a capability this tool does not
have and a claim in its own docs said it did not need.

The score fell from 65/92/76 to 13/4/6. Both numbers are correct; the first was
never a claim about stripped binaries in general. Full decomposition in
[EVALUATION-KVASIR-SUITE.md](EVALUATION-KVASIR-SUITE.md).

---

## 6. Environment notes that cost time

- Everything runs under **WSL**; the Windows-side toolchain builds PE, not ELF.
- `wsl.exe -- bash -lc '...'` silently expands `$VAR` and `$(cmd)` to **empty**.
  Pipe the script through **stdin** instead (`wsl.exe -- bash -s <<'EOF'`),
  which is not mangled.
- `emulate.py` is CRLF while the rest of the tree is LF. Multi-line patches
  match nothing until line endings are normalized.
- Byte escapes do not survive a generated-code pipeline: `\xff` arrived as a raw
  non-ASCII byte and `\x00` as a literal NUL that made the module unparseable.
  Write them arithmetically — `bytes((0xFF, 0x25))`, `bytes(n)`.
- Kvasir needs **DWARF 3** (`-gdwarf-3`). gcc 13 defaults to DWARF 5 and Kvasir
  segfaults inside Valgrind.
- Daikon always writes a serialized `.inv.gz` into the current directory unless
  `-o` redirects it, and its progress output uses carriage returns that can
  leave padding on an invariant line — which silently corrupted my own
  invariant counts for two phases.

---

## 7. Known limits

Deliberate, and stated rather than hidden:

- **A global's TYPE is not recovered.** Tier 8 finds globals and reads their
  bytes, but a `double[5]` is reported as five 8-byte integers — nothing
  distinguishes it from a `long[5]` without DWARF. Struct-shaped globals get
  `.offK` fields rather than member names, and a `char*` global is a pointer
  where Kvasir prints the string.
- **The order of a mixed int/float parameter list is not recoverable.** SysV
  numbers integer and SSE arguments independently and the machine code does not
  record how they interleaved, so tier 9 recovers both values of
  `f(double a, int b)` and assigns them to each other's names. Integer-first is
  a convention, not a recovery — which is why tier 9 is opt-in and costs 12
  facts elsewhere to gain 9 on `FloatTest`.
- **Signedness is observable only through a consuming opcode** — a value never
  shifted, compared or widened keeps the signed default and a high-bit
  `unsigned` reads back negative. (This entry previously said signedness was
  not observable at all; phase 8 disproved that.)
- **A fixed-size array without a length parameter** stays struct-modelled.
- **A non-contiguous footprint needs an allocation size.** `varying_len` reads
  only `arr[n-1]`, and is recovered because `n * 4` equals the malloc size on
  every call — `tests/test13.c` now scores 41/41 against the oracle. The same
  function over a *stack* array stays struct-modelled, because nothing bounds
  the object.
- **A pointee the callee never touches is not recovered by default.** The
  caller's accesses can supply the layout (`--infer-from-caller`), but nothing
  observable bounds a stack object, so the flag costs 22 points of precision
  for 3 of recall and stays off.
- **Uninitialized memory reads as a value unless `--poison-uninitialized`**,
  and even then a genuine value equal to the poison byte is misread. Exact
  definedness means shadow memory.
- **Dead trailing arguments are invisible at -O1+**; the corpus is -O0, which
  flatters the heuristic.
- **One level of dereference** — `char **` recovers the pointers, not their
  targets.
- ~~**No floats or SSE** at any tier.~~ **Fixed at tier 9.** Floating-point
  arguments arrive in `xmm0`-`xmm7`, which `REG_ARG_ORDER` does not list, so a
  function taking two doubles used to be seen as **nullary** rather than
  mis-typed — 8 functions out of 8 on Daikon's FloatTest.
- **A struct passed BY VALUE breaks arity in both directions.** The callee
  reads it a word at a time, so one 252-byte parameter is reported as eighteen
  arguments; a by-value struct the callee never reads is reported as zero. A
  struct *returned* by value (`rax:rdx`) has the same problem. Measured at 6
  wrong out of 6 on Daikon's Kvasir suite.
- ~~**Global variables are not emitted at all.**~~ **Fixed at tier 8**, which
  was worth 4.6x the matched facts on Daikon's own suite. They are 80% of what
  Kvasir reports there.
- **32-bit is gated off** above tier 1 and has never been executed.

Open work is tracked in [plans/review-2026-09-17.md](plans/review-2026-09-17.md):
no program-input mechanism, ~11s per iteration, modbits hardcoded to 1,
indirect calls named by call site. (The P/R/F1 scorer listed there is now
built — `scripts/score_invariants.py`, with results in
[EVALUATION.md](EVALUATION.md).)
