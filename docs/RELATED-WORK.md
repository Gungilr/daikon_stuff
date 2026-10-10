# Related work, and the methods it suggests

How prior research approached each problem this project still has open, what
of it transfers to a dynamic front end for stripped binaries, what we turned out
to have rediscovered, and the methods we propose where nothing fits as is.

Written after phase 12, before phase 13 was built. Checking the literature
against our own artefacts changed several conclusions, so section 1 comes first:
seven measurements made while doing this review. Every corpus number here can be
reproduced with the commands in [Appendix A](#appendix-a-reproducing-the-measurements).
Citations use short names; full entries and links are in the
[Bibliography](#bibliography).

**What decides whether a technique transfers.** We are dynamic only: an emulator
runs the binary, with no source. Inputs are stripped. Output is Daikon's trace
format. Scoring is against Kvasir, a front end that reads DWARF. And the
eventual consumer is a fuzzer, which can falsify a wrong invariant but cannot
recover one never emitted.

---

## 1. Seven measurements that changed the recommendations

Made on the Kvasir-suite artefacts saved in phase 11: the 14 programs for which
both Daikon reports, Kvasir's declarations and the `-g` binary were all kept.
Totals on that subset are 724 matched facts, 4,297 oracle facts and 2,679
emitted, so they differ from the 29-program figures in the README.

### 1a. Kvasir's output is DynComp-filtered and ours is not, yet that costs us almost nothing

The Daikon manual says Kvasir runs DynComp by default:

> "By default, Kvasir runs with DynComp to generate a .decls file with
> comparability information along with the usual value trace in the .dtrace
> file." (daikon/doc/daikon.texinfo:4845)

and `test.sh` passes those declarations to Daikon (test.sh:221-222). Daikon only
relates two scalars whose comparability numbers match
(`VarComparabilityImplicit.comparable`). So any fact of ours over two scalars
that DynComp put in different classes is one the oracle cannot produce, and an
emulator-side DynComp would remove it. How many are there?

| our unmatched facts | count |
|---|---|
| unary, where comparability does not apply | 982 |
| involve a sequence or a `size()` | 792 |
| names that could not be resolved | 120 |
| scalar pairs inside one DynComp class | 5 |
| **scalar pairs DynComp kept apart: Kvasir could never print them** | **56** |
| total | 1,955 |

```
precision now                               27.0%
... with every cross-class fact removed     27.6%
... and every unresolved one too (bound)    28.9%
```

52 of the 56 come from one program, `local-ptr`. The classifier labels **0** of
the 724 matched facts cross-class, which is the check that it reads the classes
correctly. Its first version failed that check, labelling 41 facts Kvasir had
printed as impossible, for the reason in the next paragraph.

**Why sequences never block a pairing.** Kvasir writes an array's comparability
as a bare number, `comparability 24`, with no index part. Daikon parses that as
a dimensionless comparability, and `elementType()` of a dimensionless
comparability is `unknown`, comparable to everything
(daikon/java/daikon/VarComparabilityImplicit.java:96-138). So Kvasir prints
`::globalInt in ::multiDimensional[]` even though the two have different numbers.

**Conclusion.** DynComp-style comparability is a *runtime* lever against this
oracle, not a precision lever. Its runtime value is still unknown; §3.6 gives a
cheap way to bound it before building anything.

### 1b. The four "forced but wrong" shapes have three causes, not one

The first version of phase 13, and FORMAL-METHODS.md, attributed all four to
bulk copies. Reading the machine code says otherwise:

| global | truth | forced | what the machine code does | cause |
|---|---|---|---|---|
| `globalFoo`, 256 B | struct | array | 32 separate 8-byte loads, one offset each, stored straight into the outgoing argument block of the by-value call `baz(f)` | copy hides the fields, and rule (ii) |
| `globalStruct`, 24 B | struct | array | stores 8 bytes at 0, 1 byte at 8, an SSE double at 16; then loads 8 bytes at 0, 8 and 16 | copy hides the fields, and rule (ii) |
| `globalBoo`, 58 KB | struct | array | six 4-byte stores of constants; the whole object is copied by `memcpy@plt`, which the emulator skips | rule (ii) |
| `population`, 600 B | array of five 120-byte structs | struct | mixed widths inside element 0; accesses at 272, 360 and 512 repeat element-0 fields modulo 120 | missing hypothesis (iii) |

`globalStruct`, verbatim:

```
mov    QWORD PTR [rip+0x2eb5],0x5     # <globalStruct>        8-byte store
mov    BYTE PTR  [rip+0x2eb6],0x62    # <globalStruct+0x8>    1-byte store
movsd  QWORD PTR [rip+0x2eae],xmm0    # <globalStruct+0x10>   SSE double
mov    rax,QWORD PTR [rip+0x2e8c]     # <globalStruct>        8-byte loads,
mov    rdx,QWORD PTR [rip+0x2e8d]     # <globalStruct+0x8>    one per eightbyte
mov    rax,QWORD PTR [rip+0x2e87]     # <globalStruct+0x10>
```

Three defects explain the table:

- **(i) The evidence store keeps only the widest access per address**
  ([globalvars.py:203](../scripts/tracer/globalvars.py#L203), and
  `fields_within` at :227). The 8-byte load at `globalStruct+8` erases the
  1-byte store under it, and the recorded evidence becomes `widths=[8]`.
- **(ii) The enumeration behind phase 13's table admits "struct" only when
  widths differ.** A struct whose touched members share a width can never
  survive, which forced `globalBoo` to "array" with no copy involved at all.
- **(iii) It has no array-of-struct hypothesis.** For `population`, the only
  layouts consistent with every observed access are period 120 and the whole
  600-byte object, and accesses touch four of the five 120-byte elements.

Phase 13 also explained `population`'s mixed widths as "an array cleared or
copied bytewise". It is not. The 2-byte accesses are the tails of inlined
string-literal copies into `char[]` members:

```
mov    DWORD PTR [rax],0x6b636952     # "Rick"     at population+0x4
mov    WORD PTR  [rax+0x4],0x79       # "y\0"      the 2-byte "field" at +0x8
movabs rbx,0x3837363534333231         # "12345678"
mov    QWORD PTR [rax],rbx            #            at population+0x68
mov    WORD PTR  [rax+0x8],0x39       # "9\0"      the 2-byte "field" at +0x70
```

So stores of constants are not always type evidence either: an inlined copy of
a short literal is a run of immediate stores whose widths follow the literal.
Method M1 (§3.1) handles this.

### 1c. Phase 13's mechanism A would not catch these copies

Mechanism A flags one instruction that touches many offsets. At `-O0` these
struct copies are unrolled: every instruction touches exactly one offset. No
stride or loop exists. Only dataflow can show that the loaded values are moved
and never used.

### 1d. A by-value struct argument has an exact call-site signature

For `baz(f)`, where `f` is the 256-byte struct:

```
sub    rsp,0x100                      # exactly the struct's size
mov    rax,rsp
mov    rcx,QWORD PTR [rip+0x2d7f]     # <globalFoo>
mov    rbx,QWORD PTR [rip+0x2d80]     # <globalFoo+0x8>
mov    QWORD PTR [rax],rcx
mov    QWORD PTR [rax+0x8],rbx
...                                   # 32 loads, 32 stores in all
call   401136 <baz>
```

### 1e. At -O0, argument registers are first read in declaration order

`initBasicTypesStruct(double a, int b, char c, float d, int *bp, unsigned long long e, char *cp, short f)`:

```
movsd  QWORD PTR [rbp-0x28],xmm0      # a
mov    DWORD PTR [rbp-0x2c],edi       # b
mov    eax,esi                        # c   (narrow types go through eax)
movss  DWORD PTR [rbp-0x34],xmm1      # d
mov    QWORD PTR [rbp-0x40],rdx       # bp
mov    QWORD PTR [rbp-0x48],rcx       # e
mov    QWORD PTR [rbp-0x50],r8        # cp
mov    edx,r9d                        # f
```

The first reads run xmm0, rdi, rsi, xmm1, rdx, rcx, r8, r9: the declaration
order. The order of the *spills* does not, because `c` and `f` are stored later,
and the frame offsets do not either, because gcc packs small types. This is the
only distinct mixed int/float signature in the corpus, so it is a hypothesis,
not a result.

It matters today because the tracer numbers SSE arguments after all integer
ones ([emulate.py:1625](../scripts/tracer/emulate.py#L1625)) while the scorer
maps argument *i* to DWARF parameter *i*
([score_invariants.py:158-168](../scripts/score_invariants.py#L158-L168)), so
every mixed signature is misaligned when scored.

### 1f. Skipped library calls change program state in 9 of 29 programs

An unmodelled call returns 0 and does nothing else. These five state-changing
functions are called in nine programs:

| function | programs |
|---|---|
| memset | PointerTest, TrivialTest, crazy-test-1, md5 |
| memcpy | MultiDimArrayTest, md5 |
| strdup | ArrayTest, CoercePointerTest, SimpleDisambigStructTest |
| strlen | md5, string-arrays |
| toupper | md5, string-arrays |

In `MultiDimArrayTest` the skipped `memcpy` is a 58,408-byte copy of
`globalBoo`; in `ArrayTest` a skipped `strdup` stores NULL where the program
stored a string. The 198-of-198 fidelity result compares sample *counts*, not
values, so it cannot see this, and VERIFICATION.md already says equal counts are
not equal contents. The README's "the tracer sees every byte the reference tool
sees" is overstated for these nine programs. Whether each call executes in the
traced runs is for the value check of §3.7 to confirm.

### 1g. Smaller facts

- Kvasir's default traversal depths are `--nesting-depth` 2 and
  `--struct-depth` 4 (daikon.texinfo:4561-4577).
- Kvasir flattens statically sized inner arrays into separate variables once
  Daikon's single level of sequence is used up (daikon.texinfo:4538-4545). That
  is the naming any multi-dimensional output of ours has to follow.
- TrivialTest and crazy-test-1 contain the same `initBasicTypesStruct`, so
  corpus totals count that function twice.

---

## 2. The thread through every problem: we record where accesses go, not where values come from

Every dynamic system that recovered program structure tracks the *provenance of
values*:

- **Howard** recovers structure "dynamically by tracking the way in which new
  pointers are derived from existing ones, and observing how the program
  dereferences them", from root pointers for "statically allocated memory
  (globals and static variables in C functions), heap and stack". It keeps a
  base-pointer tag for each register and each memory word [Howard].
- **REWARDS** tags each accessed location with a timestamped type, propagates
  it along the runtime dataflow, and resolves earlier variables backwards from
  type sinks [REWARDS].
- **DynComp** gives values tags and merges them when values interact; its C
  version ran on compiled x86 binaries [DynComp].
- **TIE** generates type constraints along dataflow, statically or over a
  trace [TIE].

Our tracer records *footprints*: which address, how wide, which program counter.
Four of the open problems are provenance questions in disguise:

| question | decides |
|---|---|
| was this loaded value ever interpreted, or only moved? | shape (§3.1), by-value arguments (§3.4) |
| was this access's base register loaded from field k of object O? | pointer depth (§3.3) |
| did a value from O+k reach `addsd`, `strlen`, a `%s`, or `sar`? | the residue (§3.5) |
| did two values interact? | comparability and runtime (§3.6) |

### Method P: a provenance shadow

In the instruction hook we already run with capstone operand detail, keep for
each register, and for each memory word written from a tracked register, a small
set of *origins* `(object, offset, width)` and a *consumed* flag.

| instruction | shadow update |
|---|---|
| load `r <- [a]` | `tag(r)` = the origin of `a`: the tracked object containing it, or the shadow of the word stored there |
| register move `r1 <- r2` | `tag(r1) = tag(r2)` |
| store `[a] <- r`, value never consumed | a **transport** edge from `tag(r)` to `a` |
| store `[a] <- imm` | **initialise** evidence at `a`; consecutive immediate stores spelling at least two printable bytes and then a NUL are a **literal** copy |
| any other instruction reading `r` | **consume** `tag(r)`, classed by opcode: integer arithmetic, signed or unsigned compare, arithmetic or logical shift, sign or zero extension, SSE single or double, address base or index, call argument k |
| memory operand `[b + ...]` | consume `tag(b)` as an address base: the pointer evidence of §3.3 |
| `lea r <- [b + ...]` | `r` is a pointer derived from `tag(b)`, as in Howard |
| `rep movs`, modelled `memcpy` | transport for the whole range |
| `call` to an unmodelled function | clear caller-saved registers |

Per-instruction aggregation keeps it sound across runs: an instruction counts
as transport only if *none* of its dynamic instances was consumed.

**Precedent and cost.** Shadow state is old: Memcheck shadows every bit for
definedness [Memcheck], and DynComp shadows values in the same framework
[DynComp]. What is ours is using it to separate type evidence from data
movement. The cost is a few dictionary operations per register operand in a hook
that already decodes every instruction. Flag-gated, and measured before
anything depends on it.

---

## 3. Problem by problem

Each part gives what prior work did, what transfers under our constraints, the
method, and a prediction that can fail.

### 3.1 Shape: struct, array, scalar, array of structs

The measured cause of 64% of our false positives is the wrong noun: right bytes
described as fields instead of elements, or the reverse (FORMAL-METHODS.md §2a).

**Prior work.**

- **Howard** names the problem exactly: programs "often use functions like
  memset and memcpy to initialize and copy data structures. Such functions
  access all bytes in a structure sequentially, typically with a stride of one
  word." It rejects blacklisting them, because blacklisting "can only cope with
  known functions, but not with similar ones that are part of the application
  itself", and instead "uses a heuristic that selects the less common layout."
  Arrays come from loops over a common base [Howard].
- **TIE** derives constraints from instruction semantics and reports an upper
  and a lower bound per type rather than one guess [TIE].
- **Laika** classifies memory words as pointers, zeros, strings or data, and
  finds repeated object layouts by Bayesian unsupervised learning [Laika].
- **DSIbin** generates speculative nested-struct hypotheses and keeps those an
  evidence-based analysis validates [DSIbin].
- **OSPREY** encodes weak hints as probabilistic constraints and reports
  posterior probabilities [OSPREY]. **Retypd** and **BinSub** solve subtyping
  constraints statically, BinSub 63 times faster at similar precision
  [Retypd, BinSub]. **TRex** argues for types that capture behaviour rather than
  reconstruct the lost source types [TRex].
- Learned systems: **XTRIDE** fully matches 74.2% of struct layouts without
  test-set adaptation, and states that "predictions cannot exceed the closed
  vocabulary" [XTRIDE]. A 2026 survey finds that "accuracy for fine-grained
  struct member reconstruction remains a significant bottleneck" [Survey2026].
- **Version spaces.** Candidate elimination keeps the set of hypotheses
  consistent with the examples. It finds the target only if the hypothesis
  language contains it and every elimination is consistent with the data
  [Mitchell].

**What transfers.** Howard's diagnosis, not its mechanism: our copies are
inlined and unrolled (§1c), so there is no stride or loop to detect. Defects (ii)
and (iii) of §1b are precisely the two ways candidate elimination fails: an
unsound elimination and a missing hypothesis. And one more consequence of the
version-space view: a struct of same-width members and an array are
*observationally equivalent* under footprint evidence. No layout observation
eliminates "struct". Only access patterns and repetition can argue for an array,
and only as preference.

**M1, evidence typing.** Combines Howard's problem statement, DynComp's split
between dataflow and interaction, and the principle shared by TIE and REWARDS
that types come from operations, not from movement. Record every access as
`(pc, offset, width, kind)` and never as a widest-access map. The kinds come
from method P:

| kind | votes on |
|---|---|
| consume | width, type, and existence of a member |
| initialise (scalar immediate) | width and existence of a member |
| literal (at least two printable bytes, then NUL) | a `char[]` of at least that length; not width |
| transport | extent only |

Without method P, the multiset store alone already fixes defect (i): the 1-byte
store at `globalStruct+8` survives beside the 8-byte load.

**M2, periodicity.** From Laika's repeated layouts and Howard's arrays of
structs. For each period p dividing the extent, fold the consume and initialise
accesses modulo p. Reject p if an access straddles a period boundary or two
folded accesses overlap without coinciding. Literal runs fold as byte ranges and
never conflict with each other. Take the smallest consistent p below the extent
with at least two periods touched. On `population` this yields p = 120, five
elements, four touched. It is corroborating evidence, not proof, and is labelled
so: two genuinely different fields can line up by chance.

**M3, sound elimination only.** Every rule that removes a hypothesis needs a
written semantic justification and a test.

- An access that straddles a candidate element boundary removes array-of-w:
  one scalar access never spans two elements.
- An extent above 8 bytes removes scalar.
- A consume or scalar-initialise access of a width other than w removes
  array-of-w, under one premise: a program accesses a scalar at its declared
  width. Every type sink relies on the same premise. Copies and literal stores
  break it, which is why M1 gives them kinds of their own.
- Uniform widths remove nothing. A struct of same-width members exists, so they
  are a preference at most.

**M4, generative soundness check.** From Csmith's random C programs [Csmith] and
QuickCheck's property-based testing [QuickCheck]. Generate random globals,
structs, arrays and arrays of structs, with random access patterns: field reads,
indexed loops, by-value passing, literal assignment, memset and memcpy. Compile
at `-O0`, trace, and assert that the DWARF truth is *never eliminated*.
Minimise any failing program. This replaces a 72-object calibration set with an
unlimited supply of labelled cases. DWARF is read only by the test, as in the
scorer.

Phase 13's B (keep and report the hypothesis set) and C (emit both shapes for
globals, whose names do not collide) stay as planned.

**Prediction.** Forced-but-wrong goes from 4 to 0:

| global | after M1-M3 |
|---|---|
| globalFoo | forced struct: the 4-byte and SSE accesses the copy hid make the widths heterogeneous, with or without the copy's own loads |
| globalStruct | forced struct: 8-byte, 1-byte and SSE accesses |
| globalBoo | ambiguous; Howard's preference picks struct, labelled conjectured |
| population | array of five 120-byte structs, labelled corroborated |

The other four structs in the suite are re-measured, not predicted.

**The risk, and why transport classification is still needed.** The multiset
store alone fixes globalFoo and globalStruct, because it stops a copy hiding the
accesses beneath it. But without M1's transport kind, the copy's own loads also
vote. An `int[]` copied 8 bytes at a time would then show widths 4 and 8, lose
array-of-4 under M3's width rule, and be forced to struct: a new forced error.
M4's generator includes exactly that case, and the transport kind removes it.

### 3.2 Unions and multi-dimensional arrays

`UnionComp` is at 1% recall and `MultiDimArrayTest` at 10%. Under M1,
overlapping accesses survive instead of being merged away. Members of different
kinds at one offset are the union hypothesis. Two loop strides, one a multiple
of the other, are the multi-dimensional hypothesis, and its output has to follow
Kvasir's convention of one sequence level with inner static arrays flattened
(§1g). Neither is tested. They are recorded so the new evidence store is
designed not to erase them.

### 3.3 Pointers inside structs (54% of misses) and global pointers (20%)

**Prior work.**

- **Kvasir** traverses by declared type, to nesting-depth 2 and struct-depth 4
  by default (§1g), and its framework, Fjalar, provides memory-safety guarantees
  while it traverses [Guo2006].
- **Howard** follows only pointers the program derives and dereferences
  [Howard].
- **DSIbin** classifies dynamic data-structure shapes such as lists and trees
  [DSIbin]. **DIVINE** recovers variables statically by iterating value-set
  analysis with aggregate structure identification, correctly identifying 88%
  of locals and 89% of heap-object fields [DIVINE, ASI].

**What transfers.** Phase 10 followed pointer-*shaped* values one level and paid
6 precision points for 176 facts. Howard's rule is gated on *use*.

**M5, use-gated recursion.** Treat O+k as a pointer, and recurse into its
target, only when a value loaded from O+k was used as a base address (method P),
and only to Kvasir's depths, since deeper facts cannot match the oracle. The
pointee's layout comes from accesses through that derived pointer, typed by M1.
A target whose layout repeats its parent's is a recursive structure, which takes
`--struct-depth` instead.

Recall is capped at pointers the run dereferences, a cap Kvasir does not have.
How much of the 54% lies under that cap is itself measurable, and is measured
first.

**Prediction.** More of the 54% than phase 10 recovered, at a smaller precision
cost, compared directly with phase 10's +176 facts and -6 points.

### 3.4 Calling conventions

Struct by value is 6 wrong out of 6. A struct returned in `rax:rdx` has no
counterpart. Mixed int/float lists are misaligned (§1e).

**Prior work.**

- The **System V AMD64 ABI** classifies each eightbyte of an argument as
  INTEGER, SSE or MEMORY. Ordinary aggregates over 16 bytes are MEMORY and
  travel on the stack, copied there by the caller. A MEMORY return uses a hidden
  pointer passed in `rdi` and handed back in `rax` [SysV].
- **TypeArmor** brackets argument counts from both ends: what a callee uses is
  a lower bound, what a call site prepares is an upper bound [TypeArmor].
- **EKLAVYA** learns argument counts at about 84% accuracy on its corpus
  [EKLAVYA]. Not comparable with our exact arity on 81 of 99 functions.

**M6a, call-site aggregate blocks.** TypeArmor's call-site side, extended from
registers to the stack. A block written to `[rsp, rsp+N)` between `sub rsp, N`
and the call, wholly by transport from one contiguous source object (method P),
is one parameter of N bytes (§1d). The callee's reads of `[rbp+16, rbp+16+N)`
are its fields. A callee that reads none of it still has the parameter. This
targets both failure directions measured so far: a 252-byte struct counted as 18
arguments, and an untouched one counted as 0.

**M6b, small aggregates in registers.** The ABI erases the boundary: a
`struct {int x, y;}` arrives as one `rdi`. A call site loading 8 bytes from one
object into `rdi` looks the same as passing a `long`, so the discriminator is in
the callee: a register spilled whole and read back at narrower widths.

**M6c, aggregate returns.** `rdx` is a second return register when the callee
writes it before `ret` and the caller reads it after the call. A MEMORY return
is a callee that returns its incoming `rdi` on every call and writes through it;
the visible parameters then start at `rsi`.

**M6d, parameter order.** Two parts.

- *Robust, scorer only.* The scorer ABI-classifies each DWARF parameter type and
  maps it onto the tracer's documented numbering: integer registers, then stack
  slots, then SSE registers. This works at any optimisation level and changes no
  tracer output.
- *`-O0` only.* Number arguments by first read (§1e), documented as a premise
  beside the six existing `-O0` premises in VERIFICATION.md.

**Dead parameters.** test09 already shows the `-O0` prologue spill recovers
them. At `-O1` and above the call site still prepares the register, so
TypeArmor's upper bound would recover the parameter and its value. Untested,
and relevant only once optimised binaries are in scope.

**Prediction.** The six by-value cases get the right arity. The mixed signature
aligns and its facts match. Tier 9's measured cost, 12 facts lost outside
FloatTest to swapped names (EVALUATION-KVASIR-SUITE.md), disappears, turning
that trade into a gain. A new fixture of at least ten mixed signatures shows
100% order recovery at `-O0`.

### 3.5 The residue we called unobservable: double vs long (3%), strings (2%)

**Prior work.** **REWARDS** resolves types from type sinks, meaning library and
system-call signatures, and propagates them [REWARDS]. **TIE** draws constraints
from instruction semantics [TIE]. **Laika** classifies words by value [Laika].
**OSPREY** combines weak hints probabilistically [OSPREY].

**M7, dataflow type sinks.** With method P, a value from O+k that reaches any of
these types O+k:

| sink | type |
|---|---|
| `addsd`, `mulsd`, `ucomisd`, `cvtsd2ss`, ... | double |
| `addss`, `mulss`, `cvtss2sd`, ... | float |
| `idiv`, `sar`, `setl`, `jg`, `movsx` | signed |
| `div`, `shr`, `setb`, `ja`, `movzx` | unsigned |
| used as a memory base | pointer |
| argument of a modelled `strlen`, `strcpy`, `strcmp`, `strdup` | `char *` |
| `printf` conversion: `%d` `%u` `%ld` `%f` `%s` `%p` `%c` | per argument |
| a literal run (§3.1) | `char[]` |

A call need not run to act as a sink: its arguments are in registers at the
`call` instruction, and the callee is known from the PLT. Reading the format
string from emulator memory to type each variadic argument is our extension.

**M8, a value-domain prior, labelled conjectured.** For an 8-byte value with no
sink, compare its description length as a 64-bit integer and as an IEEE-754
double. A non-zero value that is a short decimal as a double and an enormous
number as an integer is almost certainly a double. A pointer to printable bytes
ending in NUL is almost certainly a string.

This corrects how the README states the limit: the residue is irreducible *with
certainty*, not *in probability*. Anything M8 emits must say which kind of claim
it is.

**Prediction.** Report how much of the 3% and the 2% each method recovers, and
M8's false-positive rate on the corpus's known `long`s and non-string pointers,
which DWARF supplies at test time. Keep M8 only if that rate is under a
threshold fixed before measuring.

### 3.6 Daikon's runtime

On `bc` we declare 114 variables per program point and Daikon takes 841 s.
Kvasir's 36 s on `bc` is not a fair baseline: that run used `bc`'s own
Makefile, which passes `--ignore-globals`, so it declared about 16 variables, all
parameters and their fields, against our 112 globals. Corrected 2026-10-03.

**Prior work.** Daikon's own optimisations include equality sets, dynamically
constant variables, and suppression of invariants implied by others
[Perkins&Ernst2004]. The manual explains why comparability matters: "Without
comparability information, Daikon attempts to find invariants over all pairs
(and sometimes triples) of variables present at every program point. This can
lead to two negative consequences: First, it may take lots of time and memory
..." (daikon.texinfo:4835-4839). DynComp's evaluation found that "Daikon ran
faster, used less memory, and produced fewer invariants when using abstract
types" [DynComp]. Lackwit inferred abstract types statically for C [Lackwit].
Kvasir can cap array traversal with `--array-length-limit`.

**M9, bound before building.** §1a showed comparability will not raise
precision; whether it would cut runtime is open. Rerun Daikon on the saved `bc`
trace with every variable in its own comparability class. That is the best
runtime any comparability analysis could achieve.

- If it stays near 841 s, the cost is unary and derived-variable work, and an
  emulated DynComp is not worth building.
- If it falls by an order of magnitude or more, build interaction tags on
  method P.

Kvasir's 36 s cannot serve as the target, because it was a run without globals.
Hours of measurement decide whether weeks of building are worth it.

### 3.7 Library calls and program input

**Prior work.** **HALucinator** replaces library functions with Python handlers
inside an emulator, which it calls high-level emulation [HALucinator]. **KLEE**
models the POSIX environment, including files, stdin and command-line arguments
[KLEE]. **WINNIE** synthesises harnesses for closed-source programs from sample
executions [WINNIE]. **REWARDS** uses the same calls as type sinks [REWARDS].

**M10, every model is also a sink.** Model `memset`, `memcpy`, `strdup`,
`strlen` and `toupper` first (§1f). Each restores fidelity and yields evidence:

| call | state | evidence |
|---|---|---|
| `memset(d, c, n)` | fills n bytes | extent n at d; no width |
| `memcpy(d, s, n)` | copies n bytes | transport s to d; extent n on both |
| `strdup(s)` | allocates `strlen(s)+1` in the tier-5 arena and copies | s and the result are strings |
| `strlen(s)` | computes | s is a string |
| `fgets(buf, n, f)` | reads a line from the input model | buf is `char[n]` |

Then `fgets`, and `fopen` with `read` over a per-vector in-memory file table
after KLEE's model, which unlocks the four programs blocked on input.

Add a **value-fidelity check** beside the sample-count check: for every
variable both tools name, compare values sample by sample against Kvasir's
trace. VERIFICATION.md already proposes it; §1f gives it a known first target.

### 3.8 Input generation and the fuzzing loop

**Prior work.**

- **Operational difference** keeps a generated test only if it changes the
  inferred invariants, and grows a suite until they stop changing
  [Harder2003]. This is the loop we discussed for this project, published in
  2003 for unit-test suites.
- **Operational violation** selects generated tests that violate inferred
  invariants [Xie&Notkin2003].
- **Eclat** classifies an input that violates the inferred model as likely
  illegal, likely normal, or likely fault-revealing, by whether preconditions or
  only postconditions break [Eclat].
- **InvsCov** learns likely invariants per basic block from source, with
  Daikon, and feeds their violations to AFL++ as extra coverage [InvsCov].
  **IJON** lets an analyst feed program state to the fuzzer through annotations
  [IJON].
- **ClearView** learned Daikon invariants on stripped x86 binaries at
  instruction granularity, then checked them in deployed software [ClearView].
- **Binvariants** (2026) brings invariant feedback to binary-only fuzzing:
  "By monitoring register values at basic block boundaries, we infer likely
  invariants that encode value constraints and relationships across registers".
  It runs on AFL++ with QEMU and reports violations through AFL++'s coverage
  bitmap. Across 25 targets it found 143 bugs against 137 for coverage-only
  fuzzing, 20 of them missed by coverage, and 52% more unique coverage
  [Binvariants].
- **AFL++** includes unicornafl, which "adds AFL support to the Unicorn Engine"
  with a persistent mode, and a custom-mutator API with which researchers can
  "build novel scheduling" [AFL++].

**Where that leaves us.** Invariant-guided fuzzing of binaries exists, so that
is not ours to claim. What our tracer adds is the *level* of the invariants:
over recovered parameters, pointees and globals at function boundaries, rather
than over registers at basic-block boundaries. And three ideas from the testing
literature that the fuzzing papers above do not use, as far as we found:
operational difference as the selection criterion, Eclat's classification, and
certification.

**M11, operational-difference fuzzing.**

1. **Fast loop.** AFL++ with unicornafl over our existing memory map and
   argv/stdin model, with no Python per-instruction hooks. Our tracer manages
   about 45 executions per second (501 runs in 11 s), far below fuzzing rates.
2. **Slow loop.** Trace each new queue entry with the full tracer, and check it
   with Daikon's `InvariantChecker`, which is already in the tree
   (daikon/java/daikon/tools/InvariantChecker.java; it takes an invariant file
   and a trace, or a directory of traces, so entries can be batched).
3. **Classify** as Eclat does: a broken ENTER invariant means a new input
   region; only broken EXIT invariants mean new behaviour on a known region.
4. **Reward** operational difference through the scheduling API.
5. **Relearn** from the growing corpus. Saturation is the point where the
   invariants stop changing.
6. **Skip** invariants that are certified (§3.9): no input can falsify them.

**Prediction, on tcas.** Starting from a 10% sample of the 501 vectors, M11
recovers the full set's invariants in fewer executions than coverage-only
AFL++, and falsifies invariants the 501 vectors over-fit. The named risk:
novelty may be dominated by illegal inputs, which is what step 3 is for. A
second comparison worth running on the same targets: function-level invariants
from our tracer against register-level ones in the style of Binvariants.

### 3.9 Certification

**Prior work.** **Houdini** generates many candidate annotations and uses
ESC/Java to refute them until a consistent set remains [Houdini]. **Nimmer and
Ernst** studied programmers verifying code with ESC/Java given Houdini's and
Daikon's inferred invariants, and found Daikon helped them state more correct
invariants [Nimmer&Ernst2002]. **DART** turns solver results into concrete
inputs [DART].

**M12, Houdini per function on the binary.** Assume a function's ENTER
invariants, execute it symbolically from entry (angr [angr] is one option), and
try to prove each EXIT invariant with an SMT solver, loop-free functions first.
Proved means *certified*. Unproved means *conjectured*, and the counterexample
is an argument vector the fuzzer can aim at. Report the certified fraction
beside precision and recall, as FORMAL-METHODS.md §4 proposes.

### 3.10 Evaluation

- **Equality sets.** Daikon collapses mutually equal variables and reports other
  invariants over one leader [Perkins&Ernst2004]. The leader follows declaration
  order, which differs between the tools: scorer limitation 9, behind 80 of 251
  tcas misses. Fix: rewrite both reports onto a leader the scorer chooses for
  each equality class, using the `x == y` facts both reports print.
- **Semantic matching.** Count a Kvasir fact as recalled when our facts *entail*
  it, decided by an SMT solver over linear arithmetic. That is the general fix
  for scorer limitations 1 to 9, each of which was one fact spelled two ways.
  Comparing inferred and programmer-written contracts by meaning rather than by
  spelling has precedent [Polikarpova2009].
- **Duplicates.** The 2026 survey reports heavy duplication in standard
  datasets [Survey2026], and our corpus has the same function in two programs
  (§1g). Report per-unique-function figures as well.
- **Benchmarks.** tcas comes from the Siemens suite [Hutchins1994], distributed
  through SIR [SIR]. The four programs blocked on input are next once M10 lands.

---

## 4. What we rediscovered

| our result | earlier work |
|---|---|
| bulk copies corrupt layout evidence (phase 13) | Howard 2011 |
| signedness from the consuming opcode (tier 8) | TIE 2011's instruction-semantics constraints |
| one instruction walking offsets means an array (phase 10) | Howard 2011's loop-based arrays |
| arity bracketing (FORMAL-METHODS (b)) | TypeArmor 2016 |
| emit only what every hypothesis agrees on (FORMAL-METHODS (a)) | TIE's type bounds; version spaces, Mitchell 1982 |
| certified versus conjectured (FORMAL-METHODS (d)) | Houdini 2001; Nimmer & Ernst 2002 |
| a fuzzer and invariants feeding each other | Harder 2003; Xie & Notkin 2003; Eclat 2005; InvsCov 2021; Binvariants 2026 |
| PLT interception and library models | HALucinator 2020; KLEE 2008; REWARDS 2010 |

## 5. What appears new, relative to the sources checked

- **The metric.** Scoring a stripped-binary front end by agreement on the
  invariants it produces, against a DWARF-reading front end. Type-inference
  work, as systematised by [CSUR2016] and [Survey2026], scores recovered types
  against debug information; we found none that scores the invariants.
- **M1.** Separating transport from interpretation, so that inlined, unrolled
  copies and literal stores stop voting on types.
- **M6a.** Recovering MEMORY-class aggregate parameters from the call site's
  transport block.
- **M11 as a combination.** Operational difference and Eclat's classification as
  fuzzer scheduling, over function-level invariants recovered from a binary.
- **§1a.** The measured effect of comparability against a DynComp-filtered
  oracle.

These are claims about the sources checked, not about the whole literature.

## 6. Recommended order

| step | why in this position | cost |
|---|---|---|
| 1. scorer: ABI-aware argument alignment (M6d) and a canonical equality leader | recovers facts we already emit; no tracer change | days |
| 2. M9's bound on bc | decides whether a whole subsystem is worth building | hours |
| 3. multiset evidence store, sound elimination, array-of-struct (M1 without dataflow, M2, M3) | predicted to fix all four forced errors in §1b without method P, at the risk named in §3.1 | days |
| 4. method P and M1's transport and literal kinds | removes that risk by stopping copies voting on width; needed by M5, M6a, M7 | 1-2 weeks |
| 5. M10's five library models and the value-fidelity check | a fidelity defect in 9 of 29 programs | days |
| 6. M4's generative soundness check | guards steps 3-4 against fitting 72 objects | days |
| 7. M6a-c, M5, M7 | each needs method P | weeks |
| 8. M11 | needs a stable invariant set and M10 | weeks |
| 9. M12 and M8 | most expensive, or only conjectural | weeks |

Each step stays behind a flag, is measured on all three corpora (fixtures, the
Kvasir suite, tcas), and keeps the goldens byte-identical, per the standing rule
in [plans/README.md](plans/README.md).

---

## Appendix A. Reproducing the measurements

All commands run under WSL from the repository root. `BIN` is the `-g` build of
a Kvasir-suite program, as built for
[EVALUATION-KVASIR-SUITE.md](EVALUATION-KVASIR-SUITE.md).

**§1a, comparability.** `test.sh` names its outputs differently from what the
script expects, so gather one directory first:

```bash
# TESTS_DIR: the directory test.sh was given with --tests.
# t8: the tier the tracer reports were produced at.
mkdir -p /tmp/cmp
for k in invariants/*.kvasir.txt; do
  n=$(basename "$k" .kvasir.txt)
  cp "$k" /tmp/cmp/$n.kvasir.txt
  cp invariants/$n.tracer.t8.txt /tmp/cmp/$n.tracer.txt
  cp traces/$n.kvasir.decls /tmp/cmp/$n.kvasir.decls
  cp "$TESTS_DIR/$n.exe" /tmp/cmp/$n.exe
done
./venv/bin/python scripts/measure_comparability.py /tmp/cmp
```

The script refuses to report if its totals disagree with `score_invariants.py`,
and returns 2 if any matched fact is classified cross-class.

**§1b, the four globals.** Direct references:

```bash
objdump -d --no-show-raw-insn -M intel BIN | grep '<globalStruct'
```

`population` is reached through a computed pointer, so read from its `lea`:

```bash
objdump -d --no-show-raw-insn -M intel ArrayTest.exe | awk '/^  4011da:/{f=1} f{print; n++} n>44{exit}'
```

The period check for `population`, from its recorded accesses:

```python
fields = [(0,4),(4,4),(8,2),(24,8),(32,8),(40,8),(48,8),(56,8),(64,8),
          (96,8),(104,8),(112,2),(272,8),(360,4),(512,8)]
def consistent(p, size=600):
    layout = {}
    for off, w in fields:
        r = off % p
        if r + w > p or layout.get(r, w) != w:
            return False
        layout[r] = w
    spans = sorted(layout.items())
    return all(a + wa <= b for (a, wa), (b, _) in zip(spans, spans[1:]))
print([p for p in range(8, 601) if 600 % p == 0 and consistent(p)])   # [120, 600]
```

**§1d, the by-value call site.**

```bash
objdump -d --no-show-raw-insn -M intel ArraysInStructTest.exe | grep -B2 -A2 'sub    rsp,0x100'
```

**§1e, first reads.**

```bash
objdump -d --no-show-raw-insn -M intel TrivialTest.exe | awk '/<initBasicTypesStruct>:/{f=1} f{print; n++} n>16{exit}'
```

**§1f, library calls.**

```bash
for f in BINDIR/*.exe; do
  echo "$(basename $f): $(objdump -d --no-show-raw-insn $f \
    | grep -oE 'call +[0-9a-f]+ <[a-z_0-9]+@plt>' \
    | sed -E 's/.*<([a-z_0-9]+)@plt>/\1/' | sort -u | tr '\n' ' ')"
done
```

**§1g.** daikon/doc/daikon.texinfo, lines 4538-4545 and 4561-4577.

---

## Bibliography

### Binary type and structure recovery

- **[Howard]** A. Slowinska, T. Stancescu, H. Bos. *Howard: A Dynamic Excavator
  for Reverse Engineering Data Structures.* NDSS 2011.
  https://www.cs.vu.nl/~herbertb/papers/howard_ndss11.pdf
- **[TIE]** J. Lee, T. Avgerinos, D. Brumley. *TIE: Principled Reverse
  Engineering of Types in Binary Programs.* NDSS 2011.
  https://www.ndss-symposium.org/ndss2011/tie-principled-reverse-engineering-of-types-in-binary-programs/
- **[REWARDS]** Z. Lin, X. Zhang, D. Xu. *Automatic Reverse Engineering of Data
  Structures from Binary Execution.* NDSS 2010.
  https://www.ndss-symposium.org/wp-content/uploads/2017/09/lin_0.pdf
- **[Laika]** A. Cozzie, F. Stratton, H. Xue, S. T. King. *Digging for Data
  Structures.* OSDI 2008.
  https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf
- **[DSIbin]** T. Rupprecht, X. Chen, D. H. White, J. H. Boockmann, G. Lüttgen,
  H. Bos. *DSIbin: Identifying Dynamic Data Structures in C/C++ Binaries.*
  ASE 2017.
  https://research.vu.nl/en/publications/dsibin-identifying-dynamic-data-structures-in-cc-binaries/
- **[OSPREY]** Z. Zhang, Y. Ye, W. You, G. Tao, W.-C. Lee, Y. Kwon, Y. Aafer,
  X. Zhang. *OSPREY: Recovery of Variable and Data Structure via Probabilistic
  Analysis for Stripped Binary.* IEEE S&P 2021, pp. 813-832.
  https://www.semanticscholar.org/paper/OSPREY:-Recovery-of-Variable-and-Data-Structure-via-Zhang-Ye/cab7ab16605bd116b9020f848e4b99836490d08a
- **[Retypd]** M. Noonan, A. Loginov, D. Cok. *Polymorphic Type Inference for
  Machine Code.* PLDI 2016. https://dl.acm.org/doi/10.1145/2908080.2908119
- **[BinSub]** I. Smith. *BinSub: The Simple Essence of Polymorphic Type
  Inference for Machine Code.* SAS 2024. https://arxiv.org/abs/2409.01841
- **[TRex]** J. Bosamiya, M. Woo, B. Parno. *TRex: Practical Type
  Reconstruction for Binary Code.* USENIX Security 2025.
  https://www.usenix.org/conference/usenixsecurity25/presentation/bosamiya
- **[DIVINE]** G. Balakrishnan, T. Reps. *DIVINE: DIscovering Variables IN
  Executables.* VMCAI 2007.
  https://link.springer.com/chapter/10.1007/978-3-540-69738-1_1
- **[ASI]** G. Ramalingam, J. Field, F. Tip. *Aggregate Structure
  Identification and Its Application to Program Analysis.* POPL 1999,
  pp. 119-132. https://dl.acm.org/doi/10.1145/292540.292553
- **[XTRIDE]** L. Seidel, S. L. Thomas, K. Rieck. *Practical Type Inference:
  High-Throughput Recovery of Real-World Structures and Function Signatures.*
  arXiv:2603.08225, 2026. https://arxiv.org/html/2603.08225
- **[Survey2026]** H. Zheng et al. *From Heuristics to Transformers: A
  Comprehensive Survey of Type Inference from Stripped Binaries.*
  arXiv:2606.23692, 2026. https://arxiv.org/html/2606.23692
- **[CSUR2016]** J. Caballero, Z. Lin. *Type Inference on Executables.* ACM
  Computing Surveys 48(4), 2016. https://dl.acm.org/doi/10.1145/2896499
- **[EKLAVYA]** Z. L. Chua, S. Shen, P. Saxena, Z. Liang. *Neural Nets Can
  Learn Function Type Signatures From Binaries.* USENIX Security 2017,
  pp. 99-116.
  https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/chua
- **[TypeArmor]** V. van der Veen, E. Göktaş, M. Contag, A. Pawlowski, X. Chen,
  S. Rawat, H. Bos, T. Holz, E. Athanasopoulos, C. Giuffrida. *A Tough Call:
  Mitigating Advanced Code-Reuse Attacks at the Binary Level.* IEEE S&P 2016,
  pp. 934-953.
  https://research.vu.nl/en/publications/a-tough-call-mitigating-advanced-code-reuse-attacks-at-the-binary-2/
- **[SysV]** H. J. Lu, M. Matz, M. Girkar, J. Hubička, A. Jaeger, M. Mitchell.
  *System V Application Binary Interface, AMD64 Architecture Processor
  Supplement,* version 1.0.
  https://cs61.seas.harvard.edu/site/pdf/x86-64-abi-20210928.pdf

### Daikon, abstract types, and front ends

- **[DynComp]** P. J. Guo, J. H. Perkins, S. McCamant, M. D. Ernst. *Dynamic
  Inference of Abstract Types.* ISSTA 2006, pp. 255-265.
  https://homes.cs.washington.edu/~mernst/pubs/abstract-type-issta2006.pdf
- **[Lackwit]** R. O'Callahan, D. Jackson. *Lackwit: A Program Understanding
  Tool Based on Type Inference.* ICSE 1997, pp. 338-348.
  https://bibbase.org/network/publication/ocallahan-jackson-lackwitaprogramunderstandingtoolbasedontypeinference-1997
- **[Perkins&Ernst2004]** J. H. Perkins, M. D. Ernst. *Efficient Incremental
  Algorithms for Dynamic Detection of Likely Invariants.* FSE 2004, pp. 23-32.
  https://www.semanticscholar.org/paper/Efficient-incremental-algorithms-for-dynamic-of-Perkins-Ernst/0f46341f6e6a20b1446757c75e29b27561955447
- **[Daikon2007]** M. D. Ernst et al. *The Daikon System for Dynamic Detection
  of Likely Invariants.* Science of Computer Programming 69(1-3), 2007.
  https://dl.acm.org/doi/abs/10.1016/j.scico.2007.01.015
- **[Daikon2001]** M. D. Ernst, J. Cockrell, W. G. Griswold, D. Notkin.
  *Dynamically Discovering Likely Program Invariants to Support Program
  Evolution.* IEEE TSE 27(2), 2001. Listed at
  https://plse.cs.washington.edu/daikon/pubs/
- **[Guo2006]** P. J. Guo. *A Scalable Mixed-Level Approach to Dynamic Analysis
  of C and C++ Programs.* MEng thesis, MIT, 2006. The Fjalar framework and
  Kvasir.
  https://pg.ucsd.edu/publications/Philip-Guo_Masters-thesis_mixed-level-dynamic-analysis.pdf
- **[Memcheck]** J. Seward, N. Nethercote. *Using Valgrind to Detect Undefined
  Value Errors with Bit-Precision.* USENIX ATC 2005.
  https://www.usenix.org/legacy/events/usenix05/tech/general/seward.html
- **[Mitchell]** T. M. Mitchell. *Generalization as Search.* Artificial
  Intelligence 18(2):203-226, 1982.
  https://www.semanticscholar.org/paper/Generalization-as-Search-Mitchell/0df1aac45ff562089a3bdbcb34e2481a71478651

### Testing, fuzzing, and the environment

- **[Harder2003]** M. Harder, J. Mellen, M. D. Ernst. *Improving Test Suites via
  Operational Abstraction.* ICSE 2003.
  https://dl.acm.org/doi/10.5555/776816.776824
- **[Xie&Notkin2003]** T. Xie, D. Notkin. *Tool-Assisted Unit Test Selection
  Based on Operational Violations.* ASE 2003, pp. 40-48.
  https://www.researchgate.net/publication/2925347_Tool-Assisted_Unit_Test_Selection_Based_on_Operational_Violations
- **[Eclat]** C. Pacheco, M. D. Ernst. *Eclat: Automatic Generation and
  Classification of Test Inputs.* ECOOP 2005, pp. 504-527.
  https://people.csail.mit.edu/cpacheco/publications/classify.pdf
- **[InvsCov]** A. Fioraldi, D. C. D'Elia, D. Balzarotti. *The Use of Likely
  Invariants as Feedback for Fuzzers.* USENIX Security 2021.
  https://www.usenix.org/system/files/sec21-fioraldi.pdf
- **[Binvariants]** Z. Yang, S. Nagy. *Binvariants: Enhancing Fuzzing of
  Closed-Source Binary Executables via Register-Level Likely Invariants.* 2026,
  doi:10.1145/3797078. https://futures.cs.utah.edu/papers/26FSE-c.pdf
- **[IJON]** C. Aschermann, S. Schumilo, A. Abbasi, T. Holz. *IJON: Exploring
  Deep State Spaces via Fuzzing.* IEEE S&P 2020.
  https://conferences.computer.org/sp/pdfs/sp/2020/349700b597.pdf
- **[ClearView]** J. H. Perkins et al. *Automatically Patching Errors in
  Deployed Software.* SOSP 2009.
  https://www.sigops.org/s/conferences/sosp/2009/papers/perkins-sosp09.pdf
- **[AFL++]** A. Fioraldi, D. Maier, H. Eißfeldt, M. Heuse. *AFL++: Combining
  Incremental Steps of Fuzzing Research.* WOOT 2020.
  https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf
- **[WINNIE]** J. Jung, S. Tong, H. Hu, J. Lim, Y. Jin, T. Kim. *WINNIE:
  Fuzzing Windows Applications with Harness Synthesis and Fast Cloning.*
  NDSS 2021.
  https://www.semanticscholar.org/paper/WINNIE-:-Fuzzing-Windows-Applications-with-Harness-Jung-Tong/d1d636488a52ea2fd6c6e3f854f9c09183e418f0
- **[HALucinator]** A. Clements, E. Gustafson, T. Scharnowski, P. Grosen,
  D. Fritz, C. Kruegel, G. Vigna, S. Bagchi, M. Payer. *HALucinator: Firmware
  Re-hosting Through Abstraction Layer Emulation.* USENIX Security 2020.
  https://sites.cs.ucsb.edu/~vigna/publications/2020_USENIXSecurity_HALucinator.pdf
- **[KLEE]** C. Cadar, D. Dunbar, D. Engler. *KLEE: Unassisted and Automatic
  Generation of High-Coverage Tests for Complex Systems Programs.* OSDI 2008.
  https://www.doc.ic.ac.uk/~cristic/papers/klee-osdi-08.pdf
- **[Csmith]** X. Yang, Y. Chen, E. Eide, J. Regehr. *Finding and Understanding
  Bugs in C Compilers.* PLDI 2011.
  https://users.cs.utah.edu/~regehr/papers/pldi11-preprint.pdf
- **[QuickCheck]** K. Claessen, J. Hughes. *QuickCheck: A Lightweight Tool for
  Random Testing of Haskell Programs.* ICFP 2000, pp. 268-279.

### Verification and evaluation

- **[Houdini]** C. Flanagan, K. R. M. Leino. *Houdini, an Annotation Assistant
  for ESC/Java.* FME 2001, pp. 500-517.
  https://users.soe.ucsc.edu/~cormac/papers/fme01.pdf
- **[Nimmer&Ernst2002]** J. W. Nimmer, M. D. Ernst. *Invariant Inference for
  Static Checking: An Empirical Evaluation.* FSE 2002.
  https://www.cs.washington.edu/homes/mernst/pubs/annotation-study-fse2002.pdf
- **[DART]** P. Godefroid, N. Klarlund, K. Sen. *DART: Directed Automated
  Random Testing.* PLDI 2005, pp. 213-223.
  https://patricegodefroid.github.io/public_psfiles/pldi2005.pdf
- **[angr]** Y. Shoshitaishvili et al. *SoK: (State of) The Art of War:
  Offensive Techniques in Binary Analysis.* IEEE S&P 2016. The angr framework.
  https://sites.cs.ucsb.edu/~vigna/publications/2016_SP_angrSoK.pdf
- **[Polikarpova2009]** N. Polikarpova, I. Ciupa, B. Meyer. *A Comparative Study
  of Programmer-Written and Automatically Inferred Contracts.* ISSTA 2009,
  pp. 93-104. https://cseweb.ucsd.edu/~npolikarpova/publications/issta09.pdf
- **[Hutchins1994]** M. Hutchins, H. Foster, T. Goradia, T. Ostrand.
  *Experiments on the Effectiveness of Dataflow- and Controlflow-Based Test
  Adequacy Criteria.* ICSE 1994, pp. 191-200. The Siemens suite.
- **[SIR]** H. Do, S. Elbaum, G. Rothermel. *Supporting Controlled
  Experimentation with Testing Techniques: An Infrastructure and its Potential
  Impact.* Empirical Software Engineering 10:405-435, 2005.
  https://link.springer.com/article/10.1007/s10664-005-3861-2
