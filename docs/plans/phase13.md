# Phase 13 — type recovery as constraint solving

Status: **planned, revised 2026-10-03.** Prerequisites: the ambiguity
measurement in [../FORMAL-METHODS.md](../FORMAL-METHODS.md), the type-cost
breakdown in [../EVALUATION-KVASIR-SUITE.md](../EVALUATION-KVASIR-SUITE.md),
and the literature review in [../RELATED-WORK.md](../RELATED-WORK.md).

**What the revision changed.** The first version of this plan said the four
forced-but-wrong shapes "have one cause", bulk copies, and proposed fixing them
by recording which instruction touched which offset. Reading the machine code
showed three causes, and showed that the copies involved are unrolled, one
instruction per offset, so that mechanism cannot see them. The diagnosis, the
mechanisms and the order below are rewritten accordingly; the measurement that
motivates the phase is unchanged.

Types are the last big thing. Measured: **88.6% of every remaining missed fact
is type information already present in the execution and not acted on**, and
only ~5% is genuinely absent from it.

Eleven phases have added type *guesses*. This one proposes to stop guessing.

---

## What the evidence can already decide

Applying **every signal currently computable** to the 72 globals with a known
extent - extent, observed access widths, access alignment, and pointer-shaped
values at 8-aligned slots:

```
surviving hypotheses:
  1 (FORCED)   33 / 72   (45%)
  2            39 / 72   (54%)

of the 33 forced:  29 correct,  4 WRONG
```

**Combining signals works.** With extent alone, **zero** of 72 shapes were
forced. With all signals combined, 45% are forced and 88% of those are right.
That is the case for building this as a constraint system rather than a pile of
discriminators.

**But four are forced onto the WRONG answer**, which is worse than ambiguity:
an unforced guess can be flagged, a forced error cannot.

This table came from an offline script reading a debug dump (`typespace.py`, in
a session scratchpad, not in the repo). Mechanism B below replaces it with a
number the tool reports itself.

## The four errors have three causes

| global | truth | forced | what the machine code does | cause |
|---|---|---|---|---|
| `globalFoo`, 256 B | struct | array | 32 separate 8-byte loads, one offset each, stored into the outgoing argument block of the by-value call `baz(f)` | copy hides the fields, and rule (ii) |
| `globalStruct`, 24 B | struct | array | stores 8 bytes at 0, 1 byte at 8, an SSE double at 16; then 8-byte loads at 0, 8, 16 | copy hides the fields, and rule (ii) |
| `globalBoo`, 58 KB | struct | array | six 4-byte stores of constants; the whole object is copied by `memcpy@plt`, which the emulator skips | rule (ii) |
| `population`, 600 B | array of five 120-byte structs | struct | mixed widths inside element 0; accesses at 272, 360, 512 repeat element-0 fields modulo 120 | missing hypothesis (iii) |

- **(i) The evidence store keeps only the widest access per address**
  ([globalvars.py:203](../../scripts/tracer/globalvars.py#L203); `fields_within`
  at :227 drops overlaps the same way). The 8-byte load at `globalStruct+8`
  erases the 1-byte store under it, so the recorded widths are `[8]`.
- **(ii) "Struct" is admitted only when widths differ.** A struct whose touched
  members share a width can never survive. That alone forced `globalBoo`, with
  no copy involved.
- **(iii) There is no array-of-struct hypothesis.** For `population`, the only
  layouts consistent with every access are period 120 and the whole object.

The first version also explained `population` as "an array cleared or copied
bytewise". Its 2-byte accesses are in fact the tails of inlined string-literal
copies into `char[]` members (`"Ricky"`, `"123456789"`), so **stores of
constants are not always type evidence either**. Details and disassembly:
[RELATED-WORK.md §1b](../RELATED-WORK.md#1b-the-four-forced-but-wrong-shapes-have-three-causes-not-one).

**Why the old mechanism A would not work.** It flagged one instruction touching
many offsets. The copies above are unrolled at `-O0`: every instruction touches
exactly one offset. Only dataflow shows that a loaded value was moved and never
used. Howard (NDSS 2011) identified the same problem with `memset` and `memcpy`
and solved it with access patterns; ours are inlined, so the patterns are not
there.

---

## A. Evidence typing

Types come from operations on values, not from moving them: the principle
behind TIE's instruction constraints and REWARDS' type sinks, applied with the
dataflow/interaction split from DynComp. Each access gets a kind:

| kind | votes on |
|---|---|
| consume | width, type, and existence of a member |
| initialise (scalar immediate) | width and existence of a member |
| literal (at least two printable bytes, then NUL) | a `char[]` of at least that length; not width |
| transport | extent only |

**A1, multiset evidence store. No dataflow needed.** Record every access as
`(pc, offset, width)` instead of the widest width per address. This alone stops
the 8-byte copy at `globalStruct+8` erasing the 1-byte store.

**A2, transport and literal kinds. Needs the provenance shadow.** A load whose
value is only ever stored is transport; consecutive immediate stores spelling at
least two printable bytes and then a NUL are a literal. The shadow is specified in
[RELATED-WORK.md §2](../RELATED-WORK.md#method-p-a-provenance-shadow); it is the
same substrate later work on pointer depth, call sites and type sinks needs, so
it is built once, flag-gated, and its overhead measured first.

**A3, sound elimination only.** Every rule that removes a hypothesis gets a
written justification and a test.

| rule | sound? |
|---|---|
| an access straddles a candidate element boundary, so not array-of-w | yes: one scalar access never spans two elements |
| extent above 8 bytes, so not scalar | yes |
| a consume or scalar-initialise access of width other than w, so not array-of-w | yes, given that a program accesses a scalar at its declared width, the premise every type sink relies on. Copies and literal stores break it, hence their own kinds |
| uniform widths, so not struct | **no**: a struct of same-width members is observationally an array. Removed; at most a preference |

**A4, array-of-struct and the periodicity test.** Add array-of-struct to the
hypothesis alphabet. For each period p dividing the extent, fold the consume and
initialise accesses modulo p; reject p if an access straddles a period boundary
or two folded accesses overlap without coinciding; literal runs fold as byte
ranges. Take the smallest consistent p below the extent with at least two
periods touched. On `population` this yields p = 120 with four of five elements
touched. Labelled *corroborated*, not *forced*: unrelated fields can line up by
chance.

## B. Represent the hypothesis set instead of collapsing it

`GlobalObject` holds one shape. It should hold the surviving set, and the
emitter should know whether it is choosing or deriving.

1. **`--report-types`** prints the ambiguity, so "we guessed" stops being
   invisible, and the table above stops depending on an offline script.
2. **Conflicts become detectable.** An empty hypothesis set is a contradiction,
   a bug or a wrong premise, and should say so rather than pick.
3. **Ambiguity residue becomes a reportable metric** beside precision and
   recall. It falls as signals are added.

## C. For what stays ambiguous, emit both shapes

Where array and struct both survive, the two descriptions share almost no
sentences. For **globals** the two forms do not collide:

```
array form   g_0x404060   +  g_0x404060[..]
struct form  g_0x404060   +  g_0x404060.off0, .off4, ...
```

Both can be declared at once, and whichever one Kvasir used, we match it. A
recall-for-precision trade, flag-gated, measured on both corpora, kept only if
it pays. More declared variables per program point is also what makes Daikon
slow (phase 11), so its runtime is measured too.

## D. Type sinks for the residue

A `double` never loaded as a double is a `long`; a `char*` never walked is a
pointer. The lever is the consuming operation, which already overturned
"signedness is not observable". With the provenance shadow, a value from O+k
that reaches SSE double arithmetic, a modelled string function, a `printf`
conversion, or a signed or unsigned opcode types O+k. Static scanning finds
nothing here (the SSE-touched addresses are constant-pool literals); the dynamic
form works where the program uses the value as that type. See
[RELATED-WORK.md §3.5](../RELATED-WORK.md#35-the-residue-we-called-unobservable-double-vs-long-3-strings-2).

Where the program never distinguishes two types, neither can we. A value-domain
prior can guess, but anything it emits must be labelled conjectured.

## E. A generative soundness check

The rules were tuned on 72 objects from one suite. Generate random globals,
structs, arrays and arrays of structs with random access patterns (field
reads, indexed loops, by-value passing, literal assignment, `memset`, `memcpy`),
compile at `-O0`, trace, and assert that the DWARF truth is **never
eliminated**. Minimise failing programs. DWARF is read only by the test.

---

## Order

```
B   hypothesis sets + --report-types        makes everything else measurable in-tool
A1  multiset evidence store                 fixes defect (i) without dataflow
A3  sound elimination only                  fixes rule (ii): globalBoo stops being forced
A4  array-of-struct + periodicity           fixes (iii): population
E   generative soundness check              before tuning anything further
A2  transport and literal kinds             needs the provenance shadow; stops copies voting on width
C   emit both shapes where ambiguous        recall/precision trade, flag-gated
D   type sinks                              the residue, partially
```

B first, because without it the rest can only be evaluated by the same offline
script that produced the table above, and a mechanism that cannot be measured
in-tool will not stay correct.

A1 before A2 carries one risk. Until copies are classified, a copy's own loads
vote on width, so an `int[]` copied 8 bytes at a time shows widths 4 and 8 and
would be forced to struct. E's generator includes that case, and A2 removes it.

## Acceptance

- **Forced-but-wrong goes to 0.** Four today. Predicted per global:

  | global | after A1-A4 |
  |---|---|
  | globalFoo | forced struct after A1: the 4-byte and SSE accesses the copy hid make the widths heterogeneous |
  | globalStruct | forced struct: 8-byte, 1-byte and SSE accesses survive A1 |
  | globalBoo | ambiguous: not forced, and not wrong |
  | population | array of five 120-byte structs, corroborated |

- **On generated programs, the truth is never eliminated.**
- **Forced fraction is reported by the tool**, and shape accuracy beats the
  current **64 of 72**, and specifically **0 of 8 structs**.
- Fixture corpus unchanged at **65/92/76**; 29-program suite no worse than
  **24/17/20**; `tcas` no worse than **94/90/92**.
- All goldens byte-identical unless a new flag is passed.

## Why this is worth doing rather than more traversal

Phase 10 measured the alternative: following pointers one level deeper bought
176 facts and cost 6 points of precision, and its struct-global mechanism lost
123 facts outright. Adding *reach* has consistently cost precision.

The one change in twelve phases that cost nothing - strided access, in phase 10
- worked because it replaced a guess with evidence. This phase is that same move
applied to the whole type decision. The revision sharpens what "evidence" has to
mean: what the program does *with* a value, not merely where it moved it.
