# AI-assisted type recovery: a pilot, and what it actually showed

Question asked: **could we selectively decompile types with AI** to close the
type gaps phase 10 measured? In particular C, struct-shaped globals, which
failed three discriminators and sits at **0/8**.

Short answer: **yes, the information is in the binary, and a model found it.
But on this sample every correct call came from a signal a ~20-line
deterministic rule could also read.** The best use of a model here is to
*discover* signals and to *pick between hypotheses the evidence already
allows*. It should not be a type oracle in the trace path.

---

## The pilot

Blind and anonymised, on all 88 globals with a `.symtab` extent in 31 of
Daikon's Kvasir-suite C programs: 30 scalars, 26 arrays, 24 pointers, 8 structs.
The 8 structs are the same 8 that FORMAL-METHODS.md scores at 0/8.

```
scripts/pilot_ai_types/build_packets.py   compile -O0 -gdwarf-3 -no-pie, strip
                                          truth   <- DWARF of the debug copy
                                          packet  <- STRIPPED copy only
scripts/pilot_ai_types/preds.tsv          the model's calls, written first
scripts/pilot_ai_types/score.py           scored against truth.json afterwards
```

Each packet held only what survives `strip --strip-all`: the address, the
`.symtab` extent (the same assumption as tier 8's symbol path), the initial
bytes, and every instruction touching the range with +-3 lines of context.
`.rodata` string literals were annotated, as any decompiler would show them.
The "AI" was Claude, reading packets keyed `g001..g088` and writing all 88
predictions to `preds.tsv` before `truth.json` was opened.

### Result

```
                       kind correct    structs    false structs   doubles
tracer (FORMAL-METHODS)   88%            0/8           0          not typed
pilot, all 88             85/88 (97%)    6/8           1          4/4
pilot, no label leak      77/80 (96%)    5/7           1          3/3
```

```
truth\pred   scalar  array  pointer  struct
scalar           30      0        0       0
array             0     25        0       1   <- g051, a guess with no evidence
pointer           0      0       24       0
struct            0      2        0       6   <- g003, g011
```

**The label-leak confound.** Several suite programs print every global's
address with a label such as `"double globalDouble: %p"`, so the type is
spelled out in `.rodata`. Real programs do not do this. Predictions that used
such a string are tagged `leak=yes` (8 of 88) and the second row excludes them.
It changes little: 5 of the 8 leaked ones (g013-g017) were also decidable
from their bytes alone.

### The three misses are the right kind of miss

- **g003** `struct {int a[], b[], c[]}`: 84 bytes of ints and never accessed.
  No evidence separates it from `int[21]`. **The correct answer was to
  abstain.**
- **g011** `struct {int; char[]}`: 16 zero bytes in `.bss`, never accessed.
  **Abstain.**
- **g051** `unsigned char[8]` called a struct, because its address goes to a
  function that is also handed a heap object. A plausible story with no
  evidence behind it. This is a hallucinated fact, exactly what a fuzzing
  consumer must not be fed, and it **would have been prevented by requiring
  abstention when no access contradicts the default.**

With an abstain rule, the pilot is 6/8 structs with **zero** false structs.

---

## The finding that matters: what the hits were made of

Every struct, array-of-struct and double hit traces to one of four mechanical
signals. None needed a model:

| signal | globals it decided | why it is sound-ish |
|---|---|---|
| **whole-extent by-value copy**: the full extent is copied onto the stack before a call | g010, g022, g043 (3 structs) | C cannot pass an array by value. A by-value block copy of exactly the object's extent is a struct, or a union. |
| **heterogeneous slot classes in the INITIAL bytes**: a pointer-shaped slot next to a non-null scalar | g054, g055 (`static-struct` `{int*, int}`) | `char*[]` tables (g031, g058) are pointer + NULL only. **NULL is neutral, the review-B1 rule**, so they stay arrays. |
| **periodicity of the initial bytes**: a record pattern repeating every N bytes | g001 (5 x 120B), g023 (4 x 32B) | array of struct, with N as the element size |
| **IEEE-754 plausibility of initialised 8-byte values** | g012 `double[5]`, g039, g047 | `0x40c81cd6e63c4a08` = 12345.67. Integers of that magnitude are rare. |

Two of these are direct answers to phase 10's open problems:

- **C's diagnosis was half right.** "A statically-initialised struct is never
  written at run time" is true, so access widths say nothing. **But its
  initial bytes are sitting in `.data`, and nothing reads them.** Attempt 3,
  "a pointer-shaped value in some slot", fired on `char*[]` tables too.
  Requiring a pointer-shaped slot **and** a non-null non-pointer slot
  separates the two on every case in this sample, provided periodicity runs
  first. An array of structs (g001, g023) is heterogeneous too, and must be
  claimed by the period before this rule sees it.
- **D was declared unrecoverable for `GlobalTest`'s `globalDouble`**, which
  "main only takes the address of". It is initialised in `.data`, and its
  bytes decode as 12345.67. A double the program never uses as a double *is*
  recoverable when it has a non-zero initialiser. Only a zero or `.bss`
  double is the genuine residue.

## So where does a model actually earn its place?

1. **As a signal-discovery tool, offline.** This pilot is the use case. Hand
   it the packets of the misses, ask what distinguishes them, then codify what
   it says as a deterministic rule with a falsifiable criterion. Four candidate
   signals came out of one pass over 88 packets, and three target measured
   gaps.
2. **As a selector among enumerated hypotheses, never a generator.**
   FORMAL-METHODS.md (a) already proposes enumerating the 2-5 shapes
   consistent with the evidence. A model may *rank* that set when the
   deterministic rules leave it ambiguous. It may not introduce a shape
   outside the set, and it must be able to return "abstain". g051 is what
   happens without that constraint.
3. **For the facts no byte carries.** Names, and the order of a mixed int/float
   parameter list, are not recoverable from bytes. Here a model can only
   supply a prior, and phase 9 already chose "convention, flag-gated" over a
   guess. Names do not affect the score, because the scorer maps them via
   DWARF.

### If it is built, the constraints are not optional

- **Not in the trace path.** Run it as a pre-pass that writes a type-hints
  file keyed by binary hash, which the tracer reads with a flag. The goldens
  stay byte-identical. Trace runs stay deterministic and offline, and the
  ~11 s per-iteration budget is untouched.
- **Validate every hint against observed accesses** before use. Reject an
  `int[]` hint if a `movsd` touches the object, and a struct hint if the
  offsets tile uniformly at one width. The validator is the trust boundary,
  not the model.
- **Never show it DWARF or source**, consistent with "DWARF is read only at
  scoring time".
- **Contamination is real.** Daikon's test suite is public, and the label
  strings name the variables (`"globalFoo[0]"` is stored inside g023).
  Evaluate on (i) the suite with `.rodata` labels blanked and (ii) fixtures
  written after the model's training cutoff. **The pilot's model may have
  seen these programs**, and that is the strongest reason to discount the
  6/8.

---

## What this does NOT establish

- **End-to-end benefit.** Shape accuracy is not P/R/F1. Phase 10 C lost 123
  matched facts while trying to emit struct globals, partly from how fields
  are emitted, not only which globals are structs. The deterministic rules
  above need to go through the tracer and the scorer, against the 20%
  precision floor, before anyone believes them.
- **Behaviour on stripped `.symtab`.** Every global here had an exact extent.
  Without one, periodicity and by-value copy both lose their anchor.
- **Struct pointees and depth-2 traversal** (phase 10 A, 54% of misses).
  That gap is missing recursion, not missing type knowledge, and nothing here
  addresses it.
- **Sample size.** 8 structs. A rule that is right on 5 of them is a
  hypothesis worth a fixture, not a result.

## Recommended next steps, in order

1. Implement **heterogeneous initial-slot classification** (pointer + non-null
   scalar -> struct, NULL neutral) as phase 10 C attempt 4. Falsifiable:
   `static-struct` `foo` and `bar` become structs, and no `char*[]` in
   `StaticArraysTest` or `string-arrays` does.
2. Implement **by-value-copy detection**. Falsifiable: `globalBoo`,
   `globalStruct` and `ArraysInStructTest`'s `globalFoo` become structs.
3. Implement **IEEE plausibility for initialised 8-byte `.data` slots**,
   flag-gated alongside phase 10 D. Falsifiable: `globalDouble` in
   `GlobalTest` / `TrivialTest` / `crazy-test-1` reports as `double`.
4. Measure 1-3 through the scorer. Only then is it worth asking a model to
   rank what remains ambiguous, and only on the residue.
