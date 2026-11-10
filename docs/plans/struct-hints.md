# Plan — struct layouts as tracer hints: how much would full structs buy?

Status: **built and measured.** DWARF ceilings: full layouts +533, touched fields +235 (2026-11-10, after the merge fixes below). **ReSym on Ghidra: ±0** (1,254 vs 1,255). Follows `docs/plans/resym-hints.md`. There, perfect parameter
types added +37 matched facts, because what tier 10 misses is mostly struct fields
and globals.

## Why

Of the 4,163 Kvasir facts tier 10 misses on the suite, about 3,200 involve struct
fields:

| missed facts | count |
|---|---|
| fields of structs behind global pointers (`::p->x`) | 947 |
| fields of struct-valued globals (`::g.x`) | 822 |
| fields of global arrays (mostly of structs) | 659 |
| fields of structs behind parameters (`f[].x`) | 411 |
| fields of structs passed or returned by value (`f.x`, `return.x`) | ~370 (out of scope: not modelled) |

**Question:** if the tracer knew the struct layouts, how many of those would it
recover? And how many are within reach of a source that only knows the fields
the code touches, as ReSym's FieldDecoder does?

## How a layout is fed in

The tracer decides one type per memory object (`classify.TypeInfo`, at finalize),
and the walk prints every field of that type. A struct hint becomes that type for:
- the object an argument or return value points at (`--type-hints` "args" /
  "return", pointee `struct` with `fields`);
- a struct-valued global, or a global array of structs (new "globals" section,
  keyed by address);
- the object a pointer-valued global points at;
- one level of pointer-to-struct fields inside a hinted struct, where the run
  saw that field's target.

Field leaves:
- int / uint / float of a width;
- pointer;
- `char*`, printed as a string;
- `char[N]`, printed as an inline string;
- `T[N]` of a scalar, printed as an embedded array.

Nested structs are flattened to offsets, which the scorer already maps to Kvasir's
dotted names. Unions and arrays of structs inside structs abstain.

**Refutation by the run.** The hint is rejected, and the run's own type kept, when:
- an observed field has exactly a hinted field's offset and width but another
  kind (float / int / pointer); or
- the run accessed the object beyond the hinted size (single objects only).

A wide access spanning several hinted fields (a struct copy, a zeroing store) is
not a contradiction. Those are the run's own known false fields (phase 11).

## Two ceilings (DWARF layouts; ORACLE, never a result)

1. **Full layout:** every field DWARF declares. The most any layout source could add.
2. **Observed fields only:** hinted fields kept only where the run accessed that
   field. This is the realistic ceiling for a source like ReSym's FieldDecoder,
   which predicts types for the fields the code accesses.

   On this suite, "the run accessed it" stands in for "the code accesses it".
   Phase 11 step 6 found that Ghidra's static dereferences add no fields beyond
   the run's here, because these -O0 programs execute every constant-offset
   access they contain.

## Steps

1. **Tracer** (`hints.py`, `emulate.py`, `walk.py`):
   - struct layout hints for argument and return pointees and for globals;
   - refutation;
   - an observed-only mode;
   - string fields.

   Flag-gated, so goldens are unchanged.
2. **`hints_from_dwarf.py --structs [--observed-only]`:** layouts from DWARF.
3. **Suite runs:**
   - the baseline;
   - parameters only (the earlier ceiling);
   - with full layouts;
   - with observed fields only.
4. **Score each run:**
   - P/R/F1 against Kvasir;
   - the audit, which must find 0 false facts;
   - Daikon failures, which must be 0;
   - per-binary deltas;
   - hints applied and refuted.
5. **Write-up and next step:**
   - If ceiling 2 is large, the next experiment is ReSym's FieldDecoder in place
     of DWARF.
   - If only ceiling 1 is large, the gain needs whole struct definitions, such
     as headers, which no binary-only tool provides.

## Gates

- Goldens are byte-identical without the flag, and all tests pass.
- 0 audit violations, and Daikon exits 0 on every program.
- No pre-set gain threshold: this step only measures the two ceilings.

## Results (2026-11-09)

The container was rebuilt from source before measuring: Daikon and Kvasir
(`codespecs/daikon`, `codespecs/fjalar`), the suite recompiled with its own flags,
and Kvasir rerun. Kvasir's oracle reproduces exactly (5,419 facts). The tier-10
baseline comes out at 1,255 matched, one fact off the 1,256 recorded earlier. Every
row below is from the same rebuilt toolchain and the same runner
(`scripts/rea_eval/suite_hints.py`).

| run (DWARF hints are ORACLE ceilings) | ours | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| tier 10 baseline | 4,934 | 1,255 | 25.4% | 23.2% | 24.2% |
| + parameter types (resym-hints.md) | 4,975 | 1,289 (+34) | 25.9% | 23.8% | 24.8% |
| **+ struct layouts, fields the run touched** | 4,580 | **1,490 (+235)** | 32.5% | 27.5% | 29.8% |
| **+ full struct layouts** | 4,924 | **1,788 (+533)** | **36.3%** | **33.0%** | **34.6%** |

The struct rows include the parameter types. "Fields the run touched" is the
realistic ceiling for a source that knows only the fields the code accesses, such
as ReSym's FieldDecoder. "Full" is the most any layout source could give.

Other measurements:
- **Soundness:** `audit_soundness.py` finds 0 violations on both struct runs
  (1,494 and 1,424 decidable facts, all true).
- **Daikon:** exits cleanly on all 30 programs.
- **Overhead:** tracer time 11.6 s → 11.9 s for the suite.
- **Hints (full):**
  - 33 layouts applied and 2 refuted;
  - 1 object received two different hinted layouts and kept the first;
  - with observed-only, 14 layouts had no field the run touched.

Per binary (matched; full / observed-only; measured before the merge fixes below, totals then 1,776 / 1,479):

| binary | baseline | full | observed-only |
|---|---|---|---|
| ArrayTest | 110 | 311 (+201) | 164 (+54) |
| MultiDimArrayTest | 10 | 79 (+69) | 73 (+63) |
| ArraysInStructTest | 17 | 79 (+62) | 79 (+62) |
| static-struct | 121 | 179 (+58) | 120 (−1) |
| StructPtrTest | 5 | 38 (+33) | 5 (+0) |
| IntTest | 51 | 82 (+31) | 82 (+31) |
| NestedStructTest | 44 | 73 (+29) | 49 (+5) |
| CoercePointerTest | 35 | 63 (+28) | 35 (+0) |
| small-test, TypedefTest, DisambigTest, SimpleDisambigStructTest, string-arrays, StaticArraysTest | | +2 to +4 each | same |
| crazy-test-1 | 153 | 149 (−4) | 149 (−4) |

Precision rises along with recall. In ArrayTest, for example, typed fields replace
the run's guessed shapes and the output shrinks from 744 to 412 facts while
matching 201 more.

### Reading
- **Struct layouts are where the recall is.** Even the touched-fields-only ceiling
  (+224) is 6× what perfect parameter types bought (+34). The gain comes from:
  - typing the touched fields right (`char*` and `char[N]` as strings, floats,
    signedness);
  - using layouts for globals and arrays of structs.
- **The extra +297 of the full ceiling is untouched fields:** for example
  StructPtrTest's map/tile structs and most of static-struct. No binary-only
  source can know those. They need real struct definitions (headers, debug info
  from a related build).
- **Not covered:**
  - structs passed or returned by value (~370 missed facts);
  - arrays of structs nested inside structs;
  - a single-struct layout on a pointer into an array, which is correctly refuted
    (the object is bigger than the struct).

### Next
Replace the DWARF layouts with ReSym's FieldDecoder predictions (4.8 GB checkpoint)
on Ghidra pseudocode, mapped to the same hint format. Score it against the
touched-fields ceiling (1,479).

## ReSym on Ghidra output (2026-11-10)

Pipeline (no DWARF until scoring):
1. `ghidra_decompile.py`: Ghidra 12.1.4 via REA on `strip --strip-all` copies of
   the suite. It keeps pseudocode and p-code of the 70+ functions the tracer
   reached.
2. `ghidra_to_resym.py`: rewrites the pseudocode into IDA style (`sub_`, `aN`/`vN`,
   `_DWORD`, `__int64`, decimal constants). It writes VarDecoder prompts for the
   48 reached functions with parameters, and FieldDecoder prompts for the 16 that
   access memory through a parameter at constant offsets, keeping each access's
   byte offset and width.
3. `resym_infer.py`: both official checkpoints (Zenodo 13923982, md5-verified),
   CPU, the authors' decoding. About 2–30 s per function here, ~25 min in all.
4. `resym_to_hints.py`:
   - turns the answers into `--type-hints`;
   - pools field predictions across functions by the struct name ReSym predicts;
   - `--filter contradicted|supported` applies `resym_check.judge` on the
     Ghidra p-code.

How good ReSym is on this input (VarDecoder, 81 parameters, DWARF-scored):
- **Pointer vs scalar:** 96.3% right.
- **Type facts:** 69.1% right, against 81.5% on ReSym's own IDA test set.
- **Exact type:** 40.7%, against 57.7% there.
- **Typical misses:**
  - signedness (`Char` → `uint8_t`) and width (`long` → `int`);
  - invented struct names;
  - IntTest's six parameters all wrong (`void*`, `Object*` where the truth is
    `int*`, `float*`, `char*`, ...).
- **FieldDecoder:** answers "not a struct field" for most accesses, and names
  plausible but wrong structs elsewhere (`timeval*` for an `unsigned int *`).

| run (Kvasir suite, tier 10) | ours | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| baseline | 4,934 | 1,255 | 25.4% | 23.2% | 24.2% |
| ReSym VarDecoder types | 4,933 | 1,255 | 25.4% | 23.2% | 24.2% |
| ReSym VarDecoder, only types the code supports | 4,934 | 1,256 | 25.5% | 23.2% | 24.3% |
| **ReSym VarDecoder + FieldDecoder layouts** | 5,027 | **1,254** | 24.9% | 23.1% | 24.0% |
| same, with either evidence filter | 5,027 | 1,254 | 24.9% | 23.1% | 24.0% |
| *DWARF parameter types (ORACLE)* | 4,975 | 1,289 | 25.9% | 23.8% | 24.8% |
| *DWARF via parameters, touched fields (ORACLE)* | 4,937 | 1,295 | 26.2% | 23.9% | 25.0% |
| *DWARF via parameters, full layouts (ORACLE)* | 4,969 | 1,383 | 27.8% | 25.5% | 26.6% |
| *DWARF incl. globals, touched fields (ORACLE)* | 4,580 | 1,490 | 32.5% | 27.5% | 29.8% |
| *DWARF incl. globals, full layouts (ORACLE)* | 4,924 | 1,788 | 36.3% | 33.0% | 34.6% |

- **Soundness:** `audit_soundness.py` finds 0 violations on the ReSym run.
- **Where ReSym's hints went:** the run refuted most of what the model
  claimed.
  - Argument effects: 3 applied, 10 refuted.
  - Struct layouts: 2 applied, 6 refuted, 3 adding no field.

  The +93 extra facts it emits are mostly md5 and TrivialTest fields that
  Kvasir does not report under those names.

### Fixes to the merge made while running ReSym

ReSym's partial and wrong layouts exposed these. Each fix also applies to the
DWARF ceilings above.
- **Arrays of structs.** A struct layout on an object the run typed an array of
  structs types its elements. It no longer replaces the array. This was a
  pointer into `struct foo g[4]`, NestedStructTest −34.
- **Element fit.** It does so only if the layout's fields fit in one element. A
  5-byte "struct" on a byte array is refuted (partial-init −25).
- **Uniform-tiling guess.** A scalar "array" exactly the struct's size is the
  tracer's uniform-tiling guess, not evidence, and the struct wins.
- **Partial layouts.** A partial layout keeps the observed fields it does not
  cover: a hint adds and types fields, never deletes what the run saw.
- **Wrapper only.** A one-field layout at +0 over an object the run read as one
  scalar is ignored ("no new field"). This was `timeval*` for an `unsigned int *`,
  crazy-test-1 −8.

### Reading
- **The mechanism works.** Perfect layouts are worth up to +533 matched facts
  (F1 24.2% → 34.6%). Through parameters alone, the route ReSym can use, they are
  worth +40 (touched fields) to +128 (full).
- **ReSym on Ghidra pseudocode does not deliver them.**
  - Its types are right too rarely: about 69% of facts, and wrong in ways the
    walk cares about (signedness, width, struct vs scalar).
  - The run's refutation, correctly, throws most of them away.
- **Two limits ReSym cannot get past here:**
  - **Globals:** the larger half of the struct ceiling. ReSym's field model
    only sees accesses through a variable.
  - **Out-of-style input:** Ghidra, not IDA.
- **Ways to recover more of the ceiling:** a model trained on Ghidra output, or
  layouts from a source with whole definitions (headers).
