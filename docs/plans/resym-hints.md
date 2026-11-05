# Plan — ReSym parameter types as tracer hints, checked against the run

Status: **planned.** Builds on `docs/RESYM-LOCAL.md` and `docs/plans/resym-rerank.md`.

## Idea

1. ReSym proposes a type for each parameter.
2. The binary's evidence drops the proposals it contradicts. This is the filter
   measured in `RESYM-LOCAL.md`: 81.5% → 84.8% facts right.
3. For the parameters where sources still disagree ("contested"), the tracer
   tries every surviving type and keeps one only when the run rules out all the
   others.
4. The hope: more invariants that match Kvasir, with no invented facts.

**Why one run is enough, not one trace per hypothesis.** A type does not change
how the program executes, only how the tracer reads memory at each program
point. So one run can test every candidate type for every argument at once.
Running the program N times would give the same result at N times the cost.
The hint file therefore lists candidates per argument, and the tracer decides
which, if any, to apply.

## Step 0 — ceiling (done before writing this plan)

How many of Kvasir's facts that tier 10 misses could a parameter or return type
fix at all? Done by hand-built classification
(`scripts/rea_eval/hint_ceiling.py`).
The suite has 5,419 oracle facts; tier 10 matches 1,256 and misses 4,163.

| missed facts | count | fixable by a parameter type? |
|---|---|---|
| about globals | 3,396 | no: ReSym types parameters only |
| struct field layouts (`f.char_10`, `m[].mapName`) | 411 | no: needs field types (FieldDecoder) |
| float/int parameter order (`initBasicTypesStruct`, `doubleAdd`) | 184 | **no, by anyone**: machine code does not record how int and float parameters interleave |
| scalar-pointee arrays (`u[]`, `a[]` in IntTest) | ~46 | **yes** |
| `char*` as a string (`str`, `s`) | 13 | **yes** |
| `char**` / `char***` chains (`argv[]`, `dummy[][0]`) | ~25 | yes, harder |
| other | ~90 | mostly no |

**Ceiling: about 60–85 facts, i.e. +1.1 to +1.6 recall points (23.2% → ~24.8%),
even with perfect types.** This is stated up front: the best case is small.

## Step 1 — `--type-hints FILE` in the tracer (flag-gated)

File: `{"functions": {"0x401136": {"args": {"0": [TYPE, ...]}, "return": [TYPE, ...]}}}`.
- The key is the tracer's integer-class argument index (`argN`).
- The value is a list of **candidate** types.
- `TYPE = {"kind": "pointer", "pointee": {"kind": "char|int|float|struct|pointer|void", "size": n, "signed": b}}`
  or a scalar `{"kind": "int", "size": n, "signed": b}`.

Effects, all only with the flag:
- **E1, string.** Candidate `char*`, slot classified POINTER (or always 0):
  - declare `argN` as `char*` / `java.lang.String`;
  - capture the NUL-terminated bytes at sample time;
  - value is the string, or `null` for 0.
- **E2, scalar-pointee array.** Candidate `T*`, T an int or float of width w,
  slot POINTER:
  - emit `argN[..]` as `T[]` (stride w, elements up to the captured object's
    extent and definedness), Kvasir's `u[..]`;
  - this replaces the walk's output only when that output is absent, or is a
    struct whose only field is at offset 0 with width w (`a[].off0`).

Refutation by the run. A candidate is refuted when:
- **E1:** any non-null value does not point at a printable, NUL-terminated run
  (≥ 1 char, ≤ 4096 bytes).
- **E2:** the run typed the pointee a struct with ≥ 2 fields, or with any field
  whose width ≠ w.
- **Kind:** the slot's own classification contradicts the candidate's kind. A
  pointer candidate whose slot held a non-zero non-address is refuted. A scalar
  candidate is refuted by an address-valued slot, which here just means no
  effect.

Selection per argument:
- Drop refuted candidates, then group the survivors by effect (E1 / E2-with-w,
  kind, sign / none).
- **Apply an effect only if all survivors agree on it.**
- Otherwise abstain (no change), and log `hint contested`.

Gates:
- Goldens are byte-identical without the flag.
- Unit tests for E1, E2, refutation and contested-abstain.
- `pytest tests_py` passes.

## Step 2 — oracle ceiling, measured (a gate, never a result)

- Hints from DWARF: one candidate per argument, the true type.
- Run the suite at tier 10 with the usual flags plus `--type-hints`, and score.
- This measures what Step 1 can buy with perfect types. DWARF is used only
  to make the hint file, and the run is labelled ORACLE everywhere. It is a
  ceiling, as the static-layouts and Kvasir comparisons are.

**Gate (set after the Step 0 estimate):**
- at least +40 matched facts over 1,256;
- precision at least 25%;
- Daikon exits 0 on every program;
- `audit_soundness.py` finds 0 false facts.

If this fails, **stop**: perfect types are not worth the rest.

## Step 3 — ReSym on the suite

1. **Evidence.** `collect_pcode.py` on the stripped suite binaries: Ghidra high
   p-code and pseudocode, about 37 s per binary.
2. **Prompts.** Convert Ghidra pseudocode to ReSym's IDA-style prompt
   (`scripts/rea_eval/ghidra_to_resym.py`):
   - `FUN_00401136` → `sub_401136`;
   - `param_N` → `aN`;
   - locals → `vN`;
   - Ghidra types → IDA spellings (`undefined8` → `__int64`, `long` →
     `__int64`, `char *` → `char *`);
   - ask about the parameters only.

   This is out of ReSym's training style, and that is part of what gets measured.
3. **Run.** VarDecoder with 4 candidates, only on functions the tracer reaches
   (ENTER program points at tier 10).
4. **Score.** Parameter type facts right and exact against DWARF, with the
   same scorer as `RESYM-LOCAL.md`.

## Step 4 — hint file from ReSym

Per integer-class argument:
- **Candidates:** ReSym's 4 beam types, minus those contradicted by binary
  evidence. That evidence is the static p-code rules from `resym_check.judge`
  plus the trace's T-ptr rule.
- **Mapping:** ReSym's `aN` maps to the tracer's `argK` by order among the
  non-float parameters, as in `static_layouts.raw_indices`.
- **Contested:** the survivors disagree on effect. The tracer's run-time
  refutation then decides, or the argument abstains.

## Step 5 — measure

Suite at tier 10, with the usual flags, against these baselines:

| | matched | precision | recall | F1 |
|---|---|---|---|---|
| tier 10 baseline | 1,256 | 25.5% | 23.2% | 24.3% |
| + ReSym hints, top candidate only, no checks | | | | |
| + ReSym hints, evidence filter + run refutation (the method) | | | | |
| + DWARF hints (ORACLE ceiling) | | | | |

Also report:
- `audit_soundness.py` false facts, which must stay 0;
- how many arguments were hinted, contested and abstained;
- overhead: tracer time with and without hints, and ReSym CPU time.

**Success:** the method row
- gains at least +20 matched;
- keeps precision at or above 25.0%;
- has 0 false facts and 0 Daikon failures.

## Step 6 — write-up

- Results go in `docs/RESYM-LOCAL.md` and in this file's Results section.
- Add a row to `docs/plans/README.md`.
- Commit and push. Data stays in `bench/`.

## What this will not do

- Fix globals (82% of what is missed) or struct field layouts: those need
  ReSym's FieldDecoder or other work.
- Fix float/int parameter order, which no binary-only tool can.
- Use DWARF for anything but scoring and the labelled ORACLE ceiling.

## Overhead (expected)

- **Tracer:** one run, as now, plus string capture for hinted arguments. Near 1×.
- **ReSym:** about 20–90 s per reached function on this CPU, tens of minutes
  for the suite.
- **Ghidra:** about 37 s per binary, once.
