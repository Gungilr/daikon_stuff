# TypeForge and retypd as tracer hints (2026-11-18)

Status: **measured — both ±0 on the Kvasir suite.** Follows `struct-hints.md`
(ReSym ±0, and the DWARF ceilings).

## Why these two

ReSym reads one function at a time. The single biggest reachable gain on the suite
is a pointer passed into a function that never dereferences it (IntTest's `u`,
+28 of the +33 parameter-type facts). Its type is visible only in the caller, so
the next tools tried are ones that reason **across functions**:
- **TypeForge** (IEEE S&P 2025, `noobone123/TypeForge`, BSD-3). A Ghidra extension
  with two phases:
  - phase 1, program analysis: an inter-procedural type-flow graph that
    synthesises struct layouts;
  - phase 2, optional: LLM refinement of the layouts it marks ambiguous.

  Only phase 1 was run here.
- **retypd** (GrammaTech, `GrammaTech/retypd` + `retypd-ghidra-plugin`, GPL-3). A
  type-constraint solver over the whole program, no learning. The plugin
  generates constraints from Ghidra's high p-code; the Python package solves them.

## Getting them to run (all local, no API)

- **Ghidra 11.0.3** next to 12.1.4. TypeForge was tested on 11.0.3; the retypd
  plugin built cleanly against it too, rather than GrammaTech's own Ghidra fork,
  which its CI builds from source.
- **Gradle 8.5.** TypeForge's `build.gradle` asks for a Java 25 toolchain;
  pinned to 21.
- **TypeForge fixes:**
  - `TypeForge.java` never set `Global.outputDirectory`, which only the
    ground-truth script set, and crashed with a NullPointerException in
    `ReTyper.prepare`. Fixed in our copy with one line.
  - It needs `main` by name and, headless, needs `main_name=main`, so binaries
    are `strip --strip-debug`ged: DWARF removed, symbol table kept, which the
    tracer reads too.
- **retypd fixes:**
  - Both `setup.py` files import `imp`, which was removed in Python 3.12;
    patched to `importlib`.
  - `solver.py` uses a mutable dataclass default, which Python ≥ 3.11 rejects;
    patched to `default_factory`.
  - Installed in its own venv. retypd's 147 tests pass after the patches.

Scripts:
- `scripts/rea_eval/typeforge_run.py` → `typeforge_to_hints.py`;
- `scripts/rea_eval/retypd_run.py` → `retypd_to_hints.py`.

Both tools run in about 6–7 s per suite program.

## Feeding them in

Both mostly produce layouts whose fields have a width but no type: TypeForge's
`dword`/`qword`, retypd's `char1_t[4]`. A new hint field kind, **`unknown`**,
carries that.
- **If the run saw a field** with exactly that offset and width, the field takes
  the run's kind.
- **Otherwise** it is width-only and never printed.
- **It cannot refute** a layout, and does not hide observed fields that overlap
  it.

Also new: an optional `"refute": "field"` hint-file mode. A kind clash then drops
only the contradicted field, where the default rejects the whole layout. It was
tried as a variant because one wrong field threw away TypeForge's otherwise good
`TestBuffer` layout.

## Results

| run (Kvasir suite, tier 10) | ours | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| baseline | 4,934 | 1,255 | 25.4% | 23.2% | 24.2% |
| TypeForge layouts | 4,934 | 1,255 | 25.4% | 23.2% | 24.2% |
| TypeForge, per-field refutation | 4,938 | 1,255 | 25.4% | 23.2% | 24.2% |
| retypd types + layouts | 4,952 | 1,255 | 25.3% | 23.2% | 24.2% |
| retypd, per-field refutation | 4,952 | 1,255 | 25.3% | 23.2% | 24.2% |
| *ReSym (struct-hints.md)* | 5,027 | 1,254 | 24.9% | 23.1% | 24.0% |
| *DWARF via parameters, touched fields (ORACLE)* | 4,937 | 1,295 | 26.2% | 23.9% | 25.0% |
| *DWARF via parameters, full layouts (ORACLE)* | 4,969 | 1,383 | 27.8% | 25.5% | 26.6% |

`audit_soundness.py`: 0 violations on both TypeForge and retypd runs.

### What each produced

**TypeForge:**
- **Layouts:** 13 final struct layouts and 7 ambiguous ones (left out), in 10 of
  30 programs.
- **Some are good:**
  - DisambigTest's `TestBuffer` (`int*` at 0, `char*` fields at 32–56, two
    `char` at 64/65), linked across functions from `main`'s local to
    `fooMultiple`'s parameter;
  - SimpleDisambigStructTest's `Buffer`, linked the same way.
- **Others are not:** small-test's `node` came out as two different layouts for
  the same struct.
- **Weakly typed:** 39 of 54 fields are untyped, and 1 is a `char*`.
- **Few reach the tracer:** most layouts are attached to locals (`main`'s heap
  pointers), so only **3 parameters** get one.
  - 2 were refuted by the run, both for real errors: field +8 typed `long` where
    the truth is `int*` (DisambigTest), and a `void*` where the truth is
    `char[16]` (SimpleDisambigStructTest).
  - With per-field refutation all 3 apply and change nothing.

**retypd:**
- **Layouts:** 28 struct layouts. 12 parameters get one and 5 get a
  pointer-to-scalar type.
  - Struct layouts: 7 applied, 3 refuted, 5 conflicting.
  - Pointer-to-scalar types: 1 applied, 5 refuted.
- **Mostly untyped:** fields are mostly `char1_t[k]` (untyped bytes).
- **IntTest's `returnIntSum`:** `u` comes out `char1_t[4]` (truth `int*`), `a`
  `int64_t` (truth `float*`), `str` `char1_t[4]*` (truth `char*`); only `b`
  (`float8_t**`, truth `double**`) is right.
- **Why `u` fails:** the generated constraints do carry `main`'s argument into
  `returnIntSum.in_0`, but that argument's type variable has no constraints. The
  array is on `main`'s stack, and the plugin's constraint generator does not
  model stack memory or address-taken locals. The one fact retypd was chosen for
  never reaches its solver.

## Reading

- **Static analysis of `-O0` test programs sees nothing the run does not.**
  - Both tools learn layouts from the accesses in the code, and on this suite
    every access executes, so the tracer has already recovered those offsets and
    widths (layout F1 89.7%).
  - What a static tool could add is field types. Both leave most fields untyped,
    and their typed fields include real errors the run correctly refutes.
- **Cross-function reasoning is the right idea; these implementations miss the
  case that matters.**
  - TypeForge links a struct across functions only when a parameter is used.
  - retypd's Ghidra front end drops the stack-memory flow that would type a
    passed-but-unused pointer.
- **Where they could still help:** real programs with code the run does not
  reach (error paths, other inputs). Static layouts there would add fields the
  run never saw. This suite cannot show that; it needs a corpus with low
  coverage, and its own oracle.
- **The gap left on the suite is untouched fields and untyped bytes.** The
  DWARF-through-parameters ceiling (+40 touched, +128 full) is not reached by
  any binary-only source tried: ReSym, TypeForge or retypd.
