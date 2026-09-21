# Phase 9 — globals (tier 8) and floating point (tier 9)

Status: **complete**. Prerequisite: the Kvasir-suite evaluation, which measured
globals at 80.5% of the oracle and float arguments at 8 nullary functions
out of 8.

## Outcome, on Daikon's own Kvasir test suite

| | tracer facts | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| tier 7 (before) | 1352 | 176 | 13% | 4% | 6% |
| **tier 8 (globals)** | 3576 | **802** | **22%** | **17%** | **19%** |
| tier 9 (+ floats) | 3569 | 799 | 22% | 17% | 19% |

**4.6x more oracle facts matched, and precision rose at the same time** — the
usual sign that the work added description rather than noise.

Per binary, the ones globals unlocked:

| binary | recall before | after |
|---|---|---|
| SelectGlobalsTest | 2% | **87%** (precision 83%, F1 85%) |
| two-statics | 56% | **86%** |
| partial-init | 7% | **63%** |
| static-struct | 2% | **50%** |
| IntTest | 9% | **49%** |
| GlobalTest | 8% | **54%** |
| FloatTest | 1% | 24% (35% at tier 9) |

## Tier 8 — globals

Three signals, in descending order of how much they are trusted:

1. **`.symtab` object symbols**, when the binary is not stripped. Exact address
   AND SIZE, which is the one fact no dynamic signal can recover: an `int[18]`
   and eighteen adjacent `int`s produce identical access evidence. Used exactly
   as function discovery already uses `.symtab`, and `--scan-prologues` forces
   the stripped path for both.
2. **RIP-relative operands**, for a stripped binary. `mov 0x2f3a(%rip),%eax`
   names an object base statically. Finds 6 of 6 on `GlobalTest`, but only 64%
   across the suite — an array touched solely as `arr[5]` yields base+20 and no
   base.
3. **Observed accesses**, keyed by address. Complete for what the run touched,
   silent about boundaries.

Section headers survive `strip --strip-all`, so `.data`/`.bss`/`.rodata` bounds
are always available; that is the haystack, and the three signals find objects
in it. Globals are emitted at **every** program point, matching Kvasir, and
appended after the arguments so no lower-tier golden moves.

### What it gets exactly right

On `IntTest`, after the scorer maps `g_0x404060` to `::globalIntArray`:

```
::globalX == 5
::globalIntArray[] == [1, 2, ..., 18]
size(::globalIntArray[]) == 18
::globalIntArray[::globalX] == 6
::globalIntArray[::globalX-1] == 5
::globalX in ::globalIntArray[]
```

Every line matches Kvasir, including the derived indexed elements, which Daikon
produces on its own once the sequence and the index are both declared.

### Two bugs found while building it

- **`enclosing-var` with no declared enclosing variable.** Declaring
  `g_0x404060[..]` without `g_0x404060` makes Daikon reject the entire trace
  ("enclosing variable cannot be found"), not just that variable. Nine binaries
  produced 8-fact stub reports before this was caught. The pointee path had
  always declared the base; the globals path had to learn the same rule.
- **An 8-byte object with no observed access became `int[2]`.** A guessed
  element width must never turn a machine word into an array: it invents
  `size(g[]) == 2` and reports the two halves of a `double` as integers.
  Width now carries whether it was OBSERVED, and a guess cannot create an array.

## Tier 9 — floating point

`float mul(float a, float b)` reported **arity 0**, because SysV passes float
and double in `xmm0`-`xmm7` and the detector only watched the six integer
registers. Tier 9 adds a parallel `SSE_ARG_ORDER`, takes the element width from
the mnemonic (`movss` = 4 bytes, `movsd` = 8, since `xmm0` is 128 bits either
way), and reads the spill slot at EXIT — xmm0 holds the RESULT by then, so
without that every float function reported `arg0 == return`, the exact bug the
integer arguments had.

**It is a genuine trade, which is why it is a separate tier:**

```
FloatTest        recall 24% -> 35%   (+9 facts)
everything else  -12 facts
```

The loss is the **argument ORDER of a mixed list**. The ABI numbers integer and
SSE arguments independently, and nothing in the machine code records how they
interleaved in the source: for `f(double a, int b)` both values are recovered
correctly and assigned to the wrong names. Integer-first is a convention, not a
recovery. Off by default for that reason.

## Still not recovered

- **A global's TYPE.** A `double[5]` global is reported as five 8-byte integers,
  because nothing distinguishes it from a `long[5]` without DWARF. This is why
  `FloatTest` and `crazy-test-1` stay low.
- **Struct-shaped globals** are emitted as `.offK` fields rather than named
  members, the same wrong-noun problem as struct pointees.
- **Strings.** A `char*` global is a pointer value; Kvasir reports the text.
