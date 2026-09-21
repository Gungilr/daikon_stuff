# What can be formally verified, and what cannot

A review of the *methods*, not the code. For each inference the tracer makes:
what is its logical status, what would it take to prove it, and what is
unprovable in principle.

For the companion question — where formal reasoning would make the heuristics
**sharper** rather than merely audited — see
[FORMAL-METHODS.md](FORMAL-METHODS.md).

The short version: **the verification burden splits along exactly the same
line as the architecture.** Claims about the observed execution are decidable
and are now checked. Claims about the program are inductive and cannot be
proved from traces at all — which is fine, because refuting those is the
fuzzer's job, not ours.

---

## 1. The load-bearing distinction

Two kinds of statement travel through this pipeline and they have different
epistemic status:

| | claim | status |
|---|---|---|
| **trace** | "at this call, `arg0` held 250" | decidable — check it against the run |
| **invariant** | "`arg0 == 250` at every call, always" | inductive — no finite set of traces establishes it |

The tracer produces the first kind. Daikon produces the second from the first.
**Every defect the tracer can have is of the first kind, and every one of them
is checkable.** Conversely, no amount of rigour on our side makes the second
kind sound: Daikon's output is a set of conjectures, and its soundness is a
category error rather than a missing feature.

This is not a disclaimer. It is the reason the fuzzing loop is the right
consumer: a fuzzer is a refutation engine for exactly the statements we cannot
verify, and it needs the statements we *can* verify to be true.

---

## 2. Classification of every technique in use

### Tier A — sound by construction

These read a specified structure or apply a defined semantics. Nothing is
inferred; being wrong here means having misread a document.

| technique | why it is sound |
|---|---|
| PLT resolution via `.rela.plt` + `ff 25` scan | reads the ELF relocation structure as specified |
| data-section bounds from section headers | reads the section header table |
| global extents from `.symtab` `st_size` | reads a recorded size |
| allocation size from the `malloc` argument | observed directly, not inferred |
| sub-register canonicalization (`edi` -> `rdi`) | an ISA fact |
| ENTER/EXIT pairing by invocation nonce | we issue the nonce ourselves |
| `orig()` left to Daikon, never emitted | a format rule, verified against Kvasir's output |

### Tier B — sound relative to a stated assumption

Valid conditionally. Each names a falsifiable premise, and each premise is a
compiler or ABI convention rather than a law.

| technique | premise | how it breaks |
|---|---|---|
| use-before-def ⇒ caller-supplied | argument registers are caller-saved | reading an uninitialised caller-saved register looks identical |
| arity = highest index + 1 | SysV assigns argument registers in order, no gaps | hand-written asm, non-SysV ABIs |
| spill-slot read at EXIT | the -O0 prologue stores each parameter to a fixed frame offset | -O1+ keeps parameters in registers; no slot exists |
| SSE argument numbering | float args occupy xmm0-7, numbered independently | correct, but the interleaving with integer args is genuinely lost |
| signedness from a consuming opcode | the compiler emits `shr` for unsigned, `sar` for signed | sound *given the compiler is type-correct* — a strong premise |
| stack-argument slots at `[rbp+0x10+8k]` | standard frame layout | `-fomit-frame-pointer` |

**None of these is tested outside -O0.** The corpus is entirely -O0, which
`TOOL.md` already flags as flattering. Compiling the corpus at -O1 and -O2 and
measuring where Tier B degrades is the single cheapest *falsification* experiment
available and has never been run.

### Tier C — heuristic, defeasible even when the premises hold

These can be wrong on conforming input. Each is a deliberate trade and all but
one are documented as such.

| technique | how it can be wrong | mitigation in place |
|---|---|---|
| pointer classification by address range | an integer can land in a mapped region | measured 7/7 on the corpus; tier 4's covariance test was specified and skipped as a measured no-op |
| array vs struct via uniform tiling | necessary, not sufficient — two ints tile exactly as `int[2]` | requires a correlated length argument as a second signal |
| `length * width == allocation` | can coincide | must hold on *every* observed call |
| global boundaries from RIP targets + gaps | two adjacent same-width globals merge | prefers to split; `.symtab` used when present |
| `--infer-unobserved-fields` | guesses the width of memory nothing read | flag-gated, measured separately |
| `--poison-uninitialized` | a genuine `0xABABABAB` reads as `nonsensical` | flag-gated |
| `--infer-from-caller` | invents fields from neighbouring stack locals | flag-gated after measuring -22 precision for +3 recall |
| float width defaults to `double` | a `float` never moved by `movss` | stated |

### Tier D — inductive, unverifiable in principle

Everything Daikon outputs, read as a statement about the program. No finite
trace set establishes a universal. This is not a defect of our tool or of
Daikon; it is what dynamic invariant detection *is*.

---

## 3. What is actually checked today

### Soundness against our own samples — now automated, and it found a bug

The strongest guarantee available to a dynamic front-end: **every fact we emit
must be true of the samples we ourselves recorded.** A violation is
unambiguously our defect — not Daikon over-generalising, not the oracle being
wrong.

Audited across the Kvasir suite at tier 8:

```
facts audited: 4217
  1001  23.7%  TRUE on our own samples
     0   0.0%  FALSE
  3216  76.3%  undecidable by this checker
```

The first run was not clean. It surfaced six violations of the form

```
asserted:  arg8 one of { -6076574518398440533L, 0 }
recorded:  arg8 = 12370169555311111083
```

Same bits — the second is the first read as unsigned. The cause was
`sign_extend` returning 64-bit values unchanged, so the trace carried values at
or above 2^63 for a variable declared `int`, which in Daikon is a **signed**
64-bit long. Daikon wrapped them and the reports came out right, so the defect
was invisible in every previous measurement. **We were depending on unspecified
behaviour of the consumer.** Fixed, with a unit test; 13 values across 3 of 29
binaries were affected, and no golden moved.

That is the argument for this kind of checking in one example: it found
nothing the score could see, because the score was computed from output that
had already been silently corrected downstream.

**The 76% undecidable is the honest limit of the current checker**, not a claim
of correctness. It handles equalities, `one of`, comparisons, `has only one
value` and linear relations; it cannot evaluate sequence predicates
(`contains no nulls`, `is the reverse of`, elementwise forms).

### Emulation fidelity — differential, not proved

198 of 198 program points have **identical sample counts** between our Unicorn
emulation and Kvasir under Valgrind on real hardware, across 29 binaries
including a 1000-iteration loop. That is strong differential evidence that we
execute the same program. It is not a proof: equal call counts do not establish
equal register contents at every point.

A stronger and entirely feasible version exists: compare **every reported
value** against Kvasir's dtrace for the variables both tools name. We compare
*invariants* today; comparing *samples* would test the tracer directly instead
of through Daikon.

### Determinism and regression

Byte-identical output across runs is the phase-0 gate and still holds; golden
files pin tiers 0-6 exactly. These verify *stability*, not correctness — a
consistently wrong tracer passes both.

---

## 4. Where formalization would actually pay

### (a) The scorer's canonicalization is a heuristic, and it should not be

`canonical()` is a string normal form: flip comparisons, sort equality
operands, reduce linear terms by gcd. **Invariant equivalence over linear
arithmetic is decidable**, so this could be a decision procedure rather than a
normalizer that happens to catch the cases we met.

The evidence that it matters is already in hand: **eight bugs found in the
scorer, every one of them one-directional** — each made the tracer look worse.
That asymmetry is the signature of an incomplete normalizer, not of random
error. An incomplete normalizer can only fail to identify two equivalent
forms; it can never wrongly identify two different ones. So the measured
scores are all *lower bounds*, and the true agreement is unknown.

Replacing the linear-equality path with a proper normal form (or an SMT
equivalence check) would turn "P/R/F1 as far as our string matching can tell"
into "P/R/F1, exactly, for the linear fragment." That is the highest-value
formalization available and it is a contained change to one module.

### (b) The output format has an implicit contract

The `sign_extend` defect was a violation of a rule nobody had written down. The
full rule set is small and completely checkable before writing the file:

1. every value is within the range of its declared `rep-type`
2. every `enclosing-var` names a variable declared **earlier** in the same ppt
3. sample length equals declared-variable count
4. `nonsensical` carries modbit 2; everything else carries 1
5. the nonce is a prefix, never a declared variable

Rule 3 already exists — `add_sample` asserts it, added in phase 0 for exactly
this reason, and it is the only one of the five that has never failed. Rule 2's
violation in phase 9 made Daikon **reject entire traces** while producing
8-fact reports that looked like successful runs. Rule 1's violation is the bug
above. A `validate()` pass over the writer's buffer would make all five
structural rather than hoped-for.

### (c) The Tier B premises are untested off -O0

Stated, falsifiable, never falsified — because the corpus cannot falsify them.
Rebuilding at -O1/-O2 turns six assumptions into six measurements.

---

## 5. What cannot be verified, at any effort

- **Names.** Destroyed by stripping. The scorer supplies them from DWARF
  precisely because the tracer never can, and that is the one place DWARF is
  allowed to enter.
- **Completeness.** A dynamic analysis sees executed paths. `pick_first`'s dead
  parameter is invisible by construction, and no technique changes that.
- **That an invariant generalises.** Tier D. Structural.
- **Two same-width types the program never distinguishes.** A `double` never
  loaded as a double is a `long`; an `unsigned` never shifted or compared is an
  `int`. Measured at roughly 5% of the Kvasir oracle. This is a genuine
  information-theoretic residue, not an engineering gap — and it is the only
  part of the remaining 88% miss rate that is.

---

## 6. Summary

| category | share of techniques | verifiable? | status |
|---|---|---|---|
| A — reads a specification | 7 | yes, by inspection | sound |
| B — ABI/compiler premise | 6 | yes, by differential testing at -O1/-O2 | **untested** |
| C — heuristic | 8 | no; only measurable | measured, mostly flag-gated |
| D — inductive output | all invariants | no, in principle | the fuzzer's job |

**What is proved: nothing.** What is *checked*: soundness against recorded
samples (1001 facts, 0 violations, one real defect found), execution fidelity
against real hardware (198/198), determinism, and regression.

The honest characterisation of this tool is a **sound-relative-to-observation
describer feeding an unsound generalizer** — and the second half is intentional,
because the consumer is a refutation engine. The gap worth closing is not
between the tool and a proof; it is between the tool and its own stated
premises, six of which have never been tested outside the compiler setting
they were written for.
