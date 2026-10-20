# Implementation plans

Tiered plan for closing the gap between the black-box tracer and Kvasir
ground truth. Each tier is independently measurable; the per-tier P/R/F1 curve
is the research output.

| Phase | Tier | Content | Status |
|---|---|---|---|
| [phase0.md](phase0.md) | — | Package refactor + pytest harness | **complete** |
| [phase1.md](phase1.md) | 1 | Structural alignment (`subexit`, `EXIT0`, nonce) | **complete** |
| [phase2.md](phase2.md) | 2 | Arity via use-before-def | **complete** |
| [phase3.md](phase3.md) | 3 | Return value, **signed-value fidelity**, comparability | **complete** |
| ~~phase4~~ | 4 | Covariance pointer classification | **skipped** — measured no-op |
| [phase5.md](phase5.md) | 5 | Allocator model (malloc/free) | **complete** |
| [phase6.md](phase6.md) | 6 | Struct recovery via dereference | **complete** |
| [phase7.md](phase7.md) | 7 | Array bounds from allocation size | **complete** |
| [review-2026-09-17.md](review-2026-09-17.md) | — | Bug/blindspot review after the ladder | **4 bugs fixed** |
| [phase8.md](phase8.md) | — | Recovering the 28 missed facts | **complete** — F1 69% → 76% |
| [../EVALUATION.md](../EVALUATION.md) | — | Scoring harness + results (P/R/F1 vs Kvasir) | **built** — 8 bugs found in it |
| [../EVALUATION-KVASIR-SUITE.md](../EVALUATION-KVASIR-SUITE.md) | — | Same tool on Daikon's own test suite | **13/4/6** — globals are 80% of it |
| [phase9.md](phase9.md) | 8, 9 | Global variables; floating point | **complete** — suite F1 6% → **19%** |
| [phase10.md](phase10.md) | — | Globals as deref roots; struct globals | **B landed (opt-in), C measured harmful**; A/D/E not started |
| [../VERIFICATION.md](../VERIFICATION.md) | — | What can be formally verified, and what cannot | **reviewed** — 1 defect found |
| [../FORMAL-METHODS.md](../FORMAL-METHODS.md) | — | Formal methods layered on the heuristics | **reviewed** — 0/72 shapes are forced by the evidence |
| [../FUZZ-LOOP.md](../FUZZ-LOOP.md) | — | Daikon + fuzzer loop; Kvasir front-end, and the tracer on stripped binaries (`--frontend tracer`) | **working** — tracer input mechanism via `--fuzz-batch` |

Tier 4 was skipped after measurement, and re-measured after tier 5 landed: the
range-based classifier in `memmap.py` now gets **7 of 7** pointers right
(the heap pair joined the original five) and misclassifies none of the 118
declared variables. Covariance classification still has no acceptance criterion
that fails. Revisit only if a fixture makes the range test demonstrably wrong.

The tier ladder now runs to 9, with tier 10 planned. Tiers 8 and 9 were added after the Kvasir-suite
evaluation showed the ladder had been built against a corpus that could not
exercise them. Current standing
against the oracle: **precision 65%, recall 92%, F1 76%**, with eight of ten
binaries at 100% recall.

The black-box tracer is now plugged into the fuzzing loop
(`--frontend tracer`, which uses the tracer's new `--fuzz-batch` input mode).
The loop exists for source-available targets too
([../FUZZ-LOOP.md](../FUZZ-LOOP.md)): it uses Kvasir as the front-end, has
an input mechanism (a batch harness that runs hundreds of inputs per process),
and costs about a second of Valgrind start-up per batch rather than per
input. In tracer mode, emulation costs about 15-33ms per input (tier 3 to
tier 7) plus ~2s of start-up per batch. There are also two measurement-driven items:
bounding a stack pointee so `--infer-from-caller` can be safe enough to default
on, and real modbits, which is where the remaining precision headroom is.

## Invariants of the whole effort

- **Tier 0 output never changes.** `tests_py/golden/test08.tier0.dtrace` is the
  frozen baseline every tier is measured against. All tiers are opt-in via
  `--tier`.
- **DWARF is read only at scoring time**, purely to align names, and never
  flows back into the tracer's inputs.
- **Do not emit stack locals.** Kvasir reports parameters, pointee views,
  `return` **and globals** — `main:::ENTER` has zero LOCALS despite four live
  ones. Every local emitted is a pure false positive. (`CONTEXT.md` task #1 is
  wrong on this point.)
  **Corrected 2026-09-17:** this used to say Kvasir reports parameters,
  pointees and `return` *only*. It reports globals too, and on Daikon's own
  test suite they are **80% of everything it says**. The claim survived because
  no fixture in `tests/` has a global. Tier 8 now emits globals, worth 4.6x the
  matched facts on that suite — see
  [../EVALUATION-KVASIR-SUITE.md](../EVALUATION-KVASIR-SUITE.md).
- **Recall FALLS at tier 2 and does not recover until tier 6.** Measured, not
  predicted: tiers 0-1 encoded two real pointee facts by accident, via machine
  slots that happened to overlap the caller's frame. Tier 2 correctly prunes
  those slots and destroys the accidental signal with them. Expect a dip in the
  curve, and do not treat it as a regression. Recall should never *climb* at
  tiers 1-3 — no pointee fact is legitimately reachable before dereference.

## Correctness issues found in the phase-5 retrospective (BOTH FIXED)

Both were found by checking *content* rather than counts, and both had been
invisible because the comparison was count-based.

### 1. `flags is_param` makes Daikon report FALSE invariants — FIXED

Reproduced on a synthetic trace with `return = 2a + 1`:

| declaration | Daikon output |
|---|---|
| without `is_param` | `2 * a - return + 1 == 0` — correct |
| with `is_param` | `return - orig(a) - 1 == 0` — **false on the same data** |

Kvasir sets `is_param` on every parameter, and tier 3 copied it, so **both
sides are affected**. On `test09`'s `skip_middle` the oracle reports two
invariants that are false on its own samples and that contradict each other.

Refined: the bug manifests only when the true linear relation has a
**non-unit coefficient**. `sum(num) = num + 1` (coefficient 1) is reported
correctly by Kvasir; `skip_middle` returning `2a + 1` loses the 2, and
`trailing_dead` returning `2a` is suppressed entirely.

**Resolved in favour of correctness: tier 3+ no longer sets the flag.** The
consumer is a fuzzing loop, and a fuzzer can disprove a bad invariant but
cannot recover one that was never emitted. Our output now diverges from the
oracle and agrees with reality - on `test09` we report `2 * arg0 - return + 1
== 0` (true) where Kvasir reports `return - orig(a) - 1 == 0` (false on all six
of its own samples), and we report `trailing_dead`'s relation where Kvasir
reports nothing at all.

**Cost:** invariant counts roughly doubled (test10: 14 -> 37), because the flag
was also suppressing a large class of TRUE but trivial facts - `argN ==
orig(argN)` restated at every exit. Those are sound, so they are safe for a
fuzzer, merely redundant. Suppressing them *without* inheriting the coefficient
bug is open work: real modbits (CONTEXT.md task 4, still unimplemented) are the
obvious candidate, since the tracer currently hardcodes every modbit to 1.

### 2. Argument values at EXIT are read from clobbered registers — FIXED

The tracer re-reads argument registers at EXIT, but they are caller-saved and
the function body reuses them. In `skip_middle(a, b, c)`, gcc -O0 emits
`mov -0x4(%rbp),%edx`, so at `ret` the third argument register holds `a`:

```
kvasir (reads the DWARF storage location):  a=0 c=1   a=1 c=2   a=2 c=3
ours   (re-reads rdx):                      arg0=0 arg2=0   arg0=1 arg2=1
```

`orig(argN)` comes from the ENTER sample and was fine; **`argN` at EXIT was
unreliable for any register the body reuses**, manufacturing artifacts such as
`arg0 == arg2`. No input disproves those - the clobber is deterministic - so
they were permanent noise rather than the underscoped kind a fuzzer corrects.

**Fixed.** The tracer now records each argument's prologue spill offset and
reads the slot at EXIT. The frame base is computed at ENTER as `rsp - 8`
(where the standard -O0 prologue will put rbp) rather than read at `ret`,
because by then the epilogue has restored rbp to the CALLER's frame - the slot
memory itself is still intact. `skip_middle` now reports `arg0=0 arg2=1`,
matching Kvasir exactly, where it previously reported `arg0=0 arg2=0`.
