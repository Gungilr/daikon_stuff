# Phase 3 — Tier 3: return value, value fidelity, comparability

Status: **complete**. Prerequisite: Phase 2 (complete).

## Outcome

| binary | tier 0 | tier 3 | Kvasir | |
|---|---|---|---|---|
| test02 | 148 | **7** | 7 | parity |
| test03 | 62 | **2** | 2 | parity |
| test11 | 69 | **2** | 2 | parity |
| test09 | 126 | 7 | 8 | under by 1 |
| test10 | 95 | 13 | 14 | under by 1 |
| test07 | 189 | 22 | 15 | over by 7 |
| test12 | 173 | 10 | 17 | under by 7 |
| test08 | 176 | 3 | 37 | under by 34 (dereference gap) |

209 tests pass; all three lower-tier goldens byte-identical; `./test.sh` at 0
failures on 16 binaries.

**Content parity, not just count parity.** On the scalar programs the facts are
Kvasir's, differing only in the parameter name that stripping destroys:

```
test03  kvasir:  return - orig(num) - 1 == 0      tier 3:  return - orig(arg0) - 1 == 0
test02  kvasir:  return - orig(a) - 5 == 0        tier 3:  return - orig(arg0) - 5 == 0
        kvasir:  return >= orig(b)                tier 3:  return >= orig(arg1)
```

And `..main():::EXIT / return == 0` is now **textually identical** to Kvasir -
the first exact agreement in the project.

The corpus has split into two clean regimes: **scalar code is at parity**, and
**pointer code (test08) is blocked entirely on dereference** - 3 facts against
37, with the missing 34 all about the pointee. No tier below 6 will move it.

### Corrections found during implementation

- `returns_value()` defaulted to False, which dropped `return` everywhere and
  would have classified `main` as void - deleting the one exact Kvasir match.
  Absence of an observed caller is not evidence of void; the default is now
  True unless call sites were seen and none consumed rax.
- `classify_slot` was written to take raw values while the caller passed
  verdicts. Verdicts are correct - classification must happen while the
  layout's memory map is live, since `--layouts` relocates the stack - so the
  aggregation was fixed, not the call site. Now an O(1) running AND.
- `emulate.py` is CRLF while the rest of the tree is LF. Multi-line patches
  silently matched nothing until the patcher normalized line endings; this also
  explains the earlier silent no-op in phase 1.

## Purpose

Tier 2 got the right *set* of variables. Tier 3 gives them the right *roles* and
the right *values*.

The master plan framed this phase as "return value + comparability". Measurement
moved the centre of gravity: comparability turns out to be worth little now,
and a value-encoding defect that nothing in the corpus can see turns out to be
worth a great deal.

---

## Corrections to the master plan

### 1. The tracer reports negative integers as huge positive ones

The most consequential finding in the phase, and it has been present since
tier 0. For `int negate(int x) { return -x; }`:

```
Kvasir (ground truth):   return = -1  -2  -3  -4  -5
Tracer:                  rax = 4294967295  4294967294  4294967293 ...
```

An `int` lives in the low 32 bits of a 64-bit register. Writes to `eax`
zero-extend, so `rax` holds `0x00000000FFFFFFFF` for `-1`. The tracer reads the
full 64-bit register and reports 4294967295.

This is not cosmetic. Daikon infers `rax > 0` where the truth is `return < 0`;
every invariant touching a negative integer is wrong, not merely differently
phrased. It affects **arguments as much as return values** — an `int` argument
of -1 in `rdi` reads back as 4294967295 too.

**It is invisible in the current corpus**: a scan of every baseline `.dtrace`
finds *zero* negative values. Every fixture uses non-negative loop counters.
The defect has been latent through tiers 0-2 and would have stayed latent.

The width needed to fix it is already observable — tier 2 sees whether an
instruction names `edi` or `rdi`, and `canonical_reg` currently discards exactly
that information.

### 2. Comparability's value was largely consumed by tier 2

The master plan treated comparability as a major lever, sized against tier 0's
11 mutually-comparable variables (~55 candidate pairs per ppt). After tier 2 a
program point carries 2-3 variables. Of the 17 surviving invariants on test08,
type-based pruning removes roughly **four**:

```
..heap_read():::EXIT    rax >= arg0        int vs pointer
..stack_read():::EXIT   rax < arg0         int vs pointer
..heap_read():::EXIT    arg0 == orig(rax)  pointer vs int
..stack_read():::EXIT   arg0 == orig(rax)  pointer vs int
```

Still worth doing, and still the correct model — Kvasir puts `p` in class 1 and
`return` in class 3, so it never compares them either. But it is a tidying pass
now, not the headline. Note two of those four disappear anyway once `rax` leaves
ENTER, since `orig(rax)` ceases to exist.

### 3. Width masking from the callee's last write is a no-op at -O0

The plan specified masking the return by the sub-register last written before
`ret`. Measured, gcc -O0 never leaves a narrow write there:

```
ret_char:   and $0x7f,%eax      <- 32-bit, despite returning char
ret_short:  add %edx,%eax       <- 32-bit, despite returning short
ret_long:   add %rax,%rax       <- 64-bit
ret_ptr:    mov -0x8(%rbp),%rax <- 64-bit
```

Narrow types are computed in `eax` and truncated by the *caller*. So the
callee-side signal only ever distinguishes 32 from 64 — which is exactly what
correction 1 needs, and nothing more.

### 4. Return type is better read from the caller's consumption

The caller's first use of the result names the type precisely:

```
call ret_char ; movsbl %al,%ebx     <- sign-extend byte  => signed char
call ret_int  ; add   %eax,%ebx     <- 32-bit use        => int
```

`movsbl`/`movswl`/`movzbl` give width *and* signedness, which the callee side
cannot. This is a strictly better signal than the plan's callee-side heuristic,
and it shares its machinery with void detection (correction 5).

### 5. Void detection works as planned

```
call set_it  ; mov $0x3,%edi     <- rax never read  => void
call ret_int ; add %eax,%ebx     <- rax read        => non-void
```

"Does any caller read `rax` before writing it, after the call" cleanly separates
the two.

---

## Design

### A. Signed-value fidelity (new, highest priority)

Record the **observed access width** per slot alongside the arity evidence:

- `infer.py` gains `slot_width(func_addr, slot) -> 32 | 64`, fed from the same
  `regs_access()` stream tier 2 already consumes. `edi` ⇒ 32, `rdi` ⇒ 64. Widest
  observation wins, so a slot used both ways is treated as 64-bit.
- At sample time, a 32-bit slot is truncated to its low 32 bits and
  **sign-extended**: `v = (v & 0xFFFFFFFF); v -= 1 << 32 if v >> 31 else 0`.
- Same treatment for `return`, using the callee's last-write width.

**Signedness is a genuine ambiguity.** Nothing dynamic distinguishes `int` from
`unsigned int` with the high bit set; sign-extending is right for `int` and
wrong for large `unsigned`. `int` is overwhelmingly the common case, so it is
the better default, and the caller's `movzbl`-vs-`movsbl` evidence (correction
4) can refine it later. Record the choice as a known limitation rather than
hiding it.

### B. Return value

- `rax` is **removed from ENTER** — it holds caller residue there, and Kvasir
  declares no `return` at entry.
- At EXIT it is declared as `return`, sign-corrected per A.
- Void functions omit `return` entirely, behind `--detect-void` so the effect is
  separately measurable. Detection reuses the caller-side scan.
- `orig(return)` will not appear, because Daikon derives `orig()` only for
  variables present at ENTER. That is correct and matches Kvasir.

### C. Comparability

- `memmap.py`: `MemoryMap.classify(value) -> "pointer" | "scalar"`, a range test
  over the PT_LOAD segments and `[stack_base, stack_base+stack_size)` the
  Tracer already computes in `_setup_memory`.
- A slot classified as a pointer in **every** sample gets `rep-type hashcode`;
  otherwise `int`.
- Header switches to `var-comparability implicit`; classes are assigned per ppt,
  numbering distinct inferred types in declaration order.
- **`return` must share a class with same-typed arguments.** In Kvasir's decls
  `return` and the int fields are both class 3, and that is precisely what
  yields the `p[].a elements <= return` family at tier 6. Splitting them would
  silently delete the most valuable invariants later.

Note the `malloc` stub makes every heap pointer null, so `heap_read`'s argument
classifies as *scalar*, not pointer. A consequence of tier 5 not existing yet,
not a classifier bug — assert it, so it changes visibly when tier 5 lands.

---

## Issues, ranked by how quietly they fail

**Issue A — sign-extending an `unsigned`.** A large `unsigned` reads back
negative. Wrong in the opposite direction from today's bug, and equally silent.
*Mitigation:* fixture covering both; document the default; revisit with
`movzx`/`movsx` evidence if the corpus grows unsigned-heavy code.

**Issue B — widening the wrong slot.** If a 32-bit argument is observed once as
`rdi` (say, a `mov %rdi,%rax` spill of the whole register), widest-wins marks it
64-bit and the sign fix is skipped. *Mitigation:* prefer the width observed at
the *first* read; test with a function that both uses and forwards an argument.

**Issue C — comparability collapsing everything into one class.** If the
classifier returns "scalar" for every slot, `implicit` comparability becomes a
no-op and nothing is pruned — output looks unchanged and nothing errors.
*Mitigation:* assert `stack_read`'s `arg0` is classified pointer and that
`return < arg0` disappears.

**Issue D — `return` split from its arguments.** Costs nothing today (no int
arguments share a ppt with a same-typed return in the corpus) and everything at
tier 6. *Mitigation:* a direct unit test on the class assignment, not an
end-to-end one, since the effect is not yet observable.

**Issue E — tier 0/1/2 drift.** Three goldens now. *Mitigation:* all three
checked on every change; add `test08.tier2.dtrace`.

---

## Test plan

### New fixture — `tests/test12.c`
The corpus cannot currently see correction 1. Needs: a function returning
negative `int`; one taking a negative `int` argument; an `unsigned` returning a
high-bit value (Issue A); a `void` function; a pointer-returning function.

### Unit — `tests_py/test_value_fidelity.py` (pure)
- sign-extension: `0xFFFFFFFF` at width 32 ⇒ `-1`; at width 64 ⇒ unchanged.
- `0x7FFFFFFF` ⇒ `2147483647` (no spurious flip).
- 64-bit pointer-looking values pass through untouched.
- widest-wins width accumulation, and the Issue B first-read variant.

### Unit — `tests_py/test_memmap.py` (pure)
Boundary cases: first and last byte of each region, one byte outside, null,
unmapped.

### Unit — `tests_py/test_comparability.py` (pure)
- same inferred type ⇒ same class; different ⇒ different.
- **`return` shares a class with same-typed arguments** (Issue D).
- header is `implicit`.

### E2E — `tests_py/test_e2e_tier3.py`
- three goldens byte-identical.
- `negate` reports `return == -x`, matching Kvasir's sign (correction 1).
- `main:::EXIT` reports `return == 0` — an **exact textual match** with Kvasir's
  `..main():::EXIT / return == 0`, the first one the project will have.
- `rax` absent from every ENTER; `main:::ENTER` genuinely empty.
- `return < arg0` and `arg0 == orig(rax)` gone (correction 2).
- void function declares no `return` under `--detect-void`.
- `heap_read`'s argument classifies scalar while the stub nulls it (pin, not guard).

---

## Acceptance

- All three lower-tier goldens byte-identical; `./test.sh` at 0 failures.
- Negative values match Kvasir's sign and magnitude.
- test08 invariant count falls from 17 to roughly 6-8.
- **At least one invariant matches Kvasir exactly** (`return == 0` at
  `main:::EXIT`). NOTE: measured after phase 2, tier 2 ALREADY recovers Kvasir's
  facts structurally on every scalar program (`rax - arg0 - 5 == 0` vs
  `return - orig(a) - 5 == 0`). What tier 3 adds is NAME alignment, not the
  first recall - the earlier claim that tiers 0-2 matched nothing was wrong.
- Recall does not fall further. Tier 2's dip came from pruning slots that
  accidentally held pointee data; tier 3 prunes no slots, so a drop here means
  something is wrong.

## Carried into Phase 4

- The scorer can finally align on `return`, which both sides now name identically.
- Sign correctness is a precondition for scoring: comparing `4294967295` against
  `-1` would count a correct fact as a miss.
- `MemoryMap.classify` is the cheap half of tier 4; the covariance test across
  `--layouts` replaces the range test there.
