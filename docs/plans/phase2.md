# Phase 2 — Tier 2: argument detection via use-before-def

Status: **complete**. Prerequisite: Phase 1 (complete).

## Outcome

| Measure | Result |
|---|---|
| `stack_read:::ENTER` variables | **11 → 2** (`rax`, `arg0`) |
| test08 invariants | **179 → 17** (Kvasir: 40) |
| `reg6` / `stack8` | 6 / **8** — contiguity recovered the dead 7th |
| `pick_first` (dead param) | **2**, matching Kvasir, via the -O0 spill |
| `twelve` | **12** (6 reg + 6 stack) from one read of the 12th |
| `nullary` / `main` | 0 |
| tier 0 + tier 1 goldens | byte-identical |
| tests | 138 passed |
| `./test.sh` (14 binaries) | tracer 14/14, kvasir 7/7, 0 failures |

### Recall fell, as the acceptance criterion was designed to catch

The plan said "recall must not move - if it does, tier 2 is deleting real
information rather than noise." **It moved.** At tier 0/1 the tracer encoded
`stack_read`'s true relation twice, by accident:

```
4.294967297E9 * rax - 2 * stack0 + 4.294967295E9 == 0   <- caller's packed struct
rax - 2 * rdx - 1 == 0                                   <- p->a in a scratch reg
```

Both are algebraically `return == a + b`. Neither `stack0` nor `rdx` is an
argument of `stack_read`, so tier 2 correctly drops them — and the two semantic
facts go with them. Verified: tier 2 output contains no `rdx` or `stack0` at
that program point.

This is correct behavior, not a defect. The facts were artifacts of capturing
unrelated machine state that happened to overlap the caller's frame. But it
means **the tier curve will show recall falling at tier 2 and not recovering
until dereference lands at tier 6** — a real result worth reporting rather than
smoothing over, and one that only surfaced because the criterion was written as
a prediction that could fail.

`test_accidental_pointee_recovery_is_destroyed` pins this as a finding rather
than guarding against regression.

### Implementation notes

- Sub-register canonicalization was as load-bearing as predicted; without it
  every integer function reports arity 0.
- The deferred-schema buffer (`Tracer.pending`, flushed in `_finalize()`) was
  needed because arity is unknown when a sample is taken and later `--layouts`
  runs can still add evidence.
- Tier 2+ probes `MAX_STACK_PROBE = 12` stack words instead of the fixed 4, so
  `twelve()` is representable; tiers 0-1 keep the 4-slot window and their bytes.
- Two of my own test assertions were wrong, not the code: `add esi, edx` reads
  `edx` (arg3), so contiguity correctly yields 3, not 2.

## Purpose

The first tier that moves a measured number. Replace the fixed 11-slot window
with the arguments each function actually takes.

Target, on `stack_read(pair_t *p)`:

```
tier 0/1:  rax rdi rsi rdx rcx r8 r9 stack0 stack1 stack2 stack3   (11)
tier 2:    rax arg0                                                 (2)
kvasir:    p  (+ p[..], p[..].a, p[..].b from dereference, tier 6)
```

Ten of eleven variables at `stack_read:::ENTER` are leftovers. Daikon emits
pairwise relations across all of them, which is why the tracer reports 179
invariants against Kvasir's 40. Precision should move sharply here; recall
should not move at all, since no pointee fact is reachable until tier 6.

---

## Corrections to the master plan

Four findings from measurement. Two change the design; one removes a claimed
limitation; one reverses a planned test.

### 1. Capstone reports sub-registers, never the parent — this is load-bearing

At -O0 an `int` argument arrives in `rdi` but is *read as `edi`*. Capstone
reports exactly what the instruction names:

```
mov dword ptr [rbp - 4],  edi     reads: rbp, edi      <- not rdi
mov dword ptr [rbp - 0x14], r8d   reads: rbp, r8d      <- not r8
```

A tracker watching for `rdi`/`rsi`/`r8` would see **zero** argument reads and
report arity 0 for every integer function. Sub-register→parent canonicalization
is not a refinement, it is the difference between the heuristic working and
silently returning nothing.

Required mapping (8 families): `rax/eax/ax/al/ah`, `rdi/edi/di/dil`,
`rsi/esi/si/sil`, `rdx/edx/dx/dl/dh`, `rcx/ecx/cx/cl/ch`, `r8/r8d/r8w/r8b`,
`r9/r9d/r9w/r9b`, plus `r10`/`r11` for the caller-saved clobber set.

### 2. Dead parameters are NOT a permanent recall loss — that was -O1 thinking

The master plan specified `tests/test09.c` to "pin the permanent recall loss
where a dead parameter is invisible to dynamic detection". Measured, that is
false at -O0, because gcc spills **every** parameter in the prologue regardless
of use:

```c
int pick_first(int a, int b) { return a; }   /* b is dead */
```

```
-O0:  mov %edi,-0x4(%rbp)      <- both spilled
      mov %esi,-0x8(%rbp)      <- b spilled despite being dead
      mov -0x4(%rbp),%eax      => use-before-def finds arity 2, MATCHING Kvasir

-O1:  mov %edi,%eax            <- esi never touched
      ret                      => arity 1, Kvasir says 2. Loss is real HERE.
```

So the dead-parameter blind spot is a property of the *optimization level*, not
of dynamic detection. At -O0 the technique is exact. The corpus is entirely -O0
(`Makefile` passes no `-O` flag), which **flatters the heuristic**, and the
write-up must say so rather than claiming a general result.

`tests/test09.c` is still worth building — but as a test that tier 2 finds
arity **2**, the opposite of what the master plan specified.

### 3. Trailing dead *stack* arguments are invisible even at -O0 — use contiguity

The -O0 spill saves register arguments, but stack arguments are already in
memory and are never spilled. `stack8` from `tests/test07.c` takes `g` (arg7,
dead) and `h` (arg8, used):

```
mov %r9d,-0x18(%rbp)      <- args 1-6 spilled
mov 0x18(%rbp),%eax       <- reads arg8 only; arg7 at [rbp+0x10] never touched
```

A "set of slots observed" rule yields args {1..6, 8} — a hole, and arity 7
instead of 8. **Rule: arity = highest used index + 1.** The ABI allocates
argument slots contiguously, so observing arg8 proves arg7 exists. This
recovers `g` correctly and is strictly better than the union rule the master
plan specified.

It also bounds the damage in case 2: at -O1 `pick_first` reads only `edi`
(index 0), so contiguity still yields arity 1. Contiguity fixes holes, not
trailing absence.

### 4. Stack arguments need no memory hook

`[rbp+0x10 + 8k]` accesses are visible in Capstone's *operand* detail, which
tier 2 already pays for. No `UC_HOOK_MEM_READ` required, no second mechanism,
and attribution to the executing instruction is exact. Valid because -O0 always
keeps the frame pointer.

### 5. Performance is a non-issue at this corpus size

`cs.detail = True` costs 5x (640k → 128k insn/s measured). The corpus executes
**642 instructions** per binary — roughly 5ms. Even the 200,000-instruction
default cap is ~1.6s. Detail stays off at tiers 0-1 regardless, so nothing
regresses.

---

## Design

### `infer.py` — `ArityTracker` (pure)

```python
REG_ARG_ORDER = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]   # SysV integer args
CALLER_SAVED  = {"rax","rcx","rdx","rsi","rdi","r8","r9","r10","r11"}

canonical_reg(name) -> str       # edi -> rdi, r8d -> r8, al -> rax
```

Per **function entry address** (not name — addresses are the stable key):

- `read_before_write: set[str]`, `written: set[str]`, `max_stack_slot: int|None`
- For each instruction, in order:
  - `reads - written` ∩ `REG_ARG_ORDER` → record as argument use
  - a memory operand with base `rbp` and displacement `d >= 0x10` → stack arg
    slot `(d - 0x10) // 8`
  - `written |= writes`
  - if the instruction is a **`call`**, `written |= CALLER_SAVED`. Without this,
    a caller reading `rdi` *after* a nested call (where the callee clobbered it)
    looks like an incoming argument.
- Union across every invocation and every `--layouts` run.
- `arity()` → `(n_reg_args, n_stack_args)` by the contiguity rule: highest
  observed index + 1, independently for registers and stack slots.

Only the six ABI argument registers are considered. That is what makes the
heuristic sound: they are caller-saved, so unlike `rbx` a callee never reads one
merely to preserve it across its own body.

### Deferred schema in `emulate.py`

Arity is not known until the function has executed, but the first ENTER sample
is written before that. The writer already buffers, but it needs the schema at
`declare()` time — so the **Tracer** buffers instead:

```
pending: [(ppt_name, func_addr, kind, raw_values, nonce)]
...at end of run():
    for each traced function:  specs = schema_for(arity)
    writer.declare(...); writer.add_sample(..., filtered values)
```

`raw_values` stays the full 11-slot vector; filtering happens once, at the end,
after every layout has contributed to the union. Tiers 0 and 1 pass the vector
through unfiltered, so their bytes are untouched.

This is also the natural moment to split `run()` (Phase 0 Issue 8) — the
inference/finalize step is a real seam, and the tier-0 golden protects the move.

### Tier 2 variable set

`{rax} ∪ {arg0..arg(n-1)}`, named positionally. `rax` is retained unchanged —
turning it into a proper `return` (EXIT only, width-masked) is tier 3. Keeping
it here means precision rises monotonically with no recall dip in between.

---

## Issues, ranked by how quietly they fail

**Issue A — forgetting sub-register canonicalization.** Arity 0 everywhere;
every function declares only `rax`; Daikon still runs and reports a small, clean
invariant set that looks like a *precision win*. The most dangerous failure in
this phase because the output looks better. *Mitigation:* a test asserting
`six()` recovers exactly 6, and an e2e assertion that tier 2 on `test07.exe`
yields 6 args for `reg6` and 8 for `stack8`.

**Issue B — contiguity overestimating on scratch reads.** A function that reads
`rcx` as scratch before writing it reports arity 4. At -O0 the compiler
initializes before use, so this should not fire, but it is the main
false-positive channel. *Mitigation:* count occurrences in the corpus; if
non-zero, restrict detection to the prologue window (the contiguous
`mov %reg,-N(%rbp)` run) rather than the whole body. Measure before adding the
restriction.

**Issue C — tier-0/1 byte drift from the deferred-schema refactor.** Touches the
sample path for all tiers. *Mitigation:* both goldens
(`test08.tier0.dtrace`, `test08.tier1.dtrace`) checked on every change.

**Issue D — frame attribution.** Instructions must count toward the innermost
active frame, or a callee's reads inflate its caller's arity. *Mitigation:*
attribute via `call_stack[-1]`; unit-test with a nested sequence where the inner
function reads `r9` and the outer must not gain an argument.

**Issue E — a function with zero arguments.** `main(void)` correctly yields
arity 0 and declares no variables beyond the nonce. This is valid — Kvasir's
`main:::ENTER` has exactly zero variables — but it is an easy thing to "fix"
into a crash or a skipped ppt. *Mitigation:* explicit test that `none()` emits a
declared ppt with no variables and Daikon accepts it.

**Issue F — `stack0..3` window vs. real stack arity.** The old fixed window read
4 slots unconditionally; tier 2 reads exactly the inferred count, which may
exceed 4 for a 12-argument function. The slot reader must stop depending on
`NUM_STACK_ARG_SLOTS`. *Mitigation:* test with a >4 stack-arg function.

---

## Test plan

### Unit — `tests_py/test_infer_arity.py` (pure, table-driven, no Unicorn)
Feed synthetic `(mnemonic, reads, writes, mem_operand)` sequences:
- read-before-write ⇒ argument; write-then-read ⇒ not.
- **sub-register canonicalization**: `edi` ⇒ `rdi`; `r8d` ⇒ `r8`; `al` ⇒ `rax`.
- `call` clobbers caller-saved, so a post-call `rdi` read is not an argument.
- callee-saved (`rbx`, `r12`) never reported regardless.
- contiguity: observing only arg6 ⇒ arity 6; only stack slot 1 ⇒ 2 stack args.
- union across invocations; union across layouts.
- zero-argument function ⇒ arity 0, not an error.

### Unit — `tests_py/test_schema_build.py` (pure)
Arity → `VarSpec` list; `arg0..argN` naming; `rax` retained; filtering an
11-slot raw vector down to the schema preserves positional correspondence.

### E2E — `tests_py/test_e2e_tier2.py` (`@pytest.mark.e2e`)
- tier 0 and tier 1 goldens byte-identical (Issue C).
- `test07.exe`: `reg6` ⇒ 6 args, `stack8` ⇒ 8 args (proves contiguity, Issue A).
- `test08.exe`: `stack_read:::ENTER` declares `rax` + `arg0` only; none of
  `rsi/rcx/r8/r9/stack1..3` survive.
- `test09.exe`: `pick_first` ⇒ arity **2** at -O0 (correction 2).
- `main` ⇒ arity 0, Daikon accepts the empty ppt (Issue E).
- Invariant count on `test08` drops substantially from 179 — the headline
  number. Assert a direction and a loose bound, not an exact value, so the test
  does not become a maintenance burden.

### New fixtures
- `tests/test09.c` — `pick_first(a, b)` returning `a`; dead-parameter case.
- `tests/test10.c` — a function with 10 arguments (4 register + 6 stack) for
  Issue F, plus a zero-argument function for Issue E.

### Optional: the optimization axis
A `-O1` build of `test09.c` would measure correction 2 directly (arity 2 at -O0
vs 1 at -O1). One Makefile rule. Worth doing, but it opens a second research
dimension and should be a deliberate decision rather than a side effect of this
phase.

---

## Acceptance

- `pytest tests_py/` green; both goldens byte-identical.
- `./test.sh` full corpus at 0 failures.
- `stack_read:::ENTER` declares 2 variables, down from 11.
- `reg6` ⇒ 6, `stack8` ⇒ 8, `pick_first` ⇒ 2, `main` ⇒ 0.
- test08 invariant count **falls** from 179, and no Kvasir-recoverable fact is
  lost relative to tier 1. **Recall must not move** — if it does, tier 2 is
  deleting real information rather than noise.

## Carried into Phase 3

- `ReturnTracker` reuses this phase's last-write tracking: tier 3 needs the last
  write to the `rax` family before `ret`, and the canonicalization table
  built here is exactly what makes the sub-register width readable.
- Comparability classes need a type partition; tier 3 supplies the cheap half
  (value-in-mapped-region) and reuses `arg0..argN` as the classified slots.
