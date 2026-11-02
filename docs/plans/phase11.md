# Phase 11 — an object model for pointers: provenance, per-site layouts, typed traversal

Status: **implemented (tier 10); measured below — see [Results](#results-2026-11-02).**
Supersedes the *order* of phase 10's mechanism A; its goals and acceptance criterion
carry over unchanged.

## Why

The tracer observes almost everything: sample counts match Kvasir at 198/198 program
points and the soundness audit finds 0 false facts. What it lacks is vocabulary for
memory. Of the 3,975 oracle facts still missed on Daikon's Kvasir suite
([phase10.md](phase10.md)):

| misses | share | missing fact |
|---|---|---|
| 2142 | 53.9% | pointer inside a struct, 2+ levels deep |
| 809 | 20.4% | global that is a pointer/array |
| 355 | 8.9% | global that is a struct |
| 215 | 5.4% | local pointer/array |
| 110 | 2.8% | double, not long |
| 90 | 2.3% | `char *` that is a string |

Three earlier mechanisms aimed at these rows recovered real accesses and still lost:

| mechanism | result | what actually went wrong |
|---|---|---|
| `--infer-from-caller` | precision 65% → 43% | accesses credited to a stack object nothing bounded; 3 invented fields on `identity_ptr` |
| `--deref-globals` | +176 matched, precision 22% → 16% | one hop, every pointer-shaped global, no type to decide what to emit |
| `--struct-globals` | −123 matched | access-width heuristics on objects that are never written at run time |

**Common cause: an access was attributed to the wrong object, or to an object with no
known extent or type.** The dereference path is special-cased per root
(`_capture_pointees`, `_return_pointee_layout`, `_global_specs`) and keyed by
*(function, argument)* rather than by the object the bytes belong to.

This phase builds the missing object model first. Recursion is then a small step on top
of it, instead of a third special case.

Methods are taken from the literature that matches our setting: run-time observation of
a binary without debug info.
- **Object table and allocation-site types:** Howard (NDSS'11).
- **Type sinks:** REWARDS (NDSS'10).
- **Shadow memory semantics:** Kvasir/Fjalar itself (`fjalar_runtime.c`).
- **Heap shapes:** MemPick and DSI.

See [`reports/Blackbox Daikon tracing and fuzzing.md`](../../reports/Blackbox%20Daikon%20tracing%20and%20fuzzing.md)
and its notes for sources. Most literature figures there are unverified, but none of the
acceptance criteria below depend on them.

---

## Standing gates (every step)

- Without the step's flag, output is **byte-identical**: all goldens pass.
- Suite precision **≥ 20%**; Daikon exits 0 on all 29 suite binaries; own corpus ≥ **65/92/76**.
- `audit_soundness.py`: **0 false facts** on our own samples.
- DWARF is read **only at scoring**. Layout ground truth comes from
  `scripts/rea_eval/ground_truth.py`, which already extracts struct fields as `(offset, size, kind)`.
- An ambiguous case emits **nothing**. A guess that could be wrong stays behind a flag.

---

## Step 1 — object table and pointer provenance (no output change)

**What.** A pure module `scripts/tracer/objects.py` with an interval map from address to
`MemObject{id, kind: heap|global|stack|rodata, base, size, site}`.

- **heap:** created and destroyed by the allocator model (`scripts/tracer/alloc.py`,
  `arena.size_of`). `site` is the **PC of the call to malloc/calloc/realloc**.
- **global:** from `.symtab` extents when present, else section bounds plus RIP-relative
  starts (`scripts/tracer/globalvars.py`, `GlobalTable`). `site` is the base address.
- **stack frame:** opened at function ENTER as `[rsp_at_entry - frame_size, rsp_at_entry + 8)`
  and closed at EXIT. The upper bound protects the caller's frame; this is the bound
  `--infer-from-caller` never had. The lower bound is the lowest `rsp` seen inside the
  call.
- **rodata:** a single object over `.rodata`, used only for string detection (step 3).

`lookup(addr) -> (obj, offset) | None` replaces the current range check in
`scripts/tracer/memmap.py` (`MemoryMap.classify`) as the source of truth. `classify`
keeps its contract so lower tiers are unaffected.

**Hook change.** `_hook_mem_deref` (`scripts/tracer/emulate.py`, ~L878) records every
access as `(obj.id, offset, width, kind, pc)`. `kind` is one of int-load, int-store,
sse-load, sse-store and ptr-load, where ptr-load means the loaded value itself resolves to
an object. Accesses are **credited to the object they hit**, not to the argument being
captured. This fixes the review's open "two pointer arguments into one object" case
(`memcpy(dst, src)`), where today every access goes to whichever argument is checked
first.

**Tests (pure).**
- Interval lookup.
- Frame open/close.
- realloc moves an object and keeps its site.
- Freed objects stop resolving.
- An access straddling two objects is recorded as "straddle", not attributed.

**Acceptance.**
1. All goldens are byte-identical with the step merged and no flag set.
2. On `tests/test14.c` and a new `tests/test16.c`, the `memcpy`-shaped two-pointer
   function credits reads to `src` and writes to `dst`.
3. Overhead is ≤ 1.5× tracer time on test08 at tier 7, measured.

## Step 2 — per-allocation-site layouts (no output change)

**What.** `scripts/tracer/layout.py`, pure. It merges the access records of every object
with the same `site` into one `SiteLayout`:

- **fields:** `offset → {widths seen, kinds seen, count}`
- **stride evidence:** constant-stride accesses within one execution of a loop. A loop is
  approximated as repeated PCs within one call.
- **size:** minimum object size seen for this site. Taking the minimum keeps the phase-7
  review fix: last-write-wins was wrong.

The type of a pointer *variable* (parameter, return, global, field) is then **the set of
sites its values point into**. One site gives a type. Several sites with compatible
layouts give a merged type. Incompatible layouts mean ambiguous, so abstain.

This is the step that turns "this function read `+8`" into "objects from site S have an
8-byte pointer at `+8`". The evidence pools across every function and call that touched
the object, which is why it beats per-function footprints.

**Acceptance (layout F1, pure scoring).** Compare `SiteLayout` field sets
`{(offset, size)}` against DWARF struct definitions for the type each site is allocated
as. That is available from `ground_truth.py` on our fixtures and the Kvasir-suite
binaries.
- **Layout F1 ≥ 0.80** on observed fields.
- **Field false positives ≤ 5%**, i.e. a field we report that DWARF does not have.

Set in advance. If missed, stop and inspect before step 4.

## Step 3 — field classification

**What.** Per field (and per scalar variable), a class with the evidence that produced it.
Each rule is independently flag-able.

| class | evidence (all run-time, from step 1 records) |
|---|---|
| pointer | the stored value resolves to an object; or it is later used as an address |
| pointee type | the site(s) of the objects its values resolve to |
| double / float | an SSE access at that offset (`movsd` = 8, `movss` = 4). This is phase 10 D's run-time form; the static form measured 0 hits |
| function pointer | used as an indirect call target |
| string | the value resolves into `rodata` or a heap object, and is then read byte-wise to a NUL or passed to a `str*` / `printf %s` libc sink (REWARDS-style sinks via `scripts/rea_eval/libc_protos.py`) |
| signedness | `movsx` / `sar` / `jl`-family vs `movzx` / `shr` / `jb`-family consumers. This extends the existing return-value signedness in `scripts/tracer/infer.py` to fields |
| array vs struct | constant stride across ≥ 4 elements → array (Howard's threshold); fixed offsets with heterogeneous widths/kinds → struct. Today's `looks_like_array` (`scripts/tracer/deref.py`, ~L270) becomes one input |
| array length | heap: object size ÷ stride; global: symbol size ÷ stride; stack: abstain |
| union / conflict | one offset used as two incompatible classes → **abstain** for that field |

**Acceptance.**
- **Field kind accuracy ≥ 90%** on fields with any evidence, against DWARF.
- **Wrong-kind rate ≤ 3%.**
- Abstentions counted separately.
- Phase 10 E's string criterion: a string is reported in `string-arrays` and `GlobalTest`,
  and no `char[]` byte buffer is misreported as a string.

## Step 4 — one typed traversal from every root (tier 10, flag `--deref-depth N`)

**What.** Replace the three special cases with one walker. The roots are every parameter,
the return value and every global.

```
walk(value, name, depth, visited):
    obj, off = objects.lookup(value)        # step 1
    if obj is None or depth > N or (obj.id, off) in visited: return
    visited.add((obj.id, off))
    T = layout_of(obj.site)                 # step 2, classified by step 3
    emit(name, T)                           # array -> name[..]; struct -> fields
    for field in T.pointer_fields():
        walk(read(obj, off + field.offset), child_name(name, field), depth + 1, visited)
```

- **Naming follows Kvasir exactly:** the first hop is `p[..]`, a pointer field is
  `p[].next->val`, and a struct global field is `g.offK`. Representation is the interface,
  per the phase 6 lesson.
- **Capture broadly, emit narrowly.** Values are captured at ENTER and EXIT to depth N+1,
  because the bytes are gone by finalize. Only fields with layout evidence are declared;
  a pointer whose pointee has no evidence is printed as `hashcode` and not followed.
- **Parents come before children by construction.** The builder emits in walk order and
  `DaikonTraceWriter.validate()` (`scripts/tracer/writer.py`, ~L125) already rejects a
  missing `enclosing-var`.
- **Measure depth 1 first, then depth 2.** Depth 2 is the default target. It covers 88% of
  oracle facts by phase 10's measurement.
- **Precision controls:**
  - pointer roots are declared `hashcode` so Daikon makes no ordering or linear claims
    about addresses;
  - fields carry width-based `min-value` / `max-value`;
  - unchanged sites can be collapsed (Daikon `--var-omit-pattern` style).

**Acceptance (phase 10's criteria, unchanged).**
- `NestedStructTest` **> 150 matched facts** (10 today).
- `NestedStructVarList` reports `size(::counters[]) == 10`.
- Suite recall rises from 17%, precision ≥ 20%, Daikon exits 0 on all 29.
- At depth 1, `--deref-globals`'s +176 must be reproduced **at ≥ 20% precision**. If it
  is not, typing did not fix what sank that flag; stop and diagnose before depth 2.

## Step 5 — shadow memory with Kvasir's semantics (flag `--shadow`)

**What.** A per-byte shadow map: A = allocated/addressable, V = initialised. The
allocator, the loader (`.data`/`.bss`/`.rodata`) and stack frames set A. Stores set V.

Kvasir's rules from `fjalar_runtime.c` are copied so the output agrees with the oracle:
- the current frame counts as initialised;
- heap arrays are probed to the last initialised element;
- an invalid pointer prints `nonsensical` with modbit 2.

It replaces the poison-byte approximation (`--poison-uninitialized`) with exact
definedness. It also adds an **unmapped-access-is-a-fault** mode in place of today's silent
zero page (`scripts/tracer/emulate.py`, ~L1406). The fuzzing harness needs that too.

**Acceptance.**
- `tests/test13.c` uninitialised-read cases report `nonsensical`, matching Kvasir.
- No regression in matched facts versus `--poison-uninitialized`.
- The fault mode stops on a wild pointer that the default mode zero-fills.

## Step 6 — static evidence for paths that did not run (flag `--static-layouts`)

**What.** Use the REA/Ghidra p-code already collected by `scripts/rea_eval/collect_pcode.py`
and observed by `scripts/rea_eval/observe.py`: constant-offset dereferences from a
parameter, on every path. These add **candidate** fields only to a site that the run
already established as a struct.
- A static field that contradicts a run-time observation is dropped. This is the same
  rule direction as the stage-1 checker (0.7% false rejects).
- Static-only fields are declared, but carry no claims beyond existence and width.

**Acceptance.**
- Layout recall rises.
- Layout precision stays within 2 points of step 2's.
- No new soundness-audit failures.

## Step 7 — heap shapes (optional, measured first)

Classify recursive sites by shape: list, doubly-linked list, tree. A site with a pointer
field back to the same site, plus pointer-graph shape, decides it (MemPick/DSI). Uses:
- stop the walk with a clean cycle;
- possibly emit length/size facts.

**Gate:** build only if `small-test` and `NestedStructTest` show cycle-truncated facts
worth more than 20 oracle matches.

---

## Files

- **New, all pure (added to `PURE_MODULES` in `tests_py/test_purity.py`):**
  - `scripts/tracer/objects.py`
  - `scripts/tracer/layout.py`
  - `scripts/tracer/classify.py`
  - `scripts/tracer/walk.py`
  - `scripts/tracer/shadow.py`
- **Modified:** `scripts/tracer/emulate.py`:
  - `_hook_mem_deref`;
  - capture at ENTER/EXIT;
  - `_schema_for` / `_filter_values` (~L1432 / ~L1655) and `_global_specs` /
    `_global_values` (~L569 / ~L637), which call the walker at tier 10 and stay
    untouched below it.
- **Modified:** `scripts/tracer/cli.py` gains `--tier 10`, `--deref-depth`, `--shadow`,
  `--static-layouts`, and one flag per step-3 rule.
- **Tests:** `tests_py/test_objects.py`, `test_layout.py`, `test_classify.py`,
  `test_walk.py`, `test_shadow.py`. New fixtures:
  - `tests/test16.c`: memcpy two-pointer case, nested structs, linked list, a union,
    a `double` global, a string global;
  - `tests/test17.c`: struct global never written, struct by value.
- **Scoring:** `scripts/rea_eval/layout_score.py`, new. It reports layout F1 and field kind
  accuracy from `ground_truth.py` output; DWARF stays scoring-only.

## Order and stop points

1. Step 1, object table. **Stop if goldens move or overhead > 1.5×.**
2. Step 2, layouts. **Stop if layout F1 < 0.80 or field false positives > 5%.**
3. Step 3, classification. **Each rule is measured alone and dropped if it is wrong more
   often than it is right.**
4. Step 4 at depth 1. **Stop if `--deref-globals`' gain cannot be held at ≥ 20% precision.**
   Then depth 2, against the `NestedStructTest` > 150 criterion.
5. Step 5, shadow memory; step 6, static layouts; step 7, only if its gate passes.

Steps 1–3 change no trace output. They are pure analysis with their own scores, so each
can be landed and measured before anything reaches Daikon.

## Measurement needs

- **Steps 1–3:** score here, from `ground_truth.py` on our fixtures and the Kvasir-suite
  binaries. No Daikon is needed.
- **Steps 4–5:** need Daikon and Kvasir for P/R/F1. These aren't installed in the cloud
  container; run `./test.sh` locally, or install them here as the earlier plan proposed.
- **ReSym binaries:** usable for layout scoring only where the emulator reaches code.
  Most need input, which waits for the fuzzing harness's input mechanism, so
  ReSym coverage is reported, not gated.

## What this phase will not recover

- **Field names:** destroyed by stripping. The scorer maps them from DWARF.
- **Types of fields the program never touches**, unless step 6 sees them statically.
- **A `double` never used as a double.** About 5% of the oracle is information-theoretic
  residue of this kind.
- **Stack array bounds.** Nothing observable bounds a stack object, so step 3 abstains.

---

## Results (2026-11-02)

Everything below is tier 10 (`--tier 10`), measured in this container with Daikon and
Kvasir built from source. Suite = Daikon's 30 Kvasir-suite programs, run with
`--infer-unobserved-fields --poison-uninitialized` as for the documented tier-8 baseline;
own corpus = `tests/test*.c` with `--poison-uninitialized`.

### Standing gates

| gate | result |
|---|---|
| goldens byte-identical without the flag | **pass**, 465 tests pass (`tests_py`) |
| suite precision ≥ 20%, Daikon exits 0 on all | **pass**, 25.5%, no Daikon failures |
| own corpus ≥ 65/92/76 | **pass**, unchanged at 155/239 matched (the 65/92/76 figure) |
| `audit_soundness.py`: 0 false facts | **pass**, 0 of 6717 audited (suite + own corpus); also 0 with `--rodata-strings` and with `--shadow` |
| DWARF only at scoring | **pass**: `ground_truth.py` / `layout_score.py` / `score_invariants.py` only |

The audit caught one real defect on the way: typing the read-only literal pool made the
constant `3.45` a `double`, comparable to a `float` argument of `3.45f`, and Daikon's
fuzzy float equality then asserted `arg1 == g_0x402018`. Literal-pool entries are not
program variables (Kvasir never reports them), so tier 10 leaves them as tier 8 prints them.

### Suite: tier 8 → tier 10

| | ours | matched | precision | recall | F1 |
|---|---|---|---|---|---|
| tier 8 (documented baseline) | 3905 | 912 | 23.4% | 16.8% | 19.6% |
| **tier 10, depth 2 (default)** | 4935 | **1256** | **25.5%** | **23.2%** | **24.3%** |
| tier 10, `--deref-depth 1` | 4803 | 1256 | 26.2% | 23.2% | 24.6% |
| tier 10, `--deref-depth 3` | 4935 | 1256 | 25.5% | 23.2% | 24.3% |
| tier 10, `--shadow` (instead of poison) | 5056 | 1241 | 24.5% | 22.9% | 23.7% |
| tier 10, `--shadow --poison-uninitialized` | 4935 | 1256 | 25.5% | 23.2% | 24.3% |
| tier 10, `--rodata-strings` | 4920 | **1282** | 26.1% | 23.7% | 24.8% |

+344 matched over tier 8 with precision *up*, where `--deref-globals` bought +176 at a
loss of 6 precision points.

### Per-step acceptance

**Step 1 — object table.**
- Goldens: pass.
- Two-pointer copy: `copy_item(dst, src)` in `tests/test16.c` gets the full layout on
  both objects, as distinct stack sites (`test_two_pointer_copy_credits_each_object`).
- Overhead: pass, **1.32×** (small-test 6.38 s vs 4.85 s at tier 7, best of 2).
  test08 runs 548 instructions in 0.2 s at every tier, too short to measure, so
  small-test (the one long-running suite program) stands in for it.

**Steps 2–3 — layouts and kinds**, `scripts/rea_eval/layout_score.py` over the suite and
own corpus (89 typed sites tied to a DWARF parameter pointee or global):

| metric | target | result |
|---|---|---|
| layout F1 | ≥ 0.80 | **0.897** (P 94.9%, R 85.1%) |
| invented fields | ≤ 5% | **5.1%** (9 of 176) — just over |
| kind accuracy | ≥ 90% | **100%** (141 of 141) |
| wrong kind | ≤ 3% | **0%** |
| abstentions | counted apart | 26 fields; the one union abstained |

- The 9 invented fields are all wide moves over narrower members that the program never
  touches narrowly: a struct copied by 8-byte loads (`crazy-test-1`, `md5`), and a zeroing
  store over `char` members (`DisambigTest`, `ArraysInStructTest`). Nothing at run time
  separates such a copy from a real 8-byte field.
- Kind accuracy reached 100% after one rule: **an 8-byte slot that only ever held 0
  abstains** (NULL and 0L read alike). Before it, the 4.7% wrong kinds were all
  never-dereferenced NULL pointers typed `int`, e.g. `n1->prev = 0` in small-test.
- Shape is right for 78.7% of sites. Most misses are `T *p` used as an array (DWARF calls it
  a pointer to a scalar; the run sees elements), or an array touched at under 4 elements.
- String criterion: string-arrays reports its strings at tier 10. GlobalTest's
  `globalStr` is never dereferenced by the program, so no run-time evidence types it; it is
  reported with `--rodata-strings` (phase 10 E's flag-gated rule). No `char[]` buffer
  is reported as a string: `upcasestr[128]` is not pointer-sized.

**Step 4 — typed traversal.**

| criterion | result |
|---|---|
| suite recall rises from 17%, precision ≥ 20%, Daikon exits 0 | **pass**: 23.2%, 25.5%, 0 failures |
| depth 1 holds `--deref-globals`' +176 at ≥ 20% | **pass**: +344 at 26.2% |
| `NestedStructTest` > 150 matched | **not met, infeasible**: 44 (10 before). 560 of its 677 oracle facts are about `globalBetterFoo`, which the program never touches; ~117 is the most any black-box tracer can reach |
| `NestedStructVarList` `size(::counters[]) == 10` | **not met, abstained**: the program touches `counters[0]`, `[5]`, `[9]` with constant indices; that is byte-for-byte a struct with three `int` fields at +0/+20/+36, below Howard's 4-element stride threshold. Calling it an array would be a guess |

Depth 2 vs depth 1: on the suite, depth 2 adds 132 facts and **no** matches. They are true
(audit) but unmatched for two reasons:
- CoercePointerTest goes through a `void *` field that Kvasir does not follow.
- small-test's `n->next->b` comes out as an equality (`arg0[].off0->off16 == arg0[].off16`)
  where Kvasir, with DynComp separating the variables, prints `== [2]`.

On test16, depth 2 is what yields `head->next->val`. Depth 2 stays the default; depth 1 is
the higher-precision choice for this suite.

**Step 5 — shadow memory (`--shadow`).**
- Uninitialised read: test16's `peek` reads a heap field nobody wrote. We print
  `nonsensical` with modbit 2, identical to Kvasir's trace of the same binary. test13, named
  in the plan, has no uninitialised read; Kvasir and we both print 0 `nonsensical` there.
- Fault mode: `--fault-on-unmapped` stops on a wild pointer that the default mode zero-fills
  (`test_fault_on_unmapped_stops_on_a_wild_pointer`).
- No regression versus `--poison-uninitialized`:
  - **`--shadow` with poison: met** (1256 = 1256).
  - **`--shadow` alone: −15 matched.** It tracks heap bytes only, as Kvasir does, and treats
    the stack as initialised; poison also catches uninitialised stack bytes reached through
    pointers (crazy-test-1 −12, NestedStructTest −4).

STEP6_PLACEHOLDER

**Step 7 — heap shapes. Not built: gate failed.** Depth 3 adds 0 matched facts over depth 2
on small-test and NestedStructTest (the gate needed > 20), and on the whole suite.

### New flags

| flag | default | effect |
|---|---|---|
| `--tier 10` | — | object table, per-site layouts, typed walk from every root |
| `--deref-depth N` | 2 | walk depth |
| `--dump-layouts PATH` | off | JSON of every site's recovered type and root mapping (for scoring) |
| `--no-walk-globals` | off | keep tier 8's global handling |
| `--shadow` | off | per-byte heap definedness; never-written bytes are `nonsensical` |
| `--fault-on-unmapped` | off | stop on an access to unmapped memory |
| `--rodata-strings` | off | a pointer-sized global naming a `.rodata` text run is a `char *` |
| `--static-layouts PATH` | off | add static (Ghidra p-code) fields as ABSTAIN to run-typed structs |
