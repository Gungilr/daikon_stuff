# Phase 1 — Tier 1: structural alignment with Kvasir

Status: **complete**. Prerequisite: Phase 0 (complete).

## Outcome

Shipped as planned, with no further corrections needed beyond the four below.

| Check | Result |
|---|---|
| ppt names vs Kvasir | `..stack_read():::EXIT` — **matches** (was `:::EXIT1`) |
| invariant count t0 → t1 | 179 → 179 (framing only, as required) |
| `orig()` emitted | 0; Daikon still derived 36 orig() invariants |
| nonce in declarations | 0 |
| tier-0 golden | byte-identical on all 8 binaries |
| test suite | 79 passed |
| `./test.sh` full corpus | tracer 10/10, kvasir 5/5, 0 failures |

Implementation notes worth keeping:

- `DaikonTraceWriter` is now schema-driven (`VarSpec` + `declare(ppt, ppt_type,
  specs)`); tier 0 is the same API called via `legacy_specs()`, not a branch.
- `declared_ppts` became `ppt_specs`, and the summary line in `run()` still
  referenced the old name. The process wrote a correct `.dtrace` and *then*
  crashed, so manual runs with stdout redirected looked fine — only the exit
  code revealed it. Caught by `test_e2e_refactor.py`, which is precisely the
  case for having e2e tests that assert `returncode == 0`.
- One test of mine was wrong, not the code: nonces legitimately appear twice
  (ENTER + matching EXIT), so file-wide uniqueness was the wrong property. The
  right one is one distinct nonce per ENTER, with no id used more than twice.

## Purpose

Make the tracer's `.dtrace` *shaped* like Kvasir's, without inferring anything
new. No arity, no types, no dereference — those are tiers 2, 3 and 6.

The concrete payoff is program-point name alignment, which Phase 4's scorer
cannot work without. Measured side by side today:

```
tracer:  ..stack_read():::EXIT1        <- cannot be matched to
kvasir:  ..stack_read():::EXIT             the oracle's ppt
```

Daikon combines individual exit sites into a single `:::EXIT` ppt only when they
are declared `ppt-type subexit`. The tracer declares `ppt-type exit`, so Daikon
treats `:::EXIT1` as already-combined and never produces `:::EXIT`. Every
tracer↔Kvasir comparison at an exit point is therefore unmatchable until this
changes. That, not the nonce, is tier 1's real deliverable.

---

## Corrections to the master plan

Investigation overturned three assumptions. Two of them would have shipped bugs.

### 1. `this_invocation_nonce` is NOT a declared variable

The master plan said "emit `this_invocation_nonce` as the first variable of every
ppt" and "port the nonce contract from `daikon_test.py:93-116`". **Both are
wrong.** Kvasir's ground-truth output:

```
$ grep -c this_invocation_nonce traces/test08.kvasir.decls   -> 0
$ grep -c this_invocation_nonce traces/test08.kvasir.dtrace  -> 42
```

It appears in *every sample* and in *no declaration*. And it carries **no
modbit** — two lines, not three:

```
..stack_read():::ENTER
this_invocation_nonce      <- header
1                          <- value, then straight to the first real variable
p
0x1ffefffcb0
1                          <- regular variables DO have a modbit
```

Confirmed in the parser at [FileIO.java:1782-1812](daikon/java/daikon/FileIO.java#L1782-L1812):
Daikon *peeks* the line after the ppt name, and if it equals
`this_invocation_nonce` it consumes the header and the number — nothing else.
The nonce is a sample-level prefix, not a variable.

**Consequence if done as planned:** declaring it puts `this_invocation_nonce`
first in the decl, so after Daikon consumes the nonce prefix it reads the *next*
line expecting the first declared variable's name — and gets the modbit `1`.
Every subsequent name/value/modbit triple is shifted by one. Silent desync of
the entire sample block.

**`scripts/daikon_test.py` (the PE tracer) does exactly this** — declares the
nonce at [:127-131](scripts/daikon_test.py#L127-L131) and writes a modbit at
[:173](scripts/daikon_test.py#L173). It is the wrong model to copy, despite
`CONTEXT.md` presenting it as the reference. Out of scope here; logged as
follow-up below.

### 2. `orig()` variables must NOT be emitted

The master plan said "emit explicit `orig(v)` variables at EXIT from the entry
snapshot". Kvasir emits **zero**:

```
$ grep -c "orig(" traces/test08.kvasir.dtrace   -> 0
$ grep -c "orig(" traces/test08.kvasir.decls    -> 0
$ grep -c "orig(" invariants/test08.kvasir.txt  -> 9    <- Daikon DERIVES them
```

Daikon synthesizes `orig(v)` at exit points from the nonce-paired entry sample.
A front-end that emits them creates a literal variable named `orig(rax)`, which
Daikon then derives an `orig(orig(rax))` for. Strictly harmful.

### 3. Recursion is not broken today

I previously claimed the missing nonce mispairs recursive calls. **That was
wrong.** [FileIO.java:1009-1012](daikon/java/daikon/FileIO.java#L1009-L1012) —
"call_stack is for procedures without nonces" — and an empirical check on
`fact(5)`:

| | ENTER `rdi` | EXIT `rax` |
|---|---|---|
| order observed | 5, 4, 3, 2, 1 | 1, 2, 6, 24, 120 |

Daikon reported `rax % orig(rdi) == 0`, which holds for the LIFO pairing
(1%1, 2%2, 6%3, 24%4, 120%5) and fails immediately under arrival-order pairing
(1%5). Stack-discipline pairing already works.

Unbalanced traces also degrade *safely*. Truncating mid-recursion
(`--max-insns 60`, 3 layouts) gives 15 ENTERs against 3 EXITs, and Daikon says:

```
No return from procedure observed 15 times.  Unmatched entries are ignored!
```

Detected and dropped, not silently mispaired.

**So the honest case for the nonce is narrow:** it is what Kvasir emits (format
parity), and it makes pairing explicit rather than dependent on well-nestedness
— which matters because `--layouts N` concatenates N independent runs into one
trace, where a dangling ENTER from run 1 is *in principle* poppable by an EXIT
from run 2. Globally-unique nonces make that impossible by construction. It is
not fixing a live bug, and the plan should not pretend otherwise.

### 4. `EXIT0` is correct even for multi-return functions

At `-O0`, gcc routes every `return` through one epilogue: `fact()` has two
`return` statements and exactly **one** `ret` instruction. Kvasir names it
`EXIT0`. Single exit site is the norm for this corpus, so a single `EXIT0` per
function is right — no per-site numbering needed.

---

## Output specification

Verified against `traces/test08.kvasir.*`. Tier 1 emits:

```
decl-version 2.0
var-comparability none            <- unchanged; comparability is tier 3

ppt ..f():::ENTER
ppt-type enter
variable rax
  var-kind variable
  dec-type int
  rep-type int
  comparability 22

ppt ..f():::EXIT0                 <- was EXIT1
ppt-type subexit                  <- was exit
...
```

```
..f():::ENTER
this_invocation_nonce             <- first line after the ppt name, always
7
rax
140733193388032
1
...
                                  <- blank line ends the sample
```

Differences from tier 0, in full: `EXIT1`→`EXIT0`, `exit`→`subexit`, and a
two-line nonce prefix on every sample. Nothing else moves.

---

## Design

### Writer: schema-driven, one code path

Replace the single global `var_names` with per-ppt schemas now, because tier 2
needs them and doing it under the tier-0 golden gate is the safe moment.

```python
@dataclass(frozen=True)
class VarSpec:
    name: str
    dec_type: str = "int"
    rep_type: str = "int"
    comparability: str = "22"
    var_kind: str = "variable"
    enclosing_var: str | None = None   # tier 6
    array: int | None = None           # tier 6
    flags: str | None = None           # tier 3 (is_param)
```

```python
w = DaikonTraceWriter(path, var_comparability="none")
w.declare(ppt_name, ppt_type, specs)        # ppt_type: "enter" | "subexit" | "exit"
w.add_sample(ppt_name, values, nonce=None)  # nonce=None omits the prefix
```

**Tier 0 is not a separate branch** — it is this API called with the legacy
schema (`REG_VARS_*` as plain int/22 specs), `ppt_type` inferred as today,
`EXIT1` naming, and `nonce=None`. One serializer, two callers. The golden test
proves the tier-0 bytes are unchanged.

`ppt_type` becomes an explicit argument rather than being inferred from
`"ENTER" in ppt_name` — that inference cannot distinguish `exit` from `subexit`,
which is the whole point of the change.

### Emulator: carry the nonce on the frame

- `Tracer.call_stack` frame `(func_name, ret_addr, entry_addr)` →
  `(func_name, ret_addr, entry_addr, nonce)`. Two sites touch it
  ([emulate.py:313](scripts/tracer/emulate.py#L313) append,
  [:317](scripts/tracer/emulate.py#L317) unpack).
- Allocate via `writer.next_nonce()` at ENTER; reuse verbatim at EXIT.
- The counter lives on the **writer**, not the Tracer, and is **never reset per
  layout** — `run()` re-enters the layout loop with a fresh `call_stack`
  ([:518](scripts/tracer/emulate.py#L518)), and resetting nonces there would let
  run 2 reuse run 1's ids, reintroducing exactly the cross-run ambiguity the
  nonce exists to remove.
- Naming moves behind a tier check: `_ppt_name(func_name, "EXIT1" | "EXIT0")`.

---

## Issues, ranked by how quietly they fail

**Issue A — nonce declared by mistake.** Silent whole-sample desync (see
correction 1). Nothing in Daikon's output would obviously point at it.
*Mitigation:* test asserting `this_invocation_nonce` appears zero times in the
declaration section and exactly once per sample; plus a test that the two lines
following the ppt name are the header and an integer, with the next line being a
variable *name*, not a modbit.

**Issue B — `orig()` emitted.** Produces a variable literally named `orig(rax)`
and a derived `orig(orig(rax))`. Looks like a tier improvement ("more orig
invariants!") while being pure corruption. *Mitigation:* assert `"orig("` never
appears in tier-1 output.

**Issue C — tier 0 byte-drift.** The writer rewrite touches the exact
serialization path the golden pins. *Mitigation:* `tests_py/golden/test08.tier0.dtrace`
checked on every change; this is why Phase 0 committed it.

**Issue D — nonce reset per layout.** See above. *Mitigation:* test tracing with
`--layouts 3` and asserting every nonce in the file is distinct.

**Issue E — frame tuple arity.** Mechanical 3→4 tuple change; a missed unpack
site raises immediately. Low risk, listed for completeness.

**Issue F — `ret_addr` is recorded but never used.** [:313](scripts/tracer/emulate.py#L313)
stores it and the RET handler pops the top frame unconditionally without
checking it. Validating `[rsp] == ret_addr` at the `ret` would catch mispairing
— but changing *which* samples are emitted risks tier-0 byte-identity.
*Decision:* add the check as a **log-only warning** in tier 1+, never as control
flow. Promote to an error only with data showing it fires.

**Issue G — `ppt-type subexit` might change Daikon's ppt set in ways the scorer
does not expect.** It is the intended effect (`:::EXIT1` → combined `:::EXIT`),
but Phase 4 must key on the combined name. *Mitigation:* an e2e test asserting
Daikon's tier-1 report contains `..f():::EXIT` and not `..f():::EXIT1`.

---

## Test plan

### Unit — `tests_py/test_writer_tier1.py` (pure)
- nonce is the **first** line after the ppt name, value on the next line, and
  the line after that is a variable name.
- nonce emitted with **no modbit** (exactly 2 lines).
- `this_invocation_nonce` appears **zero** times in the declaration section.
- `nonce=None` omits the prefix entirely (tier-0 path).
- ppt-type is `subexit` for EXIT0, `enter` for ENTER.
- no `orig(` anywhere in the output.
- two ppts with different schemas serialize independently (the per-ppt change).
- `next_nonce()` is monotonic and never repeats.
- `add_sample` length guard still fires per-ppt (inherited from Phase 0).

### Unit — `tests_py/test_nonce_pairing.py` (pure)
Drive the writer directly with a synthetic nested call sequence
(ENTER a, ENTER a, EXIT a, EXIT a) and assert the ENTER/EXIT nonce pairs are
LIFO-correct — no Unicorn required.

### E2E — `tests_py/test_e2e_tier1.py` (`@pytest.mark.e2e`)
- **tier 0 unchanged**: `test08.exe --tier 0` still byte-matches the Phase 0 golden.
- **tier 1 golden**: new `tests_py/golden/test08.tier1.dtrace`.
- `--layouts 3 --tier 1`: every nonce in the file is distinct (Issue D).
- Daikon on tier-1 output reports `..stack_read():::EXIT`, **not** `:::EXIT1`
  — the alignment deliverable, and the thing Phase 4 depends on.
- Recursive fixture at tier 1 still yields `rax % orig(rdi) == 0`, proving the
  explicit nonce preserves the pairing that stack discipline was already getting
  right.

### New fixture — `tests/test11.c`
Promote the scratch recursive `fact(5)` used in this investigation. It is the
only corpus member that exercises nested same-ppt frames, and the Makefile
globs `tests/*.c`, so it needs no build changes.

---

## Acceptance

- `pytest tests_py/` green, including the Phase 0 suite unchanged.
- `test08.exe --tier 0` byte-identical to `golden/test08.tier0.dtrace`.
- `./test.sh` full corpus at 0 failures.
- Daikon on tier-1 output names exit points `:::EXIT`, matching Kvasir.
- Tier-1 output contains no `orig(` and no declared nonce.
- Invariant *content* at tier 1 is expected to be essentially unchanged from
  tier 0 — same 11 variables, same values. **If precision moves at tier 1,
  something is wrong**: this tier changes framing only.

---

## Follow-up logged, not fixed here

`scripts/daikon_test.py` declares `this_invocation_nonce` as a variable and
writes a modbit for it, which by correction 1 desyncs every sample block it
writes. The PE tracer is not driven by `test.sh` and shares no code, so it is
out of scope — but `CONTEXT.md` presents it as the reference nonce
implementation, and that should be corrected before anyone copies it again.

## Carried into Phase 2

- `VarSpec` lands here; tier 2 populates it per-function instead of per-arch.
- `_read_register_values()` still returns a fixed 11-slot vector. Tier 2 makes
  the slot set per-function, which is where the Phase 0 length guard earns its
  keep.
- `run()` remains a 147-line method. Tier 2 inserts the inference pass; that is
  the moment to split it, under the protection of the tier-0 golden.
