# Plan — checking recovered types against the binary (type-only "matching")

Status: **Stage 1 complete — all three criteria met.** Stage 2 not started. Prerequisite: the REA/Ghidra measurement on the
ReSym test set (94 binaries, 18,551 functions, 44,366 parameters, 3,363 globals),
harness in `scripts/rea_eval/`.

## Why

Ghidra-through-REA recovered fully exact types for only ~22% of parameters,
~49% of returns and ~6% of globals. Worse for our use, it was **confidently
wrong** about the kind of type for 22% of parameters, mostly by calling a
pointer `long` (8,977 cases) and by never building structs (pointee right 35%).

The video-game decompilation projects that succeed with AI do not trust a
single guess. They **check** each guess (recompile, compare bytes) and loop.
This plan borrows the checking idea for **types alone**, without decompiling
whole functions.

The principle: most type facts leave fingerprints in machine code, so a
proposed type can be tested by asking *does it explain every instruction that
touches this variable?*

| type fact | fingerprint |
|---|---|
| pointer vs integer | the value is dereferenced (LOAD/STORE address) or passed where a pointer is required |
| width | the size of every load/store/compare on it |
| signed vs unsigned | INT_SEXT vs INT_ZEXT, INT_SLESS vs INT_LESS, INT_SRIGHT vs INT_RIGHT, INT_SDIV vs INT_DIV |
| struct layout | constant offsets from the pointer, each with its access width |
| float / double | FLOAT_* operations, xmm storage |
| char pointer | passed to `strlen`/`strcmp`/`printf("%s")`…, byte-wide loads |

A checker can **refute** a type and can **narrow** a type to the set that
fits. It cannot always pick the original: types that compile identically
(signed vs unsigned when only added, `int *` vs a struct whose first field is
the only one used) stay ambiguous, and the honest output is that set.

---

## Stage 1 — static checker on Ghidra's existing answers (no AI, no API key)

**Question it answers:** of Ghidra's answers, how many wrong ones would a
cheap consistency check catch, and how many right ones would it wrongly reject?

### Evidence

REA's `analyze_function` returns Ghidra's high p-code for each function
(`native_value_flow`: operations, `def_use` edges, `parameter_uses`, up to
3,000 ops/function — truncation is reported and counted). Collected once per
binary in the same single-import session as before; cached next to the
existing `bench/resym/rea_out/`.

### Per-parameter observations (derived purely from the stripped binary)

Walk forward from each parameter through COPY / CAST / INT_ZEXT / INT_SEXT /
PTRADD / PTRSUB / INT_ADD-with-constant, recording:

- **deref**: used as a LOAD/STORE address → `(offset, size)` list
- **arith**: used in multiply/divide/shift/compare with non-pointer operands
- **sign evidence**: SEXT vs ZEXT, signed vs unsigned compare/shift/divide
- **float evidence**: input to FLOAT_* ops
- **call evidence**: passed as argument N to a known library function
  (Ghidra knows libc prototypes from imports) → that prototype's type
- **width**: size of the varnode at its first use

Returns get the same treatment from the RETURN op's input and from callers'
use of the result. Globals get it from every instruction referencing their
address (xrefs + p-code of the referencing functions).

### Rules (each yields PASS / FAIL(reason) / NO-EVIDENCE)

| rule | fails when |
|---|---|
| R1 pointer-ness | claimed integer but dereferenced; claimed pointer but used in multiply/divide or as a float |
| R2 width | claimed size ≠ observed access width |
| R3 signedness | claimed signed but only unsigned ops (or vice versa), when such ops exist |
| R4 float | claimed integer but FLOAT ops consume it (or vice versa) |
| R5 pointee scalar | claimed `T *` but dereferences use a different width than `sizeof(T)` |
| R6 pointee struct | claimed scalar pointee but dereferences hit ≥2 distinct offsets with different widths (→ struct) |
| R7 library call | claimed type contradicts the prototype of the libc function it is passed to |
| R8 void return | claimed `void` but callers read RAX after the call (needs caller p-code) |

**Abstain is not a failure.** `undefinedN` gets "no claim" but the checker
still emits what the evidence supports (e.g. "pointer, struct-like, fields at
0/8/16") — that becomes Stage 2's input.

### Metrics (scored against the DWARF answer key, which the checker never sees)

- **catch rate**: of Ghidra's wrong answers, % the checker FAILs
- **false-reject rate**: of Ghidra's correct answers, % the checker FAILs — must stay low
- per rule: catches vs false rejects (a rule with more false rejects than catches is dropped)
- **evidence coverage**: % of parameters/returns/globals with any usable evidence
- **after filtering**: Ghidra's confident-wrong rate when FAILed answers are turned into abstains
  (22% today for parameters)

### Falsifiable success criteria (set before running)

1. Catches **≥ 50%** of Ghidra's pointer→`long` errors (8,977 parameters).
2. False-reject rate on correct answers **≤ 5%**.
3. Confident-wrong rate for parameters falls from **22% to ≤ 11%** after filtering.

If 1 or 2 fail, the evidence is too weak to anchor an AI loop and Stage 2
should not start as designed.

## Stage 1 result (94 binaries, scored against DWARF, 2026-10-18)

p-code collected for 24,428 functions; 0.36% errored or truncated (stop threshold 10%).
`python3 scripts/rea_eval/check.py bench/resym/sample/truth.jsonl bench/resym/rea_out bench/resym/pcode`

| | params | returns | globals |
|---|---|---|---|
| Ghidra's wrong answers caught | **63.8%** | 16.9% | **87.4%** |
| Ghidra's right answers wrongly rejected | **0.7%** | 2.9% | 0.7% |
| pointer-called-integer errors caught | **86.2%** of 8,969 | 37.7% of 416 | — |
| wrong KIND of type, of all: before → after | **22.9% → 4.5%** | 8.2% → 6.7% | 6.6% → 0.8% |
| any wrong detail (kind/pointee/sign/size): before → after | 34.4% → 12.4% | 17.3% → 14.4% | 6.6% → 0.8% |
| Ghidra abstained but evidence proposes pointer/scalar/float | 32.8%, right 95.9% | 12.1%, right 99.9% | 18.8%, right 95.0% |

Criteria: (1) pointer→integer caught 86.2% ≥ 50% ✓  (2) false rejects 0.7% ≤ 5% ✓
(3) confident-wrong kind 22.9% → 4.5% ≤ 11% ✓.

Per rule (catches / false rejects), params: R1 7,894/45, R3 408/42, R4 14/0, R5 7/0, R6 1,080/10;
returns: R1 158/8, R3 137/78, R5 11/1; globals: R7 194/2. No rule rejects more than it catches.

Hand check of 20 random parameter verdicts against pseudocode and the answer key:
10/10 FAILs were genuinely wrong Ghidra types; 10/10 PASSes had the right kind.

**Weak spot: return values.** Most returns have NO-EVIDENCE (3,153 of 4,806 answers) - a
returned value is only "seen" through its producer and through callers, and R3 from
callers' compares is the noisiest rule (137 catches / 78 false rejects).

**Implementation notes.** A struct returned by value (> 16 bytes) arrives as a hidden
first pointer, so parameters are realigned before comparison. R2 (width) and R8 (void
return) are not implemented: Ghidra's high p-code is shaped by its own prototype, so that
evidence would be circular.

---

## Stage 2 — AI proposes, checker verifies, loop (needs `ANTHROPIC_API_KEY`)

- **Input per function:** REA pseudocode + the Stage 1 observations (not the
  answer key, not symbols). Model proposes types for params, return, and any
  struct layout it infers; output in a fixed JSON schema with an explicit
  "don't know".
- **Check:** Stage 1 rules. On FAIL, the reason ("param0 is dereferenced at
  +0x18 with 8-byte loads") goes back to the model; up to 3 rounds; then abstain.
- **Struct accumulation:** a struct layout confirmed in one function is offered
  as a known type in later functions of the same binary (the game projects'
  shared-header effect).
- **Cost control:** only send functions where Ghidra abstained or the checker
  failed Ghidra's answer; cache every response by evidence hash.
- **Report:** same table as the REA run, three rows — Ghidra, Ghidra+checker,
  AI+checker — plus rounds-to-pass and API cost.
- **Contamination caveat:** ReSym projects are public GitHub code; report it,
  and spot-check on our own fixtures that no model has seen.

## Stage 3 — run-time checker via the tracer (optional, measured first)

The tracer observes real values: whether a value lands in mapped memory, which
offsets are touched and at what widths. That is a second, independent checker.
**Risk:** many ReSym binaries need input, so coverage may be low (the tracer
reached 6 program points in `cat`). Measure coverage on the 94 first; build
only if it reaches a useful fraction of functions.

## Stage 4 — recompile spot-check (optional)

ReSym binaries are `gcc -O0`, a near-literal translation, so a C stub with the
proposed types can be compiled and its loads/stores/extensions compared with
the original. Used only to break ties the static checker leaves open.

---

## Files

- `scripts/rea_eval/collect.py` — add `analyze_function` p-code collection (cached, resumable)
- `scripts/rea_eval/observe.py` — new: p-code → per-variable observations (pure, unit-tested)
- `scripts/rea_eval/check.py` — new: rules R1–R8, PASS/FAIL/NO-EVIDENCE with reasons
- `scripts/rea_eval/score.py` — add catch / false-reject / after-filtering columns
- `tests_py/test_rea_checker.py` — rules on hand-built p-code snippets
- write-up: `docs/REA-EVALUATION.md`

Data stays in `bench/` (gitignored).

## Order and stop points

1. Collect p-code for the 94 binaries (~1–1.5 h, like the first run). **Stop if
   truncation or missing p-code affects > 10% of functions.**
2. Build `observe.py` + `check.py` with unit tests; hand-verify on 20 functions
   against the source before scoring anything.
3. Score Stage 1 against the criteria above. **Report, then decide** on Stage 2.
4. Stage 2 only with an API key and a passing Stage 1.

## Risks

- **p-code truncation** at 3,000 ops on very large functions — counted, excluded, reported.
- **Evidence-free variables**: a parameter only passed through to another
  function gives nothing locally; follow one call level using the callee's
  observations, no deeper.
- **Rules that over-fire**: measured per rule and dropped if harmful, the
  phase-10 rule (a mechanism that loses more than it gains is reverted).
- **Ambiguity is real**: report "consistent set" sizes rather than forcing a
  single type — matches the open item in `docs/FORMAL-METHODS.md`.
