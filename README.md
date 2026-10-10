# Daikon invariants from stripped binaries

A dynamic front-end that emulates a stripped x86-64 ELF binary and emits a
Daikon `.dtrace` file, so that program invariants can be recovered **without
debug information**. Scored against [Kvasir](https://plse.cs.washington.edu/daikon/),
Daikon's own C front-end, which reads DWARF.

**The research question:** how much semantic fidelity can a black-box tracer
recover from a stripped binary, and where is the irreducible limit?

---

## Where it stands

| corpus | precision | recall | F1 |
|---|---|---|---|
| **`tcas`**, a Siemens benchmark driven with 501 real inputs | **94%** | **90%** | **92%** |
| 10 fixtures written alongside the tool | 65% | 92% | 76% |
| Daikon's 29 self-contained test programs | 24% | 17% | 20% |

Those three numbers are the result, and the spread between them is the finding.

**`tcas` is the honest headline for flat data.** Integer globals, integer
parameters, no structs, no pointer chains - and with 501 input vectors the
agreement with a DWARF-reading tool is near-total.

**The 29-program figure is the honest headline overall.** Those programs were
written by the Daikon authors to exercise a *type-driven* traversal: nested
structs, unions, pointers to pointers, multi-dimensional arrays. That is where a
black-box tracer runs out of vocabulary.

**The middle row is a caution.** Those ten fixtures were written while building
the tool, so they contain the shapes it handles. Running somebody else's corpus
moved the score from 76 to 20 and produced most of what has been learned here.

Every figure is a **floor**: nine separate limitations have been found in the
scoring harness, and every one understated the tracer. See
[VERIFICATION.md](docs/VERIFICATION.md).

---

## The three findings worth knowing

### 1. Stripping costs nothing at the level of observation

Across 29 binaries, **198 of 198 program points** record an identical number of
samples under our Unicorn emulation as under Kvasir/Valgrind on real hardware -
including a 1000-iteration loop. The tracer sees every byte the reference tool
sees, except where a library call the emulator does not model would have
changed memory: nine of the 29 programs make such a call (see
[RELATED-WORK.md](docs/RELATED-WORK.md), section 1f).

What it lacks is the vocabulary to *describe* what it sees:

```
kvasir:  b[] == [61, 61, 62, 63, 65, 68]      ours:  arg1[].off0  == [61]
         size(b[]) == 6                              arg1[].off4  == [61]
                                                     arg1[].off8  == [62]  ...
```

Same bytes, same values, different sentence. Daikon compares sentences. **Kvasir
does not out-observe us; it out-describes us.**

### 2. Of what remains, ~89% is engineering and ~5% is information-theoretic

Classifying every missed fact by the single thing the tracer lacks:

```
54%  a pointer inside a struct, 2+ levels deep     observable - we just stop at one hop
20%  a global that is a pointer                    observable
 9%  these bytes are a struct with members         observable
 5%  a local pointer/array as a sequence           observable
 3%  these 8 bytes are a double, not a long        NOT observable without a consuming opcode
 2%  this char* is a string                        NOT observable without its target
```

The pointer-ness of a value is a range check we already do; the layout behind it
is in an access map we already keep. What is missing is **recursion**, not
information. Only the last ~5% is genuinely absent from the execution - a
`double` the program never loads as a double is indistinguishable from a `long`,
and no solver invents that distinction.

### 3. Adding capability usually costs precision; finding *evidence* does not

Most additions traded recall for precision. One did not: `p->a; p->b` compiles
to two instructions each at a fixed offset, while `arr[i]` in a loop is **one**
instruction walking many offsets. Recording which program counter touched which
offset separates a struct from an array with no guess at all - and it emitted
148 *fewer* facts while matching 20 more.

The measurement that explains why: of 72 shape decisions, **zero** were forced
by the evidence being used. Every one was a guess among 2-5 consistent
alternatives. Converting guesses into derivations is strictly better than
ordering the guesses well. See [FORMAL-METHODS.md](docs/FORMAL-METHODS.md).

---

## How it works

Every capability is opt-in via `--tier N` and cumulative; tiers 0-6 are pinned
**byte-identical** by golden files, so no later work can silently move an
earlier baseline.

| tier | recovers | from |
|---|---|---|
| 0 | a fixed 11-slot register/stack window | nothing inferred |
| 1 | `subexit`, `EXIT0`, invocation nonce | Daikon's format, verified against Kvasir |
| 2 | **argument count** | use-before-def on caller-saved registers |
| 3 | return value, signed values, comparability | last `rax` write; observed operand widths |
| 4 | *skipped* | measured as a no-op, evidence recorded |
| 5 | heap model | `.rela.plt` survives stripping, so `malloc` is interceptable |
| 6 | pointee structs | access footprints per pointer argument |
| 7 | arrays | `length x width == allocation size`, or a correlated length argument |
| 8 | **global variables** | section headers + `.symtab` + RIP-relative operands |
| 9 | floating point | `xmm0`-`xmm7`, width from the mnemonic |

Speculative heuristics stay behind flags so their contribution is separately
measurable - the standing rule after one of them was found to cost 22 points of
precision for 3 of recall.

**Program input** (`--argv`, `--argv-file`) runs the target once per input vector
and merges every sample into one trace. On 501 vectors this is **30x faster than
Kvasir** (11s against 329s), because Kvasir pays process startup each time and
we re-enter one emulator.

---

## Layout

```
scripts/
  unicorn_dwarf.py        CLI shim
  tracer/                 12 modules; log/schema/writer/memmap/infer/deref/
                          alloc/globalvars are PURE - no unicorn, no capstone,
                          no pyelftools - and a test enforces that
  score_invariants.py     P/R/F1 against Kvasir. DWARF is read HERE and only
                          here, to align names; feeding it back would
                          invalidate the experiment
  audit_soundness.py      is every emitted fact true on the samples we
                          ourselves recorded?  (1000 checked, 0 false)
tests/                    C fixtures
tests_py/                 434 tests, including golden .dtrace baselines
test.sh                   run both front-ends over a corpus
docs/                     see below
```

### Documentation

| | |
|---|---|
| [HANDOFF.md](docs/HANDOFF.md) | **start here in a new session: current state, audit results, next steps** |
| [OBSERVABILITY.md](docs/OBSERVABILITY.md) | **what is observed, what is derived, and case-by-case coverage** |
| [TOOL.md](docs/TOOL.md) | how it works, and the bug behind each technique |
| [EVALUATION.md](docs/EVALUATION.md) | the fixture corpus, measured |
| [EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md) | Daikon's own suite, and `tcas` |
| [VERIFICATION.md](docs/VERIFICATION.md) | what is provable, what is checked, what cannot be |
| [FORMAL-METHODS.md](docs/FORMAL-METHODS.md) | where formal reasoning would sharpen the heuristics |
| [RELATED-WORK.md](docs/RELATED-WORK.md) | **how prior research approached each open problem, what we rediscovered, and the methods it suggests** |
| [HEURISTICS.md](docs/HEURISTICS.md) | **every inference rule the tracer uses, with its strengths, flaws and a soundness verdict** |
| [plans/](docs/plans/) | per-phase design with falsifiable acceptance criteria |

---

## Running it

Requires Linux (Kvasir needs Valgrind), a built Daikon tree in `$DAIKONDIR`, and
a venv with `unicorn`, `capstone`, `pyelftools`, `pytest`.

```bash
# trace one binary
python scripts/unicorn_dwarf.py prog.exe -o prog.dtrace --tier 8

# drive it with real input, many runs merged into one trace
python scripts/unicorn_dwarf.py tcas.exe -o tcas.dtrace --tier 8 \
       --argv-file vectors.txt --gzip

# score against Kvasir
python scripts/score_invariants.py --kvasir k.txt --tracer t.txt --binary prog.exe

# the corpus, both front-ends
DAIKONDIR=/path/to/daikon ./test.sh --tier 8
```

`--gzip` is worth it: the output is extremely repetitive - on `bc`, all 154,550
array-global samples were byte-identical to the one before - so 131 MB becomes
1 MB, and Daikon reads `.dtrace.gz` natively.

---

## Known limits

Stated rather than hidden. [RELATED-WORK.md](docs/RELATED-WORK.md) maps each
one to prior research and a proposed method. The ones that are structural:

- **Names are gone.** Permanently. The scorer supplies them from DWARF purely
  to align two reports.
- **Two same-width types the program never distinguishes.** A `double` never
  loaded as a double is a `long`. ~5% of a real oracle, and genuinely
  irreducible.
- **Completeness.** A dynamic analysis sees executed paths only. A parameter the
  callee never reads is still recovered at -O0, because the prologue spills it
  (`test_dead_parameters_recovered_at_O0`); at -O1 and above only a call-site
  analysis could recover it, and none is built.

And the ones that are work not yet done:

- **One level of dereference** by default. 54% of the remaining gap.
- **A struct passed by value** breaks argument counting in both directions -
  measured 6 wrong out of 6.
- **The order of a mixed int/float parameter list** is not in the register
  assignment, because the ABI numbers the two sequences independently. The
  tracer puts floats last and the scorer aligns by position, so these lists are
  scored under swapped names. At -O0 the prologue reads argument registers in
  declaration order, which recovers the order on the one such signature in the
  corpus; nothing uses that yet.
- **Daikon's runtime grows with the square of the variables declared per program
  point.** We declare 114 on `bc`, 112 of them globals, and Daikon takes 841s;
  omitting the 22 array globals takes it to 12s. Kvasir's 36s on `bc` is not a
  fair comparison: that run used `bc`'s own Makefile, which passes
  `--ignore-globals`. A like-for-like comparison has not been run.
- **No stdin or file input.** `argv` and `atoi` are modelled; `fgets` unlocks one
  more program, `fopen`/`read` three more.

## Things that turned out not to be true

Kept because being wrong in public is the useful part of a research log.

- *"Kvasir reports parameters, pointees and `return` only."* It reports globals
  too, and they are **80% of everything it says**. The claim survived eight
  phases because no fixture had a global.
- *"Signedness is not dynamically observable."* The value carries none, but the
  *opcode* does - `shr` versus `sar`. A test that deliberately asserted the
  wrong answer was written to fail if this was ever disproved. It failed.
- *"Modbits are the clearest remaining precision lever."* Daikon recomputes
  every modbit from the previous printed value and never reads ours.
- *"Delta-encoding the trace is impossible."* Impossible in the *unmodified*
  format; a two-line patch would accept it. It would also buy nothing, because
  gzip already exploits the same redundancy and the cost is not the bytes.
- *"The four shapes forced onto the wrong answer have one cause: bulk copies."*
  They have three. A copy's wide loads erase narrower stores in the evidence; a
  rule admits a struct only when member widths differ; and an array of structs
  was never a hypothesis. The copies were unrolled, one instruction per offset,
  so the planned per-instruction fix could not have seen them. Found by reading
  the machine code during the literature review.
- *"The tracer sees every byte Kvasir sees."* Not where a library call the
  emulator skips would have changed memory: `memcpy`, `memset`, `strdup`,
  `strlen` and `toupper` are called in nine of the 29 suite programs. Equal
  sample counts could not show it.
