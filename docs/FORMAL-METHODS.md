# Formal methods on top of the heuristics: how far can the approximation be pushed?

A design review, not a verification report. [VERIFICATION.md](VERIFICATION.md)
asks what can be proved about the tool as built. This asks the opposite and more
useful question: **where would formal reasoning make the heuristics sharper than
guessing, and where can it add nothing?**

---

## 0. What "formal methods on top of heuristics" means here

Not "replace the heuristics with proofs." The heuristics are doing the work that
information-theoretically *can* be done; the question is what a formal layer
wraps around them. Four distinct roles, in increasing cost:

| role | what it does | what it buys |
|---|---|---|
| **quantify** | enumerate the hypotheses consistent with the evidence | turns a silent guess into a measured ambiguity |
| **constrain** | add constraints until the space collapses | makes the answer *forced* rather than chosen |
| **certify** | mark which outputs are entailed vs conjectured | tells the fuzzer where to spend its budget |
| **bracket** | sound over-approximation ∧ precise under-approximation | where they meet, the result is proved |

The tool currently does none of these. It picks one hypothesis and does not
record that there were others.

---

## 1. The measurement that says this pays

I enumerated, for all 72 globals with a known extent in the Kvasir suite, the
shapes consistent with the evidence the tracer actually has.

```
with extent alone (no access evidence):
  shape FORCED (exactly one hypothesis):   0 / 72
  ambiguous (2-5 hypotheses):             72 / 72

with extent + a uniform 4-byte access width:
  shape FORCED:  16 / 72       ambiguous: 56 / 72
```

**Not one global is determined by its extent.** Every shape decision the tracer
makes is a choice among 2-5 consistent alternatives, made silently.

Then: how often is that choice right? Comparing our decision against DWARF:

```
globals emitted: 72    shape correct: 64  (88%)

truth \ ours     scalar   array  struct
scalar               50       0       0
array                 0      14       0
struct                0       8       0
```

**88% accurate — and the error is perfectly structured.** Scalars 50/50, arrays
14/14, structs **0/8**. Every struct is called an array.

That is not an 88%-accurate heuristic. It is a **rule that is exactly right on
the hypotheses it considers and exactly wrong on the one it never enumerates** —
`objects_from_symbols` has no struct branch, so `struct` is not in its output
alphabet at all. An 88% score conceals a 0% score on a third of the type system.

This is precisely the failure mode hypothesis enumeration prevents. Not because
enumeration picks better, but because **a hypothesis you never list cannot be
scored, and a hypothesis space you never print cannot be seen to be missing one.**

---

## 2. Where formal machinery applies, ranked by value per unit of work

### (a) Enumerate hypotheses; emit what is invariant across them — cheapest, do first

For each object, compute the set `H` of shapes consistent with all evidence.
Then emit only the facts true under **every** `h ∈ H`.

That converts a guess into a claim that is **sound relative to the evidence**:
not "this is an array of six ints" but "whatever this is, these facts hold."
Where `|H| = 1` the shape is *forced* and can be asserted outright — and the
measurement above says that happens 0% of the time on extent alone and 22% with
a width constraint, so the honest default today is closer to "report the
ambiguity" than "pick one."

It attacks precision directly, which is where the remaining headroom is: the
measured cause of 64% of our false positives is the **wrong noun** — six correct
values described as struct fields instead of an array. Under invariance
filtering those six facts are simply not emitted, and the one fact both
hypotheses agree on still is.

Cost: a few hundred lines. No solver. Measurable in one afternoon against the
existing corpus. **Expected: precision up, recall down**, and the trade
measured rather than argued — exactly how `--infer-from-caller` was settled.

### (b) Bracket arity between a static over- and a dynamic under-approximation

Use-before-def over an execution is an **under-approximation**: it sees the
paths that ran. A standard liveness/reaching-definitions analysis over the
recovered CFG is an **over-approximation**: it sees all paths but cannot rule
out infeasible ones.

```
dynamic (under)  ⊆  true parameter set  ⊆  static (over)
```

Where the two coincide, **the arity is proved**, not guessed. Where they differ,
the interval is a quantified bound and the difference is exactly the set of
parameters the run failed to exercise — which is *actionable input for the
fuzzer*: those are the arguments it should try to reach.

This also addresses the biggest standing risk in
[VERIFICATION.md](VERIFICATION.md): six Tier-B premises hold only at -O0 and
have never been tested. A static over-approximation does not depend on the -O0
prologue shape at all.

### (c) Constraint-based type inference instead of independent local rules

Today each heuristic decides alone: range check for pointer-ness, tiling for
arrays, consuming opcode for signedness. They never talk, so **when two
disagree, nothing notices.**

The principled form (TIE, Retypd) generates constraints from instruction
semantics — `mov eax,[rdi+8]` yields *rdi is a pointer* ∧ *offset 8 has width
4*; `shr` yields *unsigned*; a comparison against a known pointer yields
*pointer* — and solves globally over a subtype lattice. Three things fall out
that we cannot currently get:

1. **Conflicts become unsat**, hence detectable, instead of silently resolved by
   whichever rule ran last.
2. **Propagation**: knowing a value is `int*` at one site constrains every other
   site that value reaches. Our per-(function, slot) keying throws that away.
3. **The size of the solution set is the ambiguity measure** from (a), computed
   for free rather than by separate enumeration.

The struct-vs-array error is the case in point. Adding `struct` to the alphabet
does not fix it — it makes array and struct both consistent. The discriminating
constraint is **heterogeneous access widths at fixed offsets**, which is
observable, is already recorded in `GlobalAccessMap`, and is not currently
consulted.

Cost: the largest item here. The conflict-detection subset alone is worth doing
first and is much cheaper than the full lattice.

### (d) Verify Daikon's output — the Houdini architecture, and the best fit for the fuzzing loop

This is the pairing from Daikon's own literature: **dynamic detection proposes,
static verification discharges.** Daikon + ESC/Java did exactly this; the binary
analogue is weakest-precondition over the recovered IR discharged by an SMT
solver.

Applied here, every emitted fact carries one of two labels:

- **CERTIFIED** — entailed by the code, for all inputs. No longer a conjecture.
- **CONJECTURED** — true on the samples, unproved.

For a fuzzing loop that distinction is worth more than any precision gain,
because it tells the fuzzer where budget can possibly pay off. Attacking a
certified invariant is provably wasted work. Today the loop has no way to tell
the two apart and must treat every fact as equally worth attacking.

Undecidable in general; entirely tractable in the fragment that matters — linear
arithmetic over scalars in single, loop-free, -O0 functions, which is most of
both corpora. Start there and report coverage honestly.

### (e) Abstract interpretation for sound invariants directly

Polyhedra or octagon domains compute sound over-approximations of the reachable
state. Intersecting those with Daikon's conjectures is another route to the
CERTIFIED/CONJECTURED split in (d), and a stronger one where loops are involved.
Higher cost, and (d) subsumes most of the value for our corpus.

---

## 3. What formal methods cannot do here

Worth stating plainly, because the appeal of a solver is that it looks like it
might do all of it.

- **No solver creates information.** The measured ~5% residue — a `double` the
  program never loads as a double, an `unsigned` never shifted or compared — is
  not ambiguity to be resolved. The distinction is *absent from the execution*.
  A constraint system will correctly report both hypotheses as consistent, which
  is an improvement in honesty, not in recall.
- **Names stay gone.** Nothing recovers them; the scorer supplies them from
  DWARF for alignment only.
- **Dynamic incompleteness stays**, except insofar as (b)'s static half covers
  unexecuted paths — which is exactly why bracketing is the highest-value
  structural change.
- **Undecidability is real** but mostly irrelevant at this scale: the functions
  in both corpora are small and mostly loop-free. The honest framing is a
  decidable fragment plus a coverage number, not a claim of full verification.

---

## 4. This changes the metric, and the metric is the research output

P/R/F1 against Kvasir measures agreement with a fallible oracle — one that has
already been caught reporting facts false on its own data (3 found so far). It
cannot express "we were right to be uncertain."

Under the formal framing, three better numbers become available:

| metric | meaning | measurable today? |
|---|---|---|
| **soundness rate** | emitted facts true on our own samples | **yes — 1001/1001, 0 violations** |
| **certified fraction** | facts entailed by the code, not just observed | needs (d) |
| **ambiguity residue** | mean hypotheses consistent with the evidence | needs (a); measured at 2-5 for globals |

The first is already implemented and already found a real defect
([scripts/audit_soundness.py](../scripts/audit_soundness.py)). The other two are
the interesting ones, and **"how far can the approximation be pushed" is exactly
the question `ambiguity residue` answers**: it falls as constraints are added,
and where it reaches 1 the heuristic has become a derivation.

---

## 5. Recommended order

```
1. hypothesis enumeration + invariance filtering        (a)  cheap, precision
2. struct hypothesis + width-heterogeneity constraint   (c-lite)  fixes 0/8
3. static liveness to bracket arity                     (b)  certifies, kills the -O0 premise risk
4. conflict detection across existing heuristics        (c)  cheap subset of the lattice
5. WP+SMT certification of linear facts                 (d)  the fuzzing-loop payoff
```

1 and 2 are days and attack a measured defect. 3 is the one that turns a stated
premise into a proved property. 5 is the one that changes what the output *is*.

**The honest headline:** the heuristics are not sloppy — they are exactly right
on 64 of 72 shape decisions and sound on 1001 of 1001 checked facts. What they
lack is any representation of their own uncertainty, and that, rather than
accuracy, is what a formal layer would supply.
