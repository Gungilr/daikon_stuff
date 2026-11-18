# Project results: what this repository measured about why binary type recovery is hard

Scope: the black-box Unicorn-based tracer in /home/user/daikon_stuff (writes Daikon traces from stripped x86-64 binaries), scored against Kvasir (Daikon's DWARF-based front end) on Daikon's own Kvasir test suite, plus the ReSym / Ghidra / TypeForge / retypd experiments. All sources are repository files (paths relative to /home/user/daikon_stuff). No web research. Numbers are quoted as written in the files. Anything not found in a file is marked **"from conversation, not in docs"**. One item was re-measured by running a repo script; it is marked **"re-run during this research"**.

Scoring method (applies to every P/R/F1 below): `scripts/score_invariants.py` compares invariant *content*, not counts. It (1) maps the tracer's `arg0`, `arg0[].off4`, `g_0x404060` onto Kvasir's names using DWARF read at scoring time only ("This is the one place DWARF is allowed; feeding it back into the tracer would invalidate the whole experiment"), (2) canonicalises linear relations, (3) excludes oracle facts that are false on Kvasir's own samples (the `is_param` defect) — [scripts/score_invariants.py docstring](scripts/score_invariants.py). `scripts/score_diagnose.py` assigns each missed fact a cause (`var-absent`: a variable it mentions is not declared at that program point in our trace; `form`; `other`) and each extra fact a cause (`var-unknown`: mentions a variable Kvasir does not declare; `form`; `other`) — [scripts/score_diagnose.py docstring](scripts/score_diagnose.py). "Soundness" below means `audit_soundness.py` checks our facts against our own samples.

---

## 1. Suite baseline and history (tier 7 → 8 → 10)

### Takeaway
On code written by others, the tracer went from F1 6% (tier 7) to 19% (tier 8, globals) to 24.3% (tier 10, object model); the current tier-10 baseline is 1,255 matched of 5,419 oracle facts (precision 25.4%, recall 23.2%, F1 24.2%). Against the project's own ten fixtures the same tool scores 65/92/76 — the gap between the two corpora is itself the main finding.

### Cited findings
- Own corpus (10 fixtures written alongside the tool), after phase 8: 155 matched of 172 oracle facts (169 valid), precision 65%, recall 92%, F1 76%; baseline 2026-09-17 was 59/84/69 — [docs/EVALUATION.md](docs/EVALUATION.md)
- First run on Daikon's Kvasir suite (29 programs, tier 7, `--infer-unobserved-fields --poison-uninitialized`): 4,778 oracle facts, 1,352 ours, 176 matched, **precision 13%, recall 4%, F1 6%** — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
  - non-global scope: 977 oracle facts, 176 matched, 13% / 18% / 15%; "genuinely plain scalars and returns": 159 oracle facts, 111 matched, recall 70% (50% including by-value struct members) — same file
  - "`small-test` is the only program in the suite whose shape resembles my corpus ... and it is also the best result" (45% precision, 55% recall) — same file
- History table on the suite — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md) §Phase 9; [docs/plans/phase9.md](docs/plans/phase9.md); [docs/plans/phase10.md](docs/plans/phase10.md):
  - tier 7: 1352 facts, 176 matched, 13% / 4% / 6%
  - tier 8 (globals): 3576 facts, 802 matched, 22% / 17% / 19% ("4.6x the matched facts, with precision rising too")
  - tier 9 (+ floating point): 3569 facts, 799 matched, 22% / 17% / 19%
  - tier 8 + strided-access discriminator (on by default): 3428 facts, 822 matched, 24% / 17% / 20%
  - tier 8 + `--deref-globals`: 6111 facts, 978 matched, 16% / 20% / 18%; `--struct-globals`: 4064 / 679 / 17% / 14% / 15% (−123 matched); both: 7133 / 973 / 14% / 20% / 16%
- Tier 8 → tier 10 (phase 11, 30 programs) — [docs/plans/phase11.md](docs/plans/phase11.md) §Results (2026-11-02):
  - tier 8 documented baseline: 3905 ours, 912 matched, 23.4% / 16.8% / 19.6%
  - **tier 10 depth 2 (default): 4935 ours, 1256 matched, 25.5% / 23.2% / 24.3%** (+344 matched, precision up)
  - `--deref-depth 1`: 4803 / 1256 / 26.2% / 23.2% / 24.6%; `--deref-depth 3`: identical to depth 2
  - `--shadow` instead of poison: 5056 / 1241 / 24.5% / 22.9% / 23.7%
  - `--rodata-strings`: 4920 / 1282 / 26.1% / 23.7% / 24.8%
- Rebuilt-toolchain tier-10 baseline (used by all hint experiments): Kvasir oracle "reproduces exactly (5,419 facts)"; **4,934 ours, 1,255 matched, 25.4% / 23.2% / 24.2%**, "one fact off the 1,256 recorded earlier" — [docs/plans/struct-hints.md](docs/plans/struct-hints.md)
- Observation is not the problem: sample counts per program point identical on 198 of 198 (100%), "We are watching the same execution. Whatever is lost is lost in description, not observation." — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
- Soundness: 0 false facts of 6717 audited (suite + own corpus) at tier 10 — [docs/plans/phase11.md](docs/plans/phase11.md); at tier 7, 10 of 1176 unmatched facts were checkable and all 10 held — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
- Arity (use-before-def) exact on 81 of 99 functions (82%); all 18 failures are by-value structs (6) or floats (8) or knock-ons — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
- One-line summary in the repo: "the tracer's observation is perfect and its vocabulary is small ... Stripping does not destroy the data; it destroys the vocabulary for talking about it." — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)

### Inferences
- Precision and recall rising together at tiers 8 and 10 means added *description* (correct nouns), not noise; the mechanisms that lowered precision (`--deref-globals`, `--infer-from-caller`) were the ones that guessed types.
- The oracle grew from 4,778 facts (29 programs, tier-7 doc) to 5,419 (30 programs, rebuilt toolchain); shares are not directly comparable across those two denominators.

### Gaps
- Baseline drift: 1,256 (phase11.md, resym-hints.md) vs 1,255 (struct-hints.md, static-type-tools.md, after container rebuild). Cite the one matching the experiment.

---

## 2. Decomposition of what is missed (and what is extra)

### Takeaway
Most of the gap is type information, not missing observation: of 4,163 missed facts at tier 10, 3,396 are about globals, 411 are struct field layouts behind parameters, 184 are float/int parameter order (unrecoverable by anyone), ~370 are by-value structs, and only ~60–85 are fixable by a parameter type. Re-running score_diagnose: 82.1% of misses mention a variable absent from our trace, and 65.9% of extras mention a variable Kvasir does not declare.

### Cited findings
- Tier-7 oracle by shape (4,778 facts): 4462 (80.5%) global variables; 486 (8.8%) two or more levels of dereference; 298 (5.4%) one level; 238 (4.3%) plain scalars and returns; 31 (0.6%) string contents; 28 (0.5%) float/double values. "Four percent of this oracle is the shape the tool was built for." — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
- Tier-7 extras (1176 unmatched): 750 (63.8%) name something the oracle never declares; 426 (36.2%) are about real oracle variables, unstated. "our precision problem is not 'we assert things that are false'. It is 'we assert things about the wrong nouns'" — same file
- Post-tier-8 misses (3,975) by the single missing fact: 2142 (53.9%) pointer inside a struct, 2+ levels deep; 809 (20.4%) global pointer/array → sequence; 355 (8.9%) bytes are a struct with members; 215 (5.4%) local pointer/array; 254 (6.4%) other; 110 (2.8%) 8 bytes are a double not a long ("only from a consuming opcode"); 90 (2.3%) `char*` is a string. "88.6% of what remains is type information already present in the execution and not acted on. Only 5.1% needs a signal the bytes do not carry." — [docs/plans/phase10.md](docs/plans/phase10.md)
- Dereference depth per oracle fact: depth 0 1774 (32.0%), 1 1706 (30.8%), 2 1436 (25.9%), 3 244 (4.4%), 4+ 383 (6.9%); limit 2 covers 88%, limit 3 covers 93% — [docs/plans/phase10.md](docs/plans/phase10.md)
- **Tier-10 missed facts (5,419 oracle, 1,256 matched, 4,163 missed)**, by `scripts/rea_eval/hint_ceiling.py` — [docs/plans/resym-hints.md](docs/plans/resym-hints.md) Step 0:
  - about globals: **3,396** — not fixable by a parameter type
  - struct field layouts (`f.char_10`, `m[].mapName`): **411** — needs field types
  - float/int parameter order (`initBasicTypesStruct`, `doubleAdd`): **184** — "no, by anyone: machine code does not record how int and float parameters interleave"
  - scalar-pointee arrays (`u[]`, `a[]` in IntTest): ~46 — yes
  - `char*` as a string: 13 — yes
  - `char**`/`char***` chains: ~25 — yes, harder
  - other: ~90 — mostly no
  - "Ceiling: about **60–85 facts**, i.e. +1.1 to +1.6 recall points (23.2% → ~24.8%), even with perfect types."
  - globals described as "82% of what is missed" (same file, §What this will not do) and "63% of all oracle facts" (same file, §What would move the number)
- Struct-field share of the 4,163 misses ("about 3,200 involve struct fields") — [docs/plans/struct-hints.md](docs/plans/struct-hints.md):
  - fields of structs behind global pointers (`::p->x`): 947
  - fields of struct-valued globals (`::g.x`): 822
  - fields of global arrays (mostly of structs): 659
  - fields of structs behind parameters (`f[].x`): 411
  - fields of structs passed or returned by value (`f.x`, `return.x`): **~370** (out of scope: not modelled)
- **score_diagnose on the tier-10 suite (re-run during this research**, `python3 scripts/score_diagnose.py --bins bench/ksuite --kv-inv bench/ksuite_inv --tr-inv bench/ksuite_inv --traces bench/ksuite_traces --kv-traces bench/ksuite_traces`): matched 1255, missed 4164, extra 3679; **missed: var-absent 3420 (82.1%)**, of which var-absent (global) 2667 (64.0%); **extra: var-unknown 2426 (65.9%)**; extra: other 1037 (28.2%). The 82% / 66% figures are **not stated in any docs file** (from conversation; confirmed by this re-run) — [scripts/score_diagnose.py](scripts/score_diagnose.py)
- Information-theoretic residue: "A `double` the program never uses as a double (`GlobalTest`) ... an `unsigned` never shifted or compared. ... measured at roughly 5% of the oracle." Names are "Permanently destroyed by stripping" — [docs/plans/phase10.md](docs/plans/phase10.md); [docs/plans/phase11.md](docs/plans/phase11.md)
- Worked example of "right bytes, wrong noun": ArrayTest `returnIntSum(int a, int* b)` — Kvasir `b[] == [61, 61, 62, 63, 65, 68]`, ours six fields `arg1[].off0..off20` with exactly those values; "We recovered the array perfectly and then described it as a struct, so of the three oracle facts we match one and contribute six unmatched ones." Stack array: no length argument, no malloc record, so the array model correctly abstains — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)

### Inferences
- 82% of misses are about variables we do not even declare, so most of the gap is "which variables/objects exist and what shape they are" (object identity and type), not wrong values. 66% of extras are about nouns Kvasir does not have (`g_0x...`, `offK`), the mirror image.
- The categories that defeat everyone (int/float interleave order, never-used-as-double, names) are a small but hard floor (~184 facts + ~5%).

### Gaps
- score_diagnose did not print counts for the `missed: form`/`missed: other` and `extra: form` buckets in the summary I captured (only the four rows above were printed); I did not investigate.

---

## 3. Specific hard shapes, each with its measured cost

### Takeaway
Each failure class traces to a type fact the machine code does not carry: by-value structs break arity both ways, float arguments were invisible and their interleaving with ints is unrecoverable, statically initialised structs leave no run-time evidence, a pointee the callee never touches is unobservable, and stack arrays have no bound.

### Cited findings
- **By-value structs: 6 of 6 functions get the wrong arity.** `baz(struct foo f)` 1 real param → 18; `createCopy` 2 → 9; `fcrashint` 2 → 7; `bar(Buffer)` 1 → 0; `barMaps(struct map)` 1 → 0; `readStruct` 1 → 2. A 252-byte parameter read a word at a time "becomes eighteen"; `arg8 == 4614256650576692846L` is the `double c = 3.14159` of a by-value struct. A returned struct in `rax:rdx` has no counterpart. It also caused a crash (`IndexError` in `_finalize`, n_stack = 32 vs `MAX_STACK_PROBE = 12`) — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md); [docs/TOOL.md](docs/TOOL.md) §7
- **Float parameters invisible, 8 of 8** at tier 7 (FloatTest functions seen as nullary; `REG_ARG_ORDER` lists only integer registers). Tier 9 fixes visibility but "is a genuine trade": FloatTest recall 24% → 35% (+9 facts), everything else −12 facts, because "the ABI numbers integer and SSE arguments independently, and nothing in the machine code records how they interleaved ... Integer-first is a convention, not a recovery." — [docs/plans/phase9.md](docs/plans/phase9.md); [docs/TOOL.md](docs/TOOL.md)
- **Functions that never touch their arguments:** `bazMapPtr(struct map* m) { return 500; }` — Kvasir 21 facts, ours 1. "These programs exist to test a type-driven traversal, so their functions deliberately do nothing." `--infer-from-caller` costs 22 points of precision for 3 of recall on the own corpus (precision 65% → 43%) because "nothing observable bounds a stack object" — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md); [docs/TOOL.md](docs/TOOL.md); [docs/plans/phase11.md](docs/plans/phase11.md)
- **Struct-shaped globals (`--struct-globals`) failed in three attempts**, measured against DWARF on 72 globals: baseline 88% shape accuracy, structs 0/8; + heterogeneous access widths 87%, 0/8; + pointer-shaped value 86%, 0/8. Reason: "a statically-initialised struct is never written at run time", while an int array copied 8 bytes at a time *does* produce mixed widths — [docs/plans/phase10.md](docs/plans/phase10.md)
- **Double-typed globals by static SSE scan: zero hits** (FloatTest 8 SSE-touched data addresses naming known globals: []; GlobalTest 0; TrivialTest 1, []) — addresses were constant-pool literals; `GlobalTest` never loads `globalDouble` as a double — [docs/plans/phase10.md](docs/plans/phase10.md)
- **Global size from a stripped binary:** RIP-relative operands find 6 of 6 globals on GlobalTest but only 64% across the suite ("an array touched solely as `arr[5]` yields base+20 and no base"); `.symtab` gives the one fact "no dynamic signal can recover: an `int[18]` and eighteen adjacent `int`s produce identical access evidence" — [docs/plans/phase9.md](docs/plans/phase9.md)
- **65 of the 85 globals we emitted were pointers**, all printed as integers where Kvasir prints a sequence (pre-tier-10) — [docs/plans/phase10.md](docs/plans/phase10.md)
- **Signedness** observable only through a consuming opcode; a never-shifted/compared `unsigned` high-bit value reads back negative — [docs/TOOL.md](docs/TOOL.md) §7
- **Uninitialised memory:** poison fill `0xAB`, "a genuine `0xABABABAB` is misread"; exact definedness needs shadow memory. `--shadow` alone is −15 matched (tracks heap only, as Kvasir does) — [docs/TOOL.md](docs/TOOL.md) §4.10/§7; [docs/plans/phase11.md](docs/plans/phase11.md)
- **Oracle itself is configured at scale:** Daikon's authors run `bc` and `perl` with `--ignore-globals`, `perl` with `--nesting-depth=1`; the three largest programs (bzip2, gzip, perl) have no `.invs.goal`; `space` declares 21,134 variables across 272 program points — [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)
- **Oracle defect:** Kvasir's `is_param` flag makes Daikon drop non-unit coefficients; 3 of 172 own-corpus oracle facts are false on Kvasir's own samples (e.g. `return - orig(a) - 1 == 0` for `return = 2a + 1`) — [docs/plans/README.md](docs/plans/README.md); [docs/EVALUATION.md](docs/EVALUATION.md)
- **The corpus hid the problem:** the claim "Kvasir reports parameters, pointee views and `return` only" survived 8 phases because no fixture had a global; globals turned out to be 80% of the suite oracle — [docs/plans/README.md](docs/plans/README.md); [docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md)

### Inferences
- Several classes (statically initialised structs, untouched pointees, never-used doubles) fail because the evidence does not exist at run time; static tools can only help where code has the access but the run did not execute it.

### Gaps
- None beyond those noted.

---

## 4. DWARF oracle ceilings (perfect types fed as hints)

### Takeaway
Even perfect types add little through parameters: perfect parameter types are worth +34 (rebuilt toolchain; +37 originally); perfect struct layouts through parameters only are worth +40 (touched fields) to +128 (full); including globals, layouts are worth +235 (touched) to +533 (full), i.e. F1 24.2% → 34.6% at most.

### Cited findings
- Parameter-type ceiling, first measurement (2026-11-05): baseline 4,935 / 1,256 / 25.5% / 23.2% / 24.3% → + DWARF hints 4,974 / **1,293** / 26.0% / 23.9% / 24.9% (**+37**). Gate was +40, "failed narrowly". Per binary: IntTest +31, NestedStructTest +5, StaticArraysTest +4, string-arrays +2, crazy-test-1 −4, static-struct −1. 25 hints applied, 11 refuted (e.g. `returnIntSum` returns `(char****)0xDEADDEAD`, not an address). "Perfect parameter types are worth +0.7 recall points on this suite" — [docs/plans/resym-hints.md](docs/plans/resym-hints.md)
- Struct-layout ceilings (rebuilt toolchain, after merge fixes) — [docs/plans/struct-hints.md](docs/plans/struct-hints.md):
  - tier 10 baseline: 4,934 / 1,255 / 25.4% / 23.2% / 24.2%
  - + parameter types: 4,975 / **1,289 (+34)** / 25.9% / 23.8% / 24.8%
  - + struct layouts, fields the run touched: 4,580 / **1,490 (+235)** / 32.5% / 27.5% / 29.8%
  - + full struct layouts: 4,924 / **1,788 (+533)** / 36.3% / 33.0% / 34.6%
  - DWARF via parameters only, touched fields: 4,937 / **1,295** (+40) / 26.2% / 23.9% / 25.0%
  - DWARF via parameters only, full layouts: 4,969 / **1,383** (+128) / 27.8% / 25.5% / 26.6%
  - soundness 0 violations on both struct runs; 33 layouts applied, 2 refuted
- Per binary (pre-merge-fix, totals then 1,776 / 1,479): ArrayTest 110 → 311 full / 164 observed; MultiDimArrayTest 10 → 79 / 73; ArraysInStructTest 17 → 79 / 79; static-struct 121 → 179 / 120; StructPtrTest 5 → 38 / 5; IntTest 51 → 82 / 82; NestedStructTest 44 → 73 / 49; CoercePointerTest 35 → 63 / 35; crazy-test-1 153 → 149 / 149. In ArrayTest typed fields shrink output 744 → 412 facts while matching 201 more — [docs/plans/struct-hints.md](docs/plans/struct-hints.md)
- "The extra +297 of the full ceiling is untouched fields ... No binary-only source can know those. They need real struct definitions (headers, debug info from a related build)." — same file
- "Even the touched-fields-only ceiling (+224) is 6× what perfect parameter types bought (+34)" — same file (note: +224 is the pre-merge-fix figure; the table after fixes says +235)

### Inferences
- The headroom is in layouts of globals and untouched fields, which are exactly what a function-local, use-driven type predictor cannot see.

### Gaps
- +37 vs +34 and +224 vs +235 are the same ceilings measured before/after a toolchain rebuild and merge fixes; the files give both.

---

## 5. ReSym (learned type recovery) results

### Takeaway
ReSym reproduces locally (66.5% exact, 85.9% class on its own IDA test data) but on Ghidra output for the suite it gets 69% of type facts and 41% exact types right, and adds ±0 matched facts; binary evidence can filter its answers but cannot fix names, and its 4 beams almost never disagree on type.

### Cited findings
- **Local reproduction** (VarDecoder, StarCoderBase-3B fine-tune, CPU, beam 4; 200 functions, 778 labelled variables from ReSym's `vardecoder_test.jsonl`): type exact **66.5%** (authors' published predictions on same vars 66.8%); coarse class **85.9%**; identical to authors' prediction 93.6%; 7.7 h total, median 86 s/function. Common class errors: `int` → project type name (14), struct → struct pointer (6), `void*` → named-struct pointer (6), struct pointer → struct (5); wrong names like `hashtab*` → `hashmap_t*` — [docs/RESYM-LOCAL.md](docs/RESYM-LOCAL.md)
- **Evidence filter** on 30,865 parameter answers (94 binaries): ReSym alone 81.5% facts right / 57.7% exact; drop contradicted (94.3% kept) 84.8% / 58.1%; keep only supported (65.6% kept) 90.7% / 58.2%. Caught 22.9% of wrong answers, rejected 1.7% of right ones. "it cannot fix the exact type ... ReSym's main error is the type NAME, which no instruction or trace reveals." Tracer reached only 680 answers (2%) from `main` with no input — [docs/RESYM-LOCAL.md](docs/RESYM-LOCAL.md)
- **Rerank pilot** (20 functions, 94 parameter answers): top candidate contradicted on 26, only 26.9% of those right; a different-class alternative exists for 6 of 26 (23.1%); 2 of 26 replaced (7.7%), both right; "the 4 beams almost never disagree on a parameter's type; they differ in names" — [docs/plans/resym-rerank.md](docs/plans/resym-rerank.md)
- **ReSym on Ghidra pseudocode of the suite** (VarDecoder, 81 parameters, DWARF-scored): pointer vs scalar **96.3%**; type facts **69.1%** (vs 81.5% on its own IDA test set); exact type **40.7%** (vs 57.7%). Misses: signedness, width, invented struct names; IntTest's six parameters all wrong. FieldDecoder answers "not a struct field" for most accesses — [docs/plans/struct-hints.md](docs/plans/struct-hints.md)
- **Suite effect: ±0.** VarDecoder types 1,255; supported-only 1,256; VarDecoder + FieldDecoder 1,254 (24.9% / 23.1% / 24.0%), same with either evidence filter. Run refuted most of it: argument effects 3 applied / 10 refuted; layouts 2 applied / 6 refuted / 3 adding no field — [docs/plans/struct-hints.md](docs/plans/struct-hints.md)
- **Verification that ±0 is not an ingestion error** — [docs/plans/struct-hints.md](docs/plans/struct-hints.md) §Is the ±0 an ingestion error?:
  1. Input conversion neutral (self-test, 89 functions, 217 parameters from ReSym's test set): authors' predictions (IDA, all vars) 44.7% exact / 63.6% class; local IDA params-only **43.8%** / 62.7%; local **Ghidra converted 41.9%** / 64.1%. Parameter counts matched on all 89.
  2. Pipe test (`pipe_oracle.py`, DWARF truth through ReSym's output format): direct +33 types / +39 with touched fields; through ReSym path **+26 / +28**. Lost 11 facts because "Ghidra's decompiler drops parameters a function does not use (`void bar(struct foo *f) {}` decompiles as `void FUN_00401136(void)`)"; of 79 reached functions with parameters, Ghidra shows none for 31.
  3. Slot audit (110 integer-class argument slots): 66 reached ReSym (44 dropped by Ghidra); 38 answers have facts right, 29 of those with nothing to apply; only **16 slots** where the true type changes output: 8 dereferenced (ReSym right on 3, worth +1 total), 4 never dereferenced (ReSym wrong on all 4), 4 dropped by Ghidra. IntTest holds +31 of +33: `u` (`int*`) **+28**, `a` (`float*`) +2, `str` (`char*`) +1; `returnIntSum` only null-checks `u` and passes it on, ReSym answered `void*`, "which is what the code supports."
  - FieldDecoder audit (82 accesses): 25 are struct fields; ReSym labelled 25, only 5 overlap (all md5, wrong layout); called real struct pointers "not a struct".
  - Reading: "ReSym and the tracer read the same evidence: how the code uses a value. Where the code dereferences a pointer, ReSym can be right, but the run has already shown the tracer the same thing ... Where the code does not touch the pointer, a type would add a lot (IntTest's `u`), but ReSym has nothing to read either."
- **Ghidra's own types on the 94 ReSym test binaries** (18,551 functions, 44,366 parameters, 3,363 globals): fully exact for only ~22% of parameters, ~49% of returns, ~6% of globals; confidently wrong about the kind for 22% of parameters, mostly pointer called `long` (8,977 cases); pointee right 35% — [docs/plans/rea-type-checker.md](docs/plans/rea-type-checker.md)
- **Stage 1 static checker on Ghidra's answers:** wrong answers caught params **63.8%**, returns 16.9%, globals **87.4%**; right answers wrongly rejected 0.7% / 2.9% / 0.7%; pointer-called-integer errors caught **86.2% of 8,969** (params), 37.7% of 416 (returns); wrong kind before → after: params **22.9% → 4.5%**, returns 8.2% → 6.7%, globals 6.6% → 0.8%; any wrong detail params 34.4% → 12.4%. Ghidra abstained but evidence proposes a kind: 32.8% of params, right 95.9%. Returns weak: 3,153 of 4,806 answers have no evidence. Hand check 10/10 FAILs genuinely wrong, 10/10 PASSes right kind — [docs/plans/rea-type-checker.md](docs/plans/rea-type-checker.md)
- **ReSym type breakdown by class on the full test set** — struct pointers 30% of variables, 44% exact, 90% class: **from conversation, not in docs** (not found in RESYM-LOCAL.md or any plan file).

### Inferences
- Machine code reliably fingerprints kind (pointer vs scalar: 96.3%, checker catches 86.2% of pointer→long) but not names, signedness-without-ops, or the pointee of an unused pointer; learned models do not escape this on out-of-style or context-poor input.

### Gaps
- The by-class breakdown (struct pointers 30% / 44% / 90%) could not be located in the repository.

---

## 6. TypeForge and retypd (cross-function static tools)

### Takeaway
Both gave ±0 (1,255 = baseline). On -O0 programs every access executes, so static analysis sees nothing the run does not; their fields are mostly untyped; and neither carries a type into a passed-but-unused pointer (retypd's Ghidra front end does not model stack memory).

### Cited findings
- Results: baseline 4,934 / 1,255 / 25.4% / 23.2% / 24.2%; TypeForge layouts 4,934 / 1,255; TypeForge per-field refutation 4,938 / 1,255; retypd 4,952 / 1,255 / 25.3%; retypd per-field 4,952 / 1,255. 0 audit violations — [docs/plans/static-type-tools.md](docs/plans/static-type-tools.md)
- TypeForge (phase 1 only): 13 final + 7 ambiguous layouts in 10 of 30 programs; some good (DisambigTest `TestBuffer`, linked across functions from `main`'s local); small-test's `node` came out as two different layouts; **39 of 54 fields untyped**; only **3 parameters** get a layout, 2 refuted for real errors (field +8 `long` vs truth `int*`; `void*` vs `char[16]`) — same file
- retypd: 28 layouts; 12 parameters get one, 5 a pointer-to-scalar; layouts 7 applied / 3 refuted / 5 conflicting; pointer-to-scalar 1 applied / 5 refuted; fields mostly `char1_t[k]`. IntTest: `u` `char1_t[4]` (truth `int*`), `a` `int64_t` (truth `float*`), `str` `char1_t[4]*` (truth `char*`), only `b` right. "The array is on `main`'s stack, and the plugin's constraint generator does not model stack memory or address-taken locals. The one fact retypd was chosen for never reaches its solver." — same file
- "Static analysis of `-O0` test programs sees nothing the run does not ... on this suite every access executes, so the tracer has already recovered those offsets and widths (layout F1 89.7%)." — same file
- Corroborated by phase 11 step 6 (`--static-layouts`, Ghidra p-code): 36 parameters with static fields, 22 agree with run-typed structs, all 9 extra candidates correctly rejected, **0 fields added** — [docs/plans/phase11.md](docs/plans/phase11.md)
- "The DWARF-through-parameters ceiling (+40 touched, +128 full) is not reached by any binary-only source tried: ReSym, TypeForge or retypd." — [docs/plans/static-type-tools.md](docs/plans/static-type-tools.md)

### Inferences
- Static tools could matter on low-coverage real programs (unexecuted paths), which this suite cannot show (noted in the file itself).

### Gaps
- No corpus with low dynamic coverage and its own oracle has been measured.

---

## 7. Phase 11 layout recovery quality and its limits

### Takeaway
Where the run touches memory, layout recovery is good (layout F1 0.897, kind accuracy 100%), but invented fields (5.1%) come from wide copies, and limits are set by what never executes (globalBetterFoo) or is indistinguishable (three constant indices).

### Cited findings
- 89 typed sites tied to a DWARF pointee or global: **layout F1 0.897 (P 94.9%, R 85.1%)**; **invented fields 5.1% (9 of 176)**, target ≤5% "just over"; **kind accuracy 100% (141 of 141)**, wrong kind 0%; 26 fields abstained, one union abstained; shape right for 78.7% of sites — [docs/plans/phase11.md](docs/plans/phase11.md)
- The 9 invented fields: wide moves over narrower members never touched narrowly (struct copied by 8-byte loads in crazy-test-1, md5; zeroing store over `char` members in DisambigTest, ArraysInStructTest). "Nothing at run time separates such a copy from a real 8-byte field." — same file
- Kind accuracy reached 100% after "an 8-byte slot that only ever held 0 abstains (NULL and 0L read alike)"; before it, 4.7% wrong kinds were all never-dereferenced NULL pointers typed `int` — same file
- **NestedStructTest:** target >150 matched "not met, infeasible": 44 (10 before); "560 of its 677 oracle facts are about `globalBetterFoo`, which the program never touches; ~117 is the most any black-box tracer can reach" — same file
- **NestedStructVarList `counters[]`:** "not met, abstained: the program touches `counters[0]`, `[5]`, `[9]` with constant indices; that is byte-for-byte a struct with three `int` fields at +0/+20/+36, below Howard's 4-element stride threshold. Calling it an array would be a guess" — same file
- Depth 2 adds 132 true but unmatched facts over depth 1 (CoercePointerTest via a `void*` field Kvasir does not follow; small-test equality form) — same file
- Literal-pool defect caught by the audit: typing `.rodata` made `3.45` a double, and Daikon's fuzzy float equality asserted `arg1 == g_0x402018` — same file

### Inferences
- Layout recovery from observed accesses is near-ceiling for touched memory; the dominant losses are untouched objects and ambiguous array-vs-struct shapes.

### Gaps
- None.

---

## 8. Tracer defects found (value-level), incl. the IntTest prototype

### Takeaway
Value comparison exposed defects the soundness audit cannot see (the audit checks facts against our own samples): float return values equal to the first float argument in all 10 float-returning functions, and in IntTest's returnIntSum strings, pointees, uninitialised values and a pointer return printed wrongly.

### Cited findings
- **Float return bug:** "At EXIT, `_read_exit_args` restores the first float argument into the `xmm0` slot, and the return value is then read from that same slot." `doubleSub(15, -5246.54)` records `return = 15.0` (true 5261.54), Daikon reports `a == return`. Scope: **all 10 float-returning functions the suite reaches (FloatTest ×8, TypesTest ×2)**. Predates the hint work; "the soundness audit cannot see it" — [docs/plans/struct-hints.md](docs/plans/struct-hints.md) §Found along the way (note: phase9.md says tier 9 reads the spill slot at EXIT precisely to avoid `arg0 == return` — [docs/plans/phase9.md](docs/plans/phase9.md); the struct-hints finding shows the bug persists in another form)
- **Float print precision:** Kvasir prints a `float` with 9 digits (`100.345001`), tracer prints exact double (`100.34500122070312`); values agree, text does not — [docs/plans/struct-hints.md](docs/plans/struct-hints.md). Same pattern seen in score_diagnose `form` misses (`450.34515161339993 == a` vs ours `450.3451516134 == a`) — re-run during this research
- Historic defects in the same class (fixed): argument values at EXIT re-read from clobbered registers (`skip_middle` `arg0 == arg2` artifact); `is_param` coefficient defect — [docs/plans/README.md](docs/plans/README.md)
- **IntTest `returnIntSum`, level-2 value comparison prototype — from conversation, not in docs:**
  - `str` printed as the raw address 4202500 instead of the string "what's up dawg!!!"
  - `a[..]` (`float*`) pointee printed as an address instead of 2.718
  - `uninit` printed as -1414812757 (the 0xABABABAB poison fill) where Kvasir says nonsensical/uninitialised
  - the pointer return 0xdeaddead printed as 2.718, because the function was judged to return a double
  - Level-1/2 prototype numbers: 18 of 29 Kvasir variables declared; 21 of 30 shared values agree; plus 5 values printed where Kvasir says uninitialised
  - (Supporting, in docs: `returnIntSum` returns `(char****)0xDEADDEAD` — [docs/plans/resym-hints.md](docs/plans/resym-hints.md); -1414812757 = 0xABABABAB as signed 32-bit, consistent with the `0xAB` poison in [docs/TOOL.md](docs/TOOL.md))
- **IntTest today:** 108 oracle facts ([docs/EVALUATION-KVASIR-SUITE.md](docs/EVALUATION-KVASIR-SUITE.md) per-binary table, tier 7: 108 oracle / 58 ours / 10 matched); 51 matched at tier 10 baseline ([docs/plans/struct-hints.md](docs/plans/struct-hints.md) per-binary table) → recall 51/108 ≈ 47%; tier 8 recall 49% ([docs/plans/phase9.md](docs/plans/phase9.md)). The "51/108 matched, precision 48%, recall 47%" summary as a whole is **from conversation, not in docs** (precision 48% not found in any file; the tracer report `bench/ksuite_inv/IntTest.tracer.t10.txt` exists but I did not rescore it).
- IntTest is also where parameter types matter most: +31 of the +33/+37 parameter-type ceiling, `u` alone +28 — [docs/plans/struct-hints.md](docs/plans/struct-hints.md)

### Inferences
- Fact-level soundness auditing (facts vs own samples) is blind to wrong *values*; a value-level comparison against the oracle trace is what found these, and several are type errors in disguise (string vs address, pointer vs double, poison vs uninitialised).

### Gaps
- The level-1/2 value-comparison prototype and its numbers are not written up in any repository file.
- I did not verify that the float-return bug is still unfixed in the current code.
