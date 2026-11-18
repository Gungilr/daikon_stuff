# Static (non-learned) type and data-structure recovery tools for stripped binaries

Scope note: primary sources read in full text were retypd (PLDI 2016, arXiv version), TIE (NDSS 2011), OSPREY (IEEE S&P 2021), TypeForge (IEEE S&P 2025), XTRIDE (arXiv 2026), the SecondWrite PLDI 2013 paper (partially), and the Caballero & Lin survey (ACM CSUR 2016, partially). Other tools (DIVINE, Debin, BITY, Ghidra and IDA internals) are covered from abstracts, vendor documentation, or secondary sources, and are flagged as such.

## Q1. Ghidra and IDA Hex-Rays: automatic type propagation, struct synthesis, library prototypes, known weaknesses

### Takeaway
Both decompilers infer primitive types locally and from library prototypes in their type databases (Ghidra .gdt archives, IDA .til type libraries). Neither synthesizes user-defined structs without a user action: Ghidra has right-click "Auto Create Structure" and "Auto Fill in Structure", and Hex-Rays has "Create new struct type". Cross-function propagation is limited. Published measurements show both perform poorly on composite types.

### Cited Findings
- **Hex-Rays, vendor's own statement.** The decompiler "does not perform full type recovery". It deduces some types from operations on variables, and from API-call type information taken from type libraries. Types from Type Libraries are copied into the IDB as Local Types once referenced. — [Hex-Rays docs, IDA 9.1 user guide: types](https://docs.hex-rays.com/9.1/user-guide/types); [Igor's tip #60: type libraries](https://hex-rays.com/blog/igors-tip-of-the-week-60-type-libraries)
- **Hex-Rays struct creation.** "Create new struct type…" is a user action on a variable's context menu. The decompiler then "analyze[s] accesses to the variables and come[s] up with a candidate structure type which matches them". The user accepts or edits the candidate, it is added to Local Types, and the variable becomes a pointer to it. For simple cases such as a char pointer, no new type is created. — [Igor's tip #118](https://hex-rays.com/blog/igors-tip-of-the-week-118-structure-creation-in-the-decompiler); [hx_newstruc docs](https://docs.hex-rays.com/ida-actions/hx_newstruc)
- **Ghidra struct creation** is likewise user-triggered: right-click a decompiler variable and choose "Auto Create Structure" or "Auto Fill in Structure". Ghidra's training material recommends setting parameter types first. — [Ghidra Advanced class: Improving Disassembly and Decompilation](https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf)
- **Trail of Bits on Ghidra's built-in inference.** It uses predefined type databases (e.g., libc) to type calls to known functions. It "does not synthesize structs or unions without user action". Its inter-procedural reach is limited, which can give conflicting types across directly connected functions (e.g., `void*` in one, `long` in the other). — [Trail of Bits blog, "Binary type inference in Ghidra", 2024](https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/)
- **undefinedN.** Under-constrained fields and variables show up as sized-but-untyped `undefinedN` (e.g., `undefined8`). This happens even after BTIGhidra's inference. — [Trail of Bits 2024](https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/). `undefined8` is not a C type, so exported decompiler output fails to compile. — [E. Schwartz blog](https://edmcman.github.io/blog/tags/ghidra)
- **Ghidra and stack structs.** The OSPREY authors inspected Ghidra's source. They report that Ghidra "do[es] not consider stack offsets as reliable base addresses (potentially due to ... compiler optimizations ...) such that it does not even group the two stack offsets to a structure". In their example Ghidra instead types a heap pointer as an array of 4 32-bit values and the stack struct as separate scalars. Ghidra does use register-based data-flow to find base addresses beyond rsp/rbp. — [OSPREY, IEEE S&P 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- **IDA and conflicting access widths.** In the same example, IDA typed `elem_t` as a union of a 2-element 64-bit array and a 128-bit field. This is because the same stack region was accessed both field-by-field and as a whole (a 128-bit copy). — [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- **IDA's composite-type rate.** TypeForge's authors state that IDA Pro "can accurately recover only 6% of composite data types, only limited to library-defined types, while user-defined composite data types remain unrecoverable". — [TypeForge, IEEE S&P 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **IDA and 64-bit pointers.** IDA often misidentifies 64-bit pointers and structs as `__int64`. — [Li et al., "Beyond the Edge of Function", arXiv 2503.07243](https://arxiv.org/html/2503.07243v2)
- **TIE vs Hex-Rays v1.2 (2011), on 87 coreutils programs, 32-bit.** Hex-Rays was under 45% conservative on structural types, against 90% for TIE. TIE was 28% more precise intra-procedurally and 38% more precise with inter-procedural analysis. TIE's authors say Hex-Rays "seems to be guessing types, e.g., any local variable moved to eax is a signed integer". Hex-Rays defaults 32-bit registers to `int32_t`. — [TIE, NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- **OSPREY's head-to-head numbers.** OSPREY outperforms Ghidra, IDA, Angr and Howard by 20.41%–56.78% in precision and 11.89%–50.62% in recall. On complex variables (arrays and structs) the margins are 6.96%–89.05% in precision and 46.45%–74.02% in recall. A secondary summary gives complex-variable F1 of 0.57 for OSPREY, 0.45 for Ghidra and 0.31 for IDA Pro; I did not verify this against the paper's table. — [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- **Ghidra's decompiler options** relevant here are `setSplitStructures`, `setSplitArrays`, `setSplitPointers` and `setInferConstantPointers`. There is also `setProtoEvalModel`, the prototype model "assumed if no other information about a function is known". The API docs do not describe the inference algorithm itself. — [Ghidra DecompileOptions API](https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompileOptions.html)

### Inferences
- Struct recovery in both decompilers is a per-variable, user-initiated operation. Its result is driven by the accesses visible where it is invoked. Library prototypes from .gdt/.til are the main way type information reaches user code automatically.
- Because Ghidra does not treat stack offsets as base addresses, stack-allocated structs, which dominate at -O0, tend to be flattened into independent scalars.

### Gaps
- I found no primary vendor documentation describing the exact algorithm of either decompiler's type propagation (both are proprietary or undocumented in this respect).
- I found no primary source for the claim that decompilers drop unused parameters from inferred prototypes. ByteTR (Li et al.) addresses parameter slots via def-use analysis, but I did not find a measured statement about Ghidra or IDA behaviour.

## Q2. Per-tool method, outputs, claims and benchmarks (TIE, retypd, OSPREY, TypeForge, SecondWrite, DIVINE/VSA, Debin, BITY, others)

### Takeaway
The constraint-based lineage runs DIVINE/VSA (2007) → TIE (2011) → SecondWrite (2013) → retypd (2016). It is evaluated mostly on primitive and pointer types, using TIE's lattice "distance" and "conservativeness" metrics on coreutils and SPEC2006. The composite-focused line runs OSPREY (2021) → TypeForge (2025). It uses precision, recall and F1 over variables and struct (offset, size) layouts, on coreutils and the Howard program set.

### Cited Findings

#### DIVINE (Balakrishnan & Reps, VMCAI 2007)
- Iterates Value-Set Analysis (VSA) with Aggregate Structure Identification (ASI, from Ramalingam, Field & Tip, POPL 1999) to recover variable-like entities in stripped executables.
- In initial experiments it correctly identified 88% of local variables and 89% of the fields of heap-allocated objects. It reports previous techniques at 83% of locals and 0% of heap fields.
- Source: [DIVINE abstract, UW–Madison](https://research.cs.wisc.edu/wpis/abstracts/vmcai07.invited.abs.html); [Springer chapter](https://rd.springer.com/chapter/10.1007/978-3-540-69738-1_1)

#### TIE (Lee, Avgerinos & Brumley, NDSS 2011)
- **Pipeline.** BAP lifts the binary to BIL. DVSA, a generalized VSA whose strided intervals use linear combinations of scalars rather than a single base register, recovers variable locations and alias information. Type reconstruction then generates subtype constraints over a lattice of C-like types (including records for structs) and solves them into an upper/lower bound interval per variable.
- **Stack slot reuse.** Memory is put into SSA form so that a reused stack slot can be typed differently in different memory instances.
- **Modes.** Works both statically and dynamically, and both intra- and inter-procedurally.
- **Evaluation setup.** 87 coreutils v8.4 programs, 32-bit x86 Linux, ground truth via libdwarf. The inter-procedural analysis used libc prototypes from header files.
- **Results.**
  - Against REWARDS (dynamic): average conservativeness/distance was TIE (dynamic) 1.0/1.15, REWARDS 0.59/2.19, REWARDS-c 0.98/1.53, and TIE static 0.93/1.57.
  - Dynamic coverage was only about 8.73% of variables.
  - On structs, TIE was 90% conservative with distance about 1.5.
- **Metric for structs.** Struct distance combines the difference in field count with per-field subtype distance.
- **Compiler optimization level is not stated** in the evaluation-setup text I read.
- Source: [TIE NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)

#### SecondWrite (ElWazeer, Anand, Kotha, Smithson & Barua, PLDI 2013)
- Lifts x86 to LLVM IR. Static analyses recover variables, types and function prototypes, which SecondWrite calls interprocedural interfaces.
- Per-procedure memory stack analysis detects memory arguments and splits the physical stack into abstract frames. Global and stack regions start out as byte arrays in the IR.
- Recovers variables on the x87 floating-point stack, which it says other tools neglect.
- Evaluated on the complete SPEC2006 suite (C, C++ and Fortran) with two compilers. Claims scaling to millions of instructions in minutes.
- Source: [SecondWrite PLDI 2013](https://user.eng.umd.edu/~barua/pldi-2013.pdf)
- Comparison figures reported in the retypd paper:
  - Multi-level pointer accuracy: 73%.
  - Conservativeness: 96% on a SPEC2006 subset.
  - Mean distance: 1.70.
  - Interval size: 1.7.
  - SecondWrite is unification-based.
  - Source: [retypd arXiv 1603.05495](https://arxiv.org/abs/1603.05495)

#### retypd (Noonan, Loginov & Cok, PLDI 2016, GrammaTech)
- **Type system.** Subtyping (not unification), recursive types and polymorphism, i.e., type schemes per procedure. Separate `.load` and `.store` capabilities on pointers give sound pointer subtyping and let it infer `const`. Results are "sketches", tree automata that are converted to C types by lossy heuristics.
- **Procedures.** Constraint simplification is done per procedure, leaving constraints only over formal-ins, formal-outs, globals and type constants. Callee schemes are instantiated at each call site. This is how it handles polymorphic functions such as `malloc` and `memcpy` and "forgets" capabilities during casts.
- **Implementation.** Built in CodeSurfer for Binaries (x86, x86-64, ARM). It was evaluated with VSA disabled; only affine stack-pointer/frame-pointer relations were computed. It needs no points-to analysis.
- **Benchmarks.** 160 32-bit x86 Linux and Windows binaries (gcc and MSVC), including the coreutils and SPEC2006 sets used for REWARDS, TIE and SecondWrite. All were optimized release builds; ground truth came from DWARF/PDB read via IDA. Clusters such as coreutils were averaged into single data points.
- **Results.**
  - Mean distance to source type: 0.54, against 1.15 dynamic TIE, 1.53 REWARDS, 1.58 static TIE and 1.70 SecondWrite.
  - Interval size: 1.2, against 1.7 SecondWrite and 2.0 TIE.
  - Conservativeness: 95% overall, 98% on coreutils, and 94% on SecondWrite's SPEC subset (where SecondWrite reports 96%).
  - Multi-level pointer accuracy: 91% on SecondWrite's suite (SecondWrite 73%), 88% across all benchmarks.
  - `const` recovery: 98% of source `const` parameter annotations.
  - Scaling: about O(N^1.1) in observed runtime.
- **Stated imprecision sources:**
  - Disassembly failures cause unsound constraints.
  - The conversion from sketches to C types is lossy.
  - Type-unsafe source code (e.g., WPARAM/LPARAM casts in miranda32) counts as failures against DWARF ground truth.
  - Imprecision in common statically linked library functions propagates out to callers.
- Source: [retypd PLDI 2016, arXiv](https://arxiv.org/abs/1603.05495)
- **Open-source implementation** (GrammaTech/retypd, GPLv3): a Python constraint solver with a disassembler-agnostic front-end schema. The user supplies a constraint set and variables of interest, and inferred constraints come back in `.constraints`. The README warns it is in active development with an unstable API. — [GrammaTech/retypd README](https://github.com/GrammaTech/retypd)
- **BTIGhidra** (Trail of Bits, 2024) is a Ghidra extension "inspired by and ... based on" Noonan et al.
  - Generates constraints with flow-sensitive data-flow from cwe_checker, per strongly connected component of the call graph.
  - Simplifies them into signatures and solves for sketches.
  - Creates a type variable per call site and merges into the formal only when structurally equal, for soundness.
  - Synthesizes composite types and accepts user constraints.
  - Its BTIEval harness compares against debug info, but no numbers were published in the post.
  - Source: [Trail of Bits 2024](https://blog.trailofbits.com/2024/02/07/binary-type-inference-in-ghidra/)

#### OSPREY (Zhang, Ye, Kwon et al., IEEE S&P 2021)
- **Method.** Extends BDA, a binary abstract interpretation for dependency analysis, to collect memory access patterns, data flow through registers and memory, points-to and heap usage. These become "hints" that feed probabilistic inference rules, a factor-graph style analysis that computes the likelihood of each variable/structure hypothesis.
- **Example.** It assigns 0.7 vs 0.3 to "stack struct" vs "two int64s", and 0.9 vs 0.1 to "pointer to struct" vs "pointer to union".
- **Outputs.** Variables, arrays, structs and nested structs; used to improve IDA decompilation and to harden binaries.
- **Setup.** GCC 4.4, default -O0, with -O3 in an appendix. Debug build for ground truth, stripped build for evaluation. Benchmarks are coreutils plus the 5-program Howard set.
- **Results.** 90.18% precision and 88.62% recall overall when reporting the most-probable result; 89.05% precision and 74.02% recall on complex variables.
- **Cost.** It is the heaviest tool: wget took 3604.8s, against 94.7s for Ghidra and 19.0s for IDA. TypeForge reports OSPREY's coreutils average as 528.2s per binary.
- **Availability.** Not publicly available.
- Sources: [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf); [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)

#### TypeForge (Wang et al., IEEE S&P 2025)
- **Stage 1: TFG-based Type Synthesis.**
  - Builds a Type Flow Graph over Ghidra-decompiled variables (stack, global, heap and parameters).
  - Edges are dataflow, member and typealias, plus inter-procedural "Inter" edges from caller arguments to callee parameters.
  - Conflict-Aware Type Hint Propagation removes "evil edges" caused by casts and unions.
  - Synthesizes several candidate declarations, to handle flattening, single-object-vs-array ambiguity, and union/cast ambiguity.
  - Builds on Ghidra's own primitive-type inference.
- **Stage 2: Readability-Guided Selection.** Retypes the decompiler output with each candidate, then has GPT-4o-mini judge readability in a double-elimination tournament. This costs about 180K tokens and about $0.12 per coreutils binary.
- **Evaluation data.**
  - Main dataset: coreutils, gzip, grep, wget2 and lighttpd; over 10,000 functions and over 11,000 composite variables; O0–O3.
  - SOTA comparison: OSPREY's coreutils dataset.
  - Ground truth comes from DWARF-4, because Ghidra does not support DWARF-5.
- **Results.** Headline F1 is 81.7% for composite identification and 88.2% for layout recovery.

  Table 2, by optimization level (P/R/F1):

  | Task | O0 | O1 | O2 | O3 |
  |---|---|---|---|---|
  | Composite identification | 74.3/77.6/75.9 | 76.1/77.5/76.9 | 74.9/82.9/78.8 | 73.5/81.8/77.4 |
  | Layout recovery | 97.9/82.2/89.4 | 97.3/46.3/62.7 | 93.9/31.2/46.8 | 94.2/30.8/46.4 |
  | Relationship recovery | 47.9/50.3/49.1 | 55.4/28.9/37.9 | (see note) | 66.9/22.2/33.3 |

  The O2 relationship row as extracted (94.2/30.8/46.4) is identical to the O3 layout row, so it is likely a typesetting error in the paper.

  Table 4, on OSPREY's coreutils dataset (composite identification R/P/F1; layout recovery R/P/F1):

  | Tool | Composite identification | Layout recovery |
  |---|---|---|
  | DIRTY | 36.8/62.0/46.2 | 4.1/51.8/7.6 |
  | OSPREY | 18.5/65.5/28.9 | 87.3/86.5/86.9 |
  | TYGR | 86.4/34.5/49.3 | 5.3/31.3/9.1 |
  | ReSym | — | 35.2/81.1/49.0 |
  | TypeForge | 87.9/76.3/81.7 | 80.9/96.9/88.2 |

  - Relationship recovery: TypeForge 66.6 R / 78.5 P / 72.1 F1; DIRTY 0.
  - Time per binary: TypeForge 7.7s; DIRTY 10.3s; TYGR 323s; OSPREY 528.2s (as reported by the OSPREY authors).
- **OSPREY's low identification recall** is attributed to its inability to recover register-based variables, including function parameters.
- **Stated limitations:**
  - Evil-edge removal is conservative and drops valid edges, so recovered structs miss members.
  - About 75% of runtime goes to the LLM selection stage.
  - Members that are never accessed cannot be recovered.
  - "Pointer Type Ambiguity": a pointer to struct B may be upcast to its first-member struct A.
  - Recall drops at O1–O3 because members are merged or flattened.
- Source: [TypeForge S&P 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **Repository status.** Results cannot yet be imported into Ghidra projects, and GUI mode is "in development". Tested on Ghidra 11.0.3. — [noobone123/TypeForge](https://github.com/noobone123/TypeForge)

#### Debin (He, Ivanov, Tsankov, Raychev & Vechev, CCS 2018)
- Statistical rather than constraint-based: a decision tree classifies which elements to predict, then a CRF (graphical model) jointly predicts names and types over a dependency graph.
- On x64 it predicts names and types with 68.8% precision and 68.3% recall.
- Type F1 is about 73.8% on x64, 63.7% on x86 and 67.4% on ARM. These figures came from a search-result summary of the paper's table; I did not verify them against the paper directly.
- Source: [Debin CCS 2018 PDF](https://files.sri.inf.ethz.ch/website/papers/ccs18-debin.pdf)
- Later critique: Debin and StateFormer "perform poorly on real-world binaries". — [Li et al., arXiv 2503.07243](https://arxiv.org/html/2503.07243v2)

#### BITY (Xu, Wen & Qin)
- Learns a classifier over basic types (SVM with linear kernel and Random Forest performed best), trained on binaries with debug info.
- Evaluated on coreutils v8.4 against Hex-Rays; claims better exact and compatible type prediction.
- The venue I could confirm is an LNCS 2017 paper, "Learning Types for Binaries" (DOI 10.1007/978-3-319-68690-5_26), plus a later journal version. I could NOT confirm "PAKDD 2018".
- Sources: [BITY project page](https://wcventure.github.io/EnPage/opensource/2018-09-01-BITY); [Crossref DOI](https://api.crossref.org/works/10.1007%2F978-3-319-68690-5_26)

#### XTRIDE (Seidel, Thomas & Rieck, arXiv 2603.08225, 2026; learned n-gram, included here as an external check on TypeForge)
- Reports OSPREY F1 of 0.869 at 528.24s per binary.
- Replicated TypeForge with the open-source code and found recall "significantly lower than reported in the original work (77–82%)". It attributes the gap to evaluation differences: "TypeForge does not attempt inference for many variables with struct ground truth if they lack observable struct field access patterns. We count these cases as misses."
- Notes that TypeForge "has no mechanism to recover the semantics of a type and its fields" (names).
- Source: [XTRIDE arXiv](https://arxiv.org/abs/2603.08225)

### Inferences
- TIE, SecondWrite and retypd report gains on primitive and pointer types using lattice distance. OSPREY and TypeForge report composite F1. The two families' numbers are not directly comparable.
- Most static tools are not runnable by third parties: TIE, OSPREY and the original CodeSurfer-based retypd are unavailable. As a result, later papers often copy numbers rather than rerun baselines (TypeForge took OSPREY's numbers from its authors, and ReSym's from its paper).

### Gaps
- I did not read the full DIVINE or SecondWrite evaluation tables. SecondWrite's numbers above come via the retypd paper.
- Howard (NDSS 2011), REWARDS (NDSS 2010), TypeMiner and HyRES are only mentioned via other papers, not researched directly.
- BinRec was not researched. I found no source tying it to type recovery within budget.
- I did not check whether the GrammaTech retypd-ghidra-plugin repository exists or what state it is in.

## Q3. Cross-function reasoning, stack memory, address-taken locals and aliasing

### Takeaway
Inter-procedural reasoning is the norm for the constraint-based tools: TIE optionally, retypd through per-procedure type schemes instantiated at call sites, BTIGhidra per call-graph SCC, and TypeForge through caller-argument-to-callee-parameter edges. All of them can only type what is used somewhere. A pointer passed to a function that never dereferences it gains information only if some other procedure constrains it. Stack handling ranges from VSA-based memory models (TIE, DIVINE, OSPREY) to "points-to free" stack-pointer tracking (retypd) to building on decompiler-recovered stack variables (TypeForge).

### Cited Findings
- **TIE.** DVSA recovers stack variables from access patterns (e.g., ebp+0xc is a parameter) and returns a VSA context used "to determine aliasing and reuse stack slots". Memory is in SSA so that reused slots get distinct types. TIE with inter-procedural constraint generation gives tighter intervals than without it. — [TIE NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- **retypd challenges named by the authors:**
  - Stack-slot reuse by the optimizer, including reuse of argument slots. Handled with subtyping and reaching definitions for stack variables.
  - Polymorphic functions such as `malloc` and `memcpy`.
  - Offset and reinterpreted pointers: a pointer-to-struct is indistinguishable from a pointer-to-first-member, and stack structs are manipulated via offsets.
  - Incomplete points-to information.
  - Unification's non-locality, which lets bad IR constraints spread.
  - Retypd works with only stack-pointer tracking. Enabling VSA "can greatly improve the reconstructed IR" at a time cost.
  - Source: [retypd arXiv](https://arxiv.org/abs/1603.05495)
- **retypd and argument flow.** At a call site, the actual-in type α need only satisfy α ⊑ F.instack0. Callee schemes are instantiated per call site, so information flows from callee constraints to the caller. A parameter the callee never uses yields no capabilities. — [retypd arXiv](https://arxiv.org/abs/1603.05495)
- **OSPREY** uses BDA's points-to and memory data-flow to link a heap pointer stored to and reloaded from the stack with stack-allocated instances of the same struct type. TIE's VSA over-approximation produces read/write overlaps, and TIE "simply declares a union" to resolve the contradiction. Howard "cannot recognize structures on stack" because it does not accept rsp+0x8 as a base address. — [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- **TypeForge** builds aliasing from shared access paths: `*(param_1+0x30)` and `*(local_10+0x30)` are aliases when param_1 and local_10 have the same type. This avoids "costly and inaccurate" alias analysis. It adds inter-procedural typealias edges from caller arguments to callee parameters. TypeForge also criticizes the "heavy inter-procedural value-set analysis" of earlier methods as causing false positives. — [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **TYGR**, a learned GNN, lacks inter-procedural analysis, so its struct member prediction works only for stack-allocated structs and not struct pointers. On OSPREY's dataset this gave 5.3% layout recall. — [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **How common cross-function flow is.** About 44.4% of variables propagate across functions, and nearly 60% of functions contain such variables. — [Li et al., arXiv 2503.07243](https://arxiv.org/html/2503.07243v2)
- **Optimization level and storage.** At O0, variables are mostly on the stack. From O1 up, they mostly move to registers. — [Li et al.](https://arxiv.org/html/2503.07243v2). OSPREY cannot recover register-based variables, including parameters. — [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **SecondWrite** runs per-procedure memory stack analysis to find memory arguments and splits the stack into abstract frames to recover "interprocedural interfaces". — [SecondWrite PLDI 2013](https://user.eng.umd.edu/~barua/pldi-2013.pdf)

### Inferences
- A pointer passed to a callee that never dereferences it gets no type evidence from that callee in any of these systems. Evidence must come from elsewhere in the call graph, or from library prototypes. TypeForge says explicitly that never-accessed members are unrecoverable "for all data flow analysis tools".
- Address-taken stack structs are a recurring weak point. Ghidra, Howard and IDA mishandle them in OSPREY's example. OSPREY's own evaluation default is -O0, where stack variables are most common.

### Gaps
- No paper I read quantified accuracy specifically for address-taken locals, or for parameters that are passed through but never used.

## Q4. Composite (struct) vs primitive accuracy: definitions and reported numbers

### Takeaway
Struct recovery is consistently harder, and it degrades sharply with optimization. TypeForge's layout recall falls from 82.2% at O0 to about 31% at O2/O3, while precision stays at 94% or above. Definitions vary across papers:
- TIE: lattice distance with a field-count term.
- OSPREY: per-variable precision and recall over complex variables.
- TypeForge and ReSym: sets of (offset, size) pairs, plus 5-tuple relationships.
- XTRIDE: full-match layout.

Names are not part of the layout metric.

### Cited Findings
- **TIE.** Structs are hard because one must identify the base pointer, that field accesses are occurring, the number of fields, and each field's type. Struct distance is the field-count difference plus per-field distance. TIE was 90% conservative on structs with distance about 1.5; Hex-Rays was under 45% conservative. — [TIE NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- **OSPREY.** 90.18% precision and 88.62% recall for all variables, against 89.05% and 74.02% for complex variables. Recall is the metric that falls for composites. — [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- **TypeForge metric definitions:**
  - Composite identification is set-based precision and recall over variables whose DWARF type is struct, struct*, union, union* or array.
  - Layout recovery is evaluated only on correctly identified variables, as the intersection of (offset, size) member sets. Field types and names are not included.
  - Relationship recovery uses 5-tuples (src, offset, dst, RelationType, ptrLevel), matched via layouts because names are unavailable.
  - Source: [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **TypeForge's reasons for composite difficulty:**
  - F1: stack and nested structs and arrays are flattened into separate variables.
  - F2: a pointer may reference a single object or an array.
  - F3: no cast or union information survives.
  - Optimization merges or flattens members.
  - Composite accesses are about 1.8 times more frequent than primitive accesses.
  - Source: [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **Retypd** reconstructs recursive struct types (e.g., a linked-list `Struct_0 *field_0` from -O2 code). However, its quantitative evaluation is distance-, conservativeness- and pointer-based, with no separate struct-layout score. — [retypd arXiv](https://arxiv.org/abs/1603.05495)
- **XTRIDE replication.** XTRIDE considers only structs (not arrays or unions), "in accordance with TypeForge's implementation" and HyRES's methodology. It reports full-match layout accuracy and emphasizes field and type names, which TypeForge does not produce. — [XTRIDE arXiv](https://arxiv.org/abs/2603.08225)
- **The survey's view.** Caballero & Lin note that boolean correct/incorrect metrics are "coarse-grained because types can overlap each other or be nested". They name multi-dimensional arrays, SIMD-accessed arrays and compiler padding fields as open challenges. — [Caballero & Lin, ACM CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- Layout F1 is conditional on correct identification. A high layout score therefore says nothing about structs that were never identified. XTRIDE's replication suggests that this conditioning, and skipped variables, inflate TypeForge's recall.

### Gaps
- No paper I read evaluates recovered field types or names inside composite types as a separate metric. XTRIDE's full-match metric comes closest.

## Q5. Evaluation methodology and critiques

### Takeaway
Nearly all of these tools use DWARF (or PDB) from a debug build as ground truth, and coreutils as the core benchmark, with SPEC2006 and the Howard programs as secondary sets. The known critiques are:
- coreutils is highly redundant.
- Optimization levels are inconsistent (OSPREY defaults to -O0; retypd uses optimized builds; TIE's level is unstated).
- Tools are unavailable, so numbers get copied between papers.
- DWARF types can be "wrong" for type-unsafe code.
- Functions missed by the disassembler are excluded.
- Variables a tool skips are not counted as misses.

### Cited Findings
- **retypd on coreutils redundancy.** Over 80% of `tail`'s .text, and over 99% of `yes`, is shared statically linked utility code. Coreutils is therefore a "particularly low-variance benchmark suite", and retypd averaged clusters to avoid over-representing it. — [retypd arXiv](https://arxiv.org/abs/1603.05495)
- **retypd on DWARF as ground truth.** Treating source types as ground truth causes "failures" whenever retypd recovers an accurate type that does not match the declared type, as in the WPARAM/LPARAM example. — [retypd arXiv](https://arxiv.org/abs/1603.05495). TIE likewise found that typing errors in the original program, such as strlen's result stored in a signed int, caused apparent errors. — [TIE NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- **TIE on type-system mismatch.** Hex-Rays and REWARDS have less expressive, C-only type systems. Their output τ was translated to the interval [⊥, τ] to give them the most conservative setting. — [TIE NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- **OSPREY's setup.** It used GCC 4.4 to match TIE and Howard, defaulted to -O0, and assumed correct disassembly. — [OSPREY 2021](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf). The Cornucopia paper notes that OSPREY ignores functions missed by Radare, and compares against IDA and Ghidra only on functions detected by all tools. — [Cornucopia, arXiv 2209.06694, via search summary](https://arxiv.org/pdf/2209.06694)
- **Unavailability of tools.** The DIRTY paper notes that TIE, Howard, Retypd, TypeMiner and OSPREY are not publicly available. — [DIRTY, arXiv 2108.06363, via search summary](https://arxiv.org/pdf/2108.06363). TypeForge obtained OSPREY's results from its authors and used ReSym's published numbers. — [TypeForge 2025](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **TypeForge's evaluation details.** Ghidra-to-DWARF variable alignment across optimization levels is nontrivial (see repo issue #18). An earlier bug made identification results "much lower than expected" and was later fixed. — [TypeForge Evaluation.md](https://raw.githubusercontent.com/noobone123/TypeForge/main/Evaluation.md)
- **XTRIDE vs TypeForge.** XTRIDE's replication found lower TypeForge recall because skipped variables were counted as misses. XTRIDE's own learned results involve 40.9%–71% train-test overlap, which it acknowledges as a threat to validity. — [XTRIDE arXiv](https://arxiv.org/abs/2603.08225)
- **Dataset duplication in learned-type work.** Function duplication is 89.9% in StateFormer's dataset and 65.5% in DIRTY's. — [Li et al., arXiv 2503.07243](https://arxiv.org/html/2503.07243v2)
- **The survey** systematizes 38 type-inference works across benchmarks and metrics:
  - Several works evaluate only qualitatively.
  - Many use coarse boolean metrics.
  - Only TIE, SecondWrite and LEGO use finer-grained metrics.
  - Cross-tool comparisons are typically done on coreutils with TIE's distance and conservativeness.
  - SPEC CPU is used by 4 approaches.
  - Source: [Caballero & Lin, ACM CSUR 48(4), 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- Results are hard to compare across eras. The 32-bit x86 work (TIE, retypd, SecondWrite) predates the x86-64 focus of OSPREY and TypeForge, and the optimization levels and metrics differ. The only x86-64, multi-optimization-level composite numbers here are TypeForge's Table 2, which shows severe recall loss above O0.
- Layout metrics conditioned on identification, together with "skip if no evidence" behaviour, can inflate recall. Independent replications (XTRIDE) are rare and find gaps.

### Gaps
- I did not find a systematic third-party benchmark that ran Ghidra, IDA, retypd/BTIGhidra and TypeForge on the same x86-64 binaries at O0–O3.
- I did not verify TIE's compilation optimization level from the paper text.
