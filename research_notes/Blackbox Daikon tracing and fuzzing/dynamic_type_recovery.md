# Dynamic and hybrid data-structure / type recovery from stripped binaries (for Daikon traces from an emulator)

Method note (read first): this session could only use web search. Fetching full papers failed: arxiv.org, ndss-symposium.org, usenix.org, sure-workshop.org, cs.purdue.edu and the GitHub API were all outside the allowed network domains. So every number below comes from a search-engine summary of the primary PDF, or from a secondary page that quotes the abstract. None comes from a table I read myself. Items marked **[unverified]** come from the author's prior knowledge of these papers and were not re-checked this session. The report writer should treat them as leads, not facts. Allowing those hosts and re-reading Howard Fig. 12, TypeForge §6, ReSym §6, TIE §7 and the SURE'25 tables would turn most gaps into numbers.

## 1. Dynamic struct/type recovery systems (Howard, REWARDS, Laika, TIE, ARTISTE, MemPick, DSIbin, ReClass-style)

### Takeaway
The dynamic line of work, from REWARDS (2010) and Howard (2011) through MemPick (2013) and DSI/DSIbin (2017), shows three things. An emulator that tracks pointer provenance from allocation sites can recover struct layouts and array extents with high precision for the code that actually runs. Running memory-graph "shape" analysis over the same events recovers linked lists and trees. Primitive types (int, char*, double, signedness) need "type sinks", meaning calls or instructions with a known signature. Coverage is the universal limit. Howard is reported at about 81.5% accuracy with only 59% function coverage. Our emulator already has every ingredient these systems needed: instruction-level memory events, a malloc model and values.

### Cited Findings
- Howard (Slowinska, Stancescu, Bos; NDSS 2011) is a dynamic tool built on a QEMU-based emulator. It recovers data structures from stripped gcc-generated x86 C binaries by tracking how the program uses memory. — [Howard NDSS'11 PDF (syssec mirror)](https://www.syssec-project.eu/m/page-media/3/howard-ndss11.pdf); [VU preprint](https://www.cs.vu.nl/~herbertb/papers/dde_ndss11-preprint.pdf)
- Howard's authors acknowledge that its results depend on the code covered at run time: data structures in code that never runs are not found. — [Howard NDSS'11](https://sites.cs.ucsb.edu/~chris/teaching/cs290/doc/howard-ndss11.pdf)
- Howard classifies an array with fewer than 4 elements accessed in a loop as a structure, by design. This can cause false negatives (array missed) but not false positives. Per-application accuracy is reported in the paper's Fig. 12 with categories such as "OK" for fully correct structures, but I could not read the percentages. — [Howard NDSS'11 (few.vu.nl)](http://www.few.vu.nl/~herbertb/papers/howard_ndss11.pdf)
- A third-party measurement in the OSPREY paper (S&P 2021) reports Howard at **81.5% accuracy with 59% function coverage**. — [OSPREY S&P'21 (youwei.site mirror)](https://www.youwei.site/papers/SP2021a.pdf)
- DSIbin (Rupprecht et al.) argues that Howard's precision is limited because its inferred types are often too coarse. — [DSIbin, VU research portal](https://research.vu.nl/en/publications/dsibin-identifying-dynamic-data-structures-in-cc-binaries/)
- **[unverified]** How Howard works:
  - It treats a malloc return, a stack frame or a global as a "root pointer".
  - It tracks every pointer derived from a root by arithmetic.
  - An access at a constant offset from a base pointer becomes a struct field.
  - Repeated accesses through a pointer that advances by a fixed stride, in a loop, become an array element. The extent comes from the allocation size and the observed maximum index.
  - Results from multiple runs are merged, and symbolic execution (KLEE-style) is used to raise coverage.
- REWARDS (Lin, Zhang, Xu; NDSS 2010) tags each memory location the program accesses with timestamped type attributes. It propagates them forward along data flow and resolves earlier variables backward from "type sinks", then rebuilds the in-memory layout of data structures from the derived types. Its applications were memory forensics and binary fuzzing. — [REWARDS project page (Purdue FRIENDS)](https://friends.cs.purdue.edu/dokuwiki/doku.php?id=rewards); [ACM DL entry](https://dl.acm.org/doi/10.5555/2788959.2788964); [Semantic Scholar](https://www.semanticscholar.org/paper/Automatic-Reverse-Engineering-of-Data-Structures-Lin-Zhang/a21921eb0c5600562c8dad8e2bc40fff1ec8906b)
- **[unverified]** REWARDS' type sinks are system-call arguments and known libc/API signatures (for example, the argument of `strlen` is `char*` and a `time()` result is `time_t`). It ran on a PIN-like dynamic binary instrumentation platform. I found no REWARDS accuracy figures; the search summaries did not include them.
- Laika (OSDI 2008, Cozzie et al.) finds data structures in memory images with Bayesian unsupervised learning. It clusters similar objects to detect lists and other abstract data types. The MemPick authors call its detection imprecise and not good enough for debugging or reverse engineering. — [MemPick WCRE'13 PDF](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf)
- MemPick (Haller, Slowinska, Bos; WCRE 2013, extended in EMSE 2015) detects and classifies high-level data structures in stripped C/C++ binaries. It rests on the observation that the shape of a data structure reveals its type. A hand-crafted decision tree classifies each heap graph as a linked list, binary tree, n-ary tree, graph and so on. A heuristic picks out "quiescent periods", when no changes are being made to the structure. — [MemPick WCRE'13](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf); [EMSE 2015 extension](https://link.springer.com/article/10.1007/s10664-015-9363-y)
- A 2017 comparison credits MemPick with handling tree-like nesting and skip lists poorly. It says ARTISTE runs an analysis on the memory graph and, from recovered primitive types, rebuilds the data structures that contain them, but loses precision on the "degenerate shapes" that appear while a structure is being changed. — [DSI, Bamberg (KPS2017)](https://www.swt-bamberg.de/luettgen/publications/pdf/KPS2017.pdf); [DSI tech report](https://fis.uni-bamberg.de/server/api/core/bitstreams/0e15f8bb-abfe-460d-bff7-caa5803bddb7/content)
- TIE (Lee, Avgerinos, Brumley; NDSS 2011) works on 87 programs. The authors report that it is both more accurate and more precise at recovering high-level types than existing mechanisms. It outputs an upper and a lower bound on each inferred type, which measures conservativeness, and uses a distance measure for structural types. — [TIE NDSS'11 (Semantic Scholar)](https://www.semanticscholar.org/paper/TIE:-Principled-Reverse-Engineering-of-Types-in-Lee-Avgerinos/ab4878b4a9ae07cb9facaef639f76cbbc131199f); [NDSS PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/lee.pdf)
- When TIE concludes that a variable is an integer but cannot decide its signedness, it outputs a generic "number" type. In effect it abstains on signedness. — [Learning Types for Binaries (Springer)](https://link.springer.com/chapter/10.1007/978-3-319-68690-5_26)
- **[unverified]** TIE runs over the BAP IR, both statically and on dynamic traces. Its constraint solving uses a subtyping lattice (a top type, then number/reg_n, then signed/unsigned and pointer types).
- The SURE 2025 benchmark (Vedant Soni et al., "Benchmarking Binary Type Inference Techniques in Decompilers") describes Howard-style tools as capturing memory snapshots and matching them to type templates to recover array or struct types. — [SURE'25 paper 8](https://sure-workshop.org/accepted-papers/2025/sure25-8.pdf)
- "What You Trace is What You Get: Dynamic Stack-Layout Recovery for Binary Recompilation" (ASPLOS 2024, DOI 10.1145/3620665.3640371) recovers stack layout dynamically from traces. I could not retrieve its numbers. — [OpenAlex record](https://api.openalex.org/works/doi:10.1145%2F3620665.3640371); related dynamic lifter: [BinRec EuroSys'20](https://download.vusec.net/papers/binrec_eurosys20.pdf)

### Inferences
- Howard's core algorithm (root pointers, then derived pointers, then offset/stride classification, sized by the allocation) maps almost one-to-one onto our emulator, which already sees every access and every malloc size. It is the direct fix for "struct pointees undecided" and for the 54% of missed facts that are pointers inside structs two or more levels deep. If every pointer value carries its root-allocation identifier as a shadow tag, the access map becomes a recursive graph to any depth.
- Howard's "fewer than 4 elements means struct" rule is a deliberately conservative abstention. Our "struct globals 0/8" failure looks the opposite way round: statically initialised globals are never written, only read. So for globals, Howard-style evidence must come from reads (load widths and offsets) and from whether a loaded value is later used as a pointer, not from writes.
- MemPick/DSI shape analysis (in-degree and out-degree of heap objects joined by pointer fields at the same offset) is how to label "linked list" or "tree" recursively. It runs over the same allocation graph, and is only reliable at quiescent points, which correspond to function entry and exit, exactly where Daikon program points are.

### Gaps
- Howard's per-program percentages for structs, arrays and fields (Fig. 12) and REWARDS' accuracy tables could not be read (hosts blocked).
- ARTISTE: I could not confirm its authors, venue or whether it is a dynamic type-inference system. A comparison paper cites it only as a memory-graph-based tool.
- Cheat Engine / ReClass-style manual dissection: I found no academic evaluation. These are interactive tools that show live memory, with the user assigning field types by watching values change. I found no sources to cite.
- I found no paper measuring Howard or REWARDS specifically on x86-64. Howard's paper is about 32-bit x86 gcc binaries **[unverified as to bitness]**.

## 2. Recent static / ML / LLM type recovery: who reports struct-layout and pointer-to-struct numbers

### Takeaway
Struct layout is now a first-class metric:
- OSPREY (S&P'21) reports struct precision/recall.
- TypeForge (S&P'25) reports F1 for struct identification, layout and relationship recovery.
- RecStruct (USENIX Sec'26) targets nested structs.
- XTRIDE (CODASPY'26) reports struct precision.
- ReSym (CCS'24) reports field-access and layout recovery.

Numbers do not carry across papers, because datasets and metric definitions differ. An independent re-run of TypeForge in the Idioms paper got F1 of roughly 37-69, against TypeForge's self-reported 81.7-88.2. Ghidra and IDA recover almost no structs by default, which matches our measurement (struct-by-value 0/698).

### Cited Findings
- **OSPREY (S&P 2021)**, probabilistic variable and data-structure recovery. In one example it reports **84% recall / 86% precision** for structs, against **Ghidra about 5.5% / 27%** and **IDA Pro about 6.8% / 50%**. It also measures Howard (81.5% accuracy, 59% function coverage). — [OSPREY S&P'21 (Kwon)](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf); [mirror](https://zzhang.xyz/res/SP21a.pdf)
- **TypeForge (S&P 2025, DOI 10.1109/SP61157.2025.00193)**, a Ghidra extension. It builds composite-type candidates from a Type Flow Graph, using conflict-aware type-hint propagation and an adaptive sliding window. It then **selects** among candidates by retyping through the decompiler and scoring the readability of the resulting code with an LLM-assisted elimination step. — [TypeForge GitHub](https://github.com/noobone123/TypeForge); [ISCLab talk slides (Chinese)](https://www.isclab.org.cn/wp-content/uploads/2025/09/二进制文件复合数据类型恢复-高玺凯.pdf)
- TypeForge's self-reported abstract numbers are **F1 81.7% (identification), 88.2% (layout), 72.1% (relationship recovery)**, at about 3.8% of OSPREY's running time. The source is secondary (a GitHub issue quoting the abstract). — [Awesome-REA issue #592](https://github.com/reacher-z/Awesome-REA/issues/592)
- The Idioms paper (NDSS 2026 per the URL; arXiv 2502.04536) re-evaluated TypeForge under TypeForge-style metrics and got noticeably lower F1, **about 37-69** depending on benchmark and optimisation level. The search summary flagged that table as hard to parse. — [Idioms NDSS'26 PDF](https://www.ndss-symposium.org/wp-content/uploads/2026-f795-paper.pdf); [arXiv 2502.04536](https://arxiv.org/pdf/2502.04536)
- **Idioms** predicts user-defined type (UDT) definitions jointly with neural decompilation and measures UDT accuracy separately. Its best models reach **about 30-40%** type accuracy on UDTs. — [Idioms arXiv](https://arxiv.org/pdf/2502.04536)
- **RecStruct (Chen et al., USENIX Security 2026, pp. 4127-4143)**:
  - It recovers nested structs without a decompiler. It lifts binaries directly, uses flow-insensitive symbolic execution to reduce memory aliases, and "Stack-Driven Unification", a union-find algorithm that tracks an offset stack during traversal.
  - It compares against TypeForge, TRex and ReSym and claims F1 about 2.2× TypeForge's on one dataset.
  - The same summary says TypeForge got the best F1 on coreutils-O3 and "utils", and that TypeForge failed to finish on some binaries.
  - The abstract claims "competitive accuracy" with large efficiency gains.
  - Artifact: [Zenodo 20560521](https://zenodo.org/records/20560521).
  - Sources: [RecStruct USENIX'26 PDF](https://www.usenix.org/system/files/usenixsecurity26-chen-yuxin.pdf); [USENIX Sec'26 contents](https://www.usenix.org/sites/default/files/sec26_contents.pdf)
- **XTRIDE ("Practical Type Inference: High-Throughput Recovery of Real-World Structures and Function Signatures", CODASPY 2026, arXiv 2603.08225)**, a successor to STRIDE. On the DIRT test set it reports **90.15%** overall type accuracy and **68.66%** on out-of-training functions, **94.88% precision recovering struct types**, and 0.04 ms per function (Rust), against DIRTY's 200-8,500 ms. Because its vocabulary is closed, novel user-defined types may be missed, in which case it abstains. — [XTRIDE CODASPY'26 PDF](https://www.mlsec.org/docs/2026-codaspy.pdf); [arXiv html v2](https://arxiv.org/html/2603.08225v2); [EmergentMind summary](https://www.emergentmind.com/papers/2603.08225); [BIFOLD listing](https://www.bifold.berlin/impact-transfer/publications/view/publication-detail/practical-type-inference-high-throughput-recovery-of-real-world-structures-and-function-signatures)
- **DIRTY (USENIX Security 2022)** reports **75.8%** overall type accuracy. Its struct accuracy appears as 68.6% in one table and 56.4% in another; the extraction was garbled, so the setting each applies to is unclear. Only **1.8%** of variables in the DIRT dataset are struct-typed, so overall accuracy says little about structs. DIRTY degrades on unseen types because of its closed vocabulary. — [DIRTY USENIX Sec'22](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- **ReSym (CCS 2024; Xie, Zhang, Jiang, Xu, Tan, Zhang)** combines fine-tuned LLMs for per-function predictions with a **Prolog-based reasoning component** that aggregates and cross-checks predictions across functions. A similarity-biased voting scheme resolves conflicts, which the authors say suppresses hallucination. I did not get its headline field-recovery numbers. A third party notes that only two models were released and that the Prolog component was not public. — [ReSym CCS'24 PDF](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf); [HF space README](https://huggingface.co/spaces/ejschwartz/test/blob/9bd433d2aa5540d6e2aa4c8aeca3067ccf582945/README.md)
- A 2026 "superset decompilation" paper reports that IDA and Ghidra do not recover structs by default, and that struct-recovery scores are very low for all tools it tested. — [Superset Decompilation, arXiv 2603.28002](https://arxiv.org/pdf/2603.28002)
- Other recent related work found in searches, without numbers:
  - TyGr (graph neural network type inference, USENIX Sec'24) — [TyGr](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
  - TypeFSL (ASE'24, interprocedural data flow plus few-shot learning) — [TypeFSL](https://conf.researchr.org/details/ase-2024/ase-2024-research/102/TypeFSL-Type-Prediction-from-Binaries-via-Inter-procedural-Data-flow-Analysis-and-Fe)
  - "Beyond the Edge of Function" (ByteTR, 2025, which frames type recovery as interprocedural prediction) — [arXiv 2503.07243](https://arxiv.org/html/2503.07243v2)
  - ReCopilot — [arXiv 2505.16366](https://arxiv.org/pdf/2505.16366)
  - SoK: AI-Augmented Binary Reversing — [arXiv 2606.17398](https://arxiv.org/pdf/2606.17398)
  - Binarly's industry write-up — [Binarly blog](https://www.binarly.io/blog/type-inference-for-decompiled-code-from-hidden-semantics-to-structured-insights)
- Surveys:
  - "Type recovery in stripped binaries: a comprehensive survey of inference tools and methods" (Automated Software Engineering, Springer, 2026) — [Springer](https://link.springer.com/article/10.1007/s10515-026-00677-y)
  - HKUST thesis "Recovering High-Level Semantics from Software Binaries: From Symbolic Analysis To LLM-Assisted Reasoning" (June 2026) — [HKUST](https://cse.hkust.edu.hk/pg/defenses/Summer26/qzhangdh-15-06-2026.html)
  - Auburn dissertation on binary type inference (2026) — [Auburn ETD](https://etd.auburn.edu/handle/10415/10634)
- SecondWrite and Retypd belong with TIE in the "principled static analysis over a lifted IR" family. — [Learning Types for Binaries](https://link.springer.com/chapter/10.1007/978-3-319-68690-5_26); [Barua PLDI 2013 (SecondWrite)](https://user.eng.umd.edu/~barua/pldi-2013.pdf)
- **[unverified]** Background on the remaining systems:
  - Retypd (Noonan et al., PLDI 2016) infers types by solving subtyping constraints over "sketches" and handles recursive types and polymorphism. It is the basis of GrammaTech's tooling; the related patent is US 10423397.
  - BinSub applies algebraic subtyping to make Retypd-style inference much faster.
  - TRex (USENIX Security 2025) infers structural types (types defined by shape, not by name) and argues for evaluating against what the binary actually implies, not the nominal source type.

  None of their numbers were retrieved. Patent link: [US 10423397](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/10423397)

### Inferences
- Our Ghidra measurement (pointee right 35%, struct-by-value 0/698) is consistent with OSPREY's report of Ghidra struct recall around 5.5%. Ghidra's default struct recovery is close to absent, so any layout recovery is a large gain.
- The strongest static systems (TypeForge, RecStruct, OSPREY) produce struct layouts with layout-F1 in the 70-88% range on their own benchmarks. Independent re-runs (Idioms on TypeForge) are much lower. Expect at most about 40-70% on a different corpus such as ReSym's.
- TypeForge's two-phase design ("synthesise candidates, then select") has the same shape as our checker plan. Replacing TypeForge's LLM readability score with run-time consistency is the natural hybrid.

### Gaps
- Retypd, BinSub and TRex accuracy numbers, and whether any of them reports a struct-layout metric, were not retrieved.
- ReSym's field-recovery precision/recall, and its exact metric, were not retrieved (Purdue host blocked).
- I found no paper reporting "pointer-to-struct pointee correct" as a separate number comparable to our "pointee right 35%".
- I found no 2025-2026 dynamic or hybrid type-recovery paper. All the recent struct work I found is static or ML.

## 3. Specific type facets: array vs struct, bounds, recursive structures, strings, floating point, signedness, unions, function pointers

### Takeaway
Each facet has a known fingerprint, and most of them are observable at run time:
- **Array vs struct and bounds:** stride loops plus the allocation size (Howard).
- **Recursive structures:** pointer graph shape (MemPick, DSI).
- **Strings and other primitives:** type sinks such as libc calls (REWARDS).
- **Signedness:** sign-extend vs zero-extend and signed vs unsigned compares (TIE). Abstain when there is no evidence.

Floating point that is never touched by an SSE instruction, and unions, have no reliable dynamic fingerprint. The literature abstains or uses static or ML priors for them.

### Cited Findings
- Array vs struct: Howard uses loop-based access patterns and needs at least 4 elements accessed in a loop to call something an array. Otherwise it reports a struct. — [Howard NDSS'11](http://www.few.vu.nl/~herbertb/papers/howard_ndss11.pdf)
- Recursive and dynamic data structures: MemPick classifies heap graph shapes (singly or doubly linked list, binary tree, n-ary tree, graph) using quiescent periods. DSI/DSIbin target overlay and nesting and cyclic shapes, where MemPick and ARTISTE are weak. — [MemPick](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf); [DSI (Bamberg)](https://www.swt-bamberg.de/luettgen/publications/pdf/KPS2017.pdf); [DSIbin](https://research.vu.nl/en/publications/dsibin-identifying-dynamic-data-structures-in-cc-binaries/); also [Identifying Dynamic Data Structures by Learning Evolving Patterns in Memory](https://www.researchgate.net/publication/262222132_Identifying_Dynamic_Data_Structures_by_Learning_Evolving_Patterns_in_Memory)
- Nested structs (static): RecStruct's Stack-Driven Unification tracks an offset stack to rebuild nesting. The types it misses that are only used on the stack are reported to be mostly anonymous nested types (garbled snippet, unverified). — [RecStruct](https://www.usenix.org/system/files/usenixsecurity26-chen-yuxin.pdf)
- Primitive types from sinks: REWARDS resolves types backward from type sinks, which gives `char*`, file descriptors, `time_t` and similar types wherever a value reaches a known API. — [REWARDS](https://friends.cs.purdue.edu/dokuwiki/doku.php?id=rewards)
- Signedness: TIE emits a generic "number" type when signedness cannot be decided. — [Learning Types for Binaries](https://link.springer.com/chapter/10.1007/978-3-319-68690-5_26)
- Unions: TypeForge lists unions among the composite types it recovers. I found no reported union accuracy. — [TypeForge GitHub](https://github.com/noobone123/TypeForge)
- Function pointers: I found no measured results. **[unverified]** Dynamic systems treat a value that is the target of an indirect call (`call *reg` or `call *[mem]`) as a code pointer. The REWARDS family treats those call targets as type sinks.

### Inferences
- **Strings:** at run time, `char*` can be confirmed when the pointer is passed to a str*, printf-%s or puts-style function. Without a sink, the evidence is a byte-wide load loop that stops at 0. Emit `rep-type java.lang.String` only when one of those holds, and abstain otherwise.
- **Doubles never used as doubles:** no dynamic method can recover these from the defining instructions, because a store of 8 bytes through a GPR is indistinguishable from `long`. The options are:
  - a sink, where the value reaches `printf("%f")` or `xmm` argument registers at a call;
  - static evidence elsewhere, such as another function that loads it with `movsd`;
  - a value-range heuristic: interpret the bits as an IEEE double and check that it is a "reasonable" number. This is not in the literature I found; it is our idea.
- **Array bounds:** the malloc model gives the allocation size. Element count = size / stride. This is stronger than Howard's observed-max-index for heap data. Globals need the gap to the next symbol or relocation, or the static extent.
- **Unions** show up dynamically as the same offset accessed with incompatible kinds: a float op in one run and a pointer dereference in another, or a different width. A tracer should flag the conflict and abstain, not pick one.

### Gaps
- I found no published accuracy for dynamic string, float or function-pointer recovery on x86-64.
- I found no paper evaluating union recovery quantitatively.

## 4. Combining dynamic evidence with static hypotheses; "type checking" a recovered type against behaviour; abstention

### Takeaway
I found no published system that does exactly what our rea-type-checker does: refute a decompiler's static type guess using run-time traces. The closest patterns are:
- TIE: constraint solving with upper and lower bounds, outputting a bound or abstaining.
- ReSym: per-function guesses checked for consistency across the program by Prolog rules, with voting.
- TypeForge: enumerate candidate layouts, then select one.
- OSPREY: probabilistic constraints, where static hints are weighted evidence.

"Static hypothesis + dynamic refutation + abstain-on-ambiguity" appears to be an open niche, so far as these searches could tell (not exhaustively verified).

### Cited Findings
- ReSym uses a Prolog reasoning module to aggregate and cross-check LLM predictions across functions, and similarity-biased voting to settle conflicts. This is explicitly aimed at suppressing hallucinated types. — [ReSym CCS'24](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- TypeForge synthesises several composite-type candidates and then selects the "best-fit" one by retyping it through the decompiler and running an LLM-assisted elimination step. — [TypeForge GitHub](https://github.com/noobone123/TypeForge); [ISCLab slides](https://www.isclab.org.cn/wp-content/uploads/2025/09/二进制文件复合数据类型恢复-高玺凯.pdf)
- TIE produces upper and lower type bounds from constraint solving. A wide gap between them is an explicit statement of uncertainty, and "number" is its abstention for signedness. — [TIE](https://www.semanticscholar.org/paper/TIE:-Principled-Reverse-Engineering-of-Types-in-Lee-Avgerinos/ab4878b4a9ae07cb9facaef639f76cbbc131199f)
- OSPREY models variable and type recovery probabilistically over many weak hints. It beats Ghidra and IDA by a wide margin on struct precision and recall. — [OSPREY](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- XTRIDE abstains when a type is outside its vocabulary. — [EmergentMind summary of XTRIDE](https://www.emergentmind.com/papers/2603.08225)
- Decompile-then-check work exists for code rather than types: SCRIBE recompiles decompiled code and checks the stack layout, and Echo uses "trusted back-translation". These show the "verify, then iterate" loop the rea-type-checker plan borrows. — [SCRIBE arXiv 2605.02121](https://arxiv.org/pdf/2605.02121); [Echo arXiv 2609.18706](https://arxiv.org/pdf/2609.18706)

### Inferences
- A hybrid design for our tracer follows directly from this literature:
  1. Static candidates: Ghidra, plus TypeForge- or RecStruct-style layouts, plus the p-code checker's evidence.
  2. Dynamic refutation: Howard-style access maps keyed by allocation root, MemPick-style shapes, and REWARDS-style sinks observed in the emulator.
  3. Select the most specific surviving candidate, or emit the "number" / unknown-pointee abstention when more than one survives.
- Our static checker already reaches 0.7% false rejects. Dynamic evidence is under-approximate (coverage) but precise (every observed access is real), so it can only *add* refutations. It never needs to override a pass from the static checker on unexecuted code. That makes the combination monotone and safe.
- Dynamic evidence fixes exactly the cases static p-code struggles with: aliasing through memory, and pointers loaded from struct fields (multiple levels deep), where the run-time value and its allocation root are known.

### Gaps
- I found no paper measuring a dynamic-refutes-static-type hybrid on x86-64 ELF. Howard used KLEE-style coverage expansion **[unverified]**, but not as a type checker.
- I could not confirm whether any 2025-2026 work uses execution traces to validate LLM type guesses. None appeared in these searches.

## 5. Evaluation metrics for struct layout and field types

### Takeaway
Papers score structs at three granularities:
- identification: is this variable a struct or a pointer to one?
- layout: the set of (offset, size) pairs, and sometimes field types;
- relationships: nested and pointed-to structs.

They report precision, recall and F1 over the field sets. The older TIE line uses a lattice "distance" between the inferred and true type. DIRTY-style ML papers use exact-match accuracy, which hides structs, since only about 1.8% of variables are structs. Our offset/size-set scoring against DWARF matches the TypeForge and OSPREY style.

### Cited Findings
- TypeForge scores identification F1, layout F1 and relationship F1 separately (81.7 / 88.2 / 72.1). — [Awesome-REA issue #592](https://github.com/reacher-z/Awesome-REA/issues/592)
- Idioms re-implemented "TypeForge-style metrics" to compare across systems, and measures UDT accuracy separately from scalar types. — [Idioms NDSS'26](https://www.ndss-symposium.org/wp-content/uploads/2026-f795-paper.pdf)
- OSPREY reports struct precision and recall (for example 84% / 86%). — [OSPREY](https://yonghwi-kwon.github.io/data/osprey_sp21.pdf)
- TIE uses a distance measure on its type lattice for structural types, plus upper/lower-bound conservativeness. — [TIE](https://www.semanticscholar.org/paper/TIE:-Principled-Reverse-Engineering-of-Types-in-Lee-Avgerinos/ab4878b4a9ae07cb9facaef639f76cbbc131199f)
- In DIRTY, 1.8% of variables are struct-typed, so overall accuracy says little about struct recovery. — [DIRTY](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- Howard grades each recovered structure into categories (such as "OK" for fully correct) per application. — [Howard](http://www.few.vu.nl/~herbertb/papers/howard_ndss11.pdf)
- The SURE'25 benchmark compares type inference across decompilers on a common dataset. — [SURE'25](https://sure-workshop.org/accepted-papers/2025/sure25-8.pdf)

### Inferences
- For Daikon traces, we should report:
  - kind accuracy (pointer, int, float or struct);
  - layout F1 over (offset, size) sets;
  - pointee-depth recall (the fraction of 2+-level pointer facts recovered);
  - an abstention rate.

  These map onto the TypeForge (identification / layout / relationship) and TIE (bounds or abstain) conventions and make our numbers comparable.

### Gaps
- I did not retrieve the exact definitions: whether layout F1 counts an offset with the wrong size as partially correct, and how padding and nested flattening are handled. They live in the TypeForge, ReSym and RecStruct papers, which this session could not fetch.
- I did not retrieve the SURE'25 per-tool numbers or its dataset.
