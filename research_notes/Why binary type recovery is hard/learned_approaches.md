# Learned (ML/LLM) approaches to type and name recovery from stripped binaries, and their known weaknesses

Note on verification: items marked [VERIFIED-PRIMARY] were read directly from the paper's PDF or HTML in this session. Items marked [ABSTRACT/PAGE] come only from the abstract or a landing page. Items marked [UNVERIFIED] come from background knowledge with no primary source checked this session. They are flagged so the writer can either hedge them or drop them.

## Q1. Per-model summaries: input, outputs, context, accuracy, limitations

### Takeaway
Most learned systems work on the output of one decompiler, usually IDA Hex-Rays (DIRE, DIRTY, ReSym, Idioms). The exceptions are TYGR (angr/VEX IR), StateFormer and DEBIN (assembly or binary level), and LLM4Decompile-End (raw binary/assembly). Most of them predict names plus a type from a closed vocabulary, function by function. Only ReSym, TYGR, Idioms and TypeForge try to recover struct layouts or definitions, and their struct numbers are much lower than their headline numbers: TYGR 45.2% struct accuracy, ReSym 28.9% layout recall, Idioms 15.1% UDT structural accuracy.

### Cited Findings

**DIRE (Lacomis et al., ASE 2019)**
- Predicts variable names only, from decompiler output, using both lexical tokens and the AST structure. Names match the original source up to 74.3% of the time. Corpus: 164,632 unique x86-64 binaries from C projects on GitHub. [ABSTRACT/PAGE] — [arXiv 1909.09029](https://arxiv.org/abs/1909.09029)
- The abstract does not name the decompiler. Hex-Rays is the commonly reported one [UNVERIFIED]. — [arXiv 1909.09029](https://arxiv.org/abs/1909.09029)

**DIRTY (Chen, Lacomis, Schwartz, Le Goues, Neubig, Vasilescu; USENIX Security 2022, Distinguished Paper)**
- A Transformer encoder-decoder that post-processes decompiled code to predict variable names and types. Reported accuracy: names 66.4%, types 75.8%. [ABSTRACT/PAGE] — [USENIX page](https://www.usenix.org/conference/usenixsecurity22/presentation/chen-qibin)
- The original work used Hex-Rays output, and its authors had concluded Ghidra was a poor fit. — [Cao & Leach, ICPC 2023](https://arxiv.org/pdf/2304.03854)
- DIRTY "only predicts types in its vocabulary and does not support predicting structs that did not appear in" training. — [TYGR, USENIX Sec 2024](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- When ReSym's authors reproduced DIRTY on a project-split, sanitized, fully stripped dataset, its "In Train" and "Not in Train" accuracies came out 2.1–21.3% below the originally reported numbers. They attribute this to reduced train/test leakage and to fully stripped input. Reproduced DIRTY scores: overall 48.7% names, 55.8% types; not-in-train 34.8% names, 44.5% types; not-in-train structs 31.0% names, 33.3% types. [VERIFIED-PRIMARY] — [ReSym, CCS 2024](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- On struct layout recovery (Coreutils), DIRTY's recall is very low (the ReSym paper cites a figure of 3.3% in this comparison), because DIRTY "focuses on name and type". [VERIFIED-PRIMARY, number partially garbled in the PDF text extraction] — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)

**Cao & Leach, "Revisiting Deep Learning for Variable Type Recovery" (ICPC 2023)**: retrains DIRTY on Ghidra output
- Overall type accuracy: DIRTY-Hex-Rays 73.9%, DIRTY-Ghidra 73.5%. Function in train: 88.1% vs 91.2%. Not in train: 54.3% vs 64.1%. Structs overall: 65.8% vs 61.7%. Structs not in train: 51.7% vs 57.1%. [VERIFIED-PRIMARY] — [ar5iv 2304.03854](https://ar5iv.labs.arxiv.org/html/2304.03854)
- Structs make up only 2.45% of the Ghidra training set and 1.22% of the test set. Exact string match is the metric. Ghidra aliasing (values assigned to `uVar1` temporaries instead of the DWARF variable) is unresolved. 62.15% of Ghidra variables lack a DWARF mapping, against 20.13% for Hex-Rays. — [ar5iv 2304.03854](https://ar5iv.labs.arxiv.org/html/2304.03854)

**DEBIN (He, Ivanov, Tsankov, Raychev, Vechev; CCS 2018)**
- Trains probabilistic graphical models on non-stripped binaries to predict symbol names and types in stripped ones. Reported x64 precision is 68.8% and recall 68.3%. The CRF/dependency-graph detail and the use of a binary-level IR (BAP) are [UNVERIFIED] this session. — [ETH SRI page](https://eth-sri.github.io/publications/he18debin)
- A 2026 survey states that DEBIN and StateFormer "do not perform well on real-world binary programs." [snippet only] — [Zheng et al., arXiv 2606.23692 (2026)](https://arxiv.org/pdf/2606.23692)

**CATI (Chen et al., ICPC 2020)**
- A context-assisted neural model that infers types for variables located in stripped binaries, at the assembly level. The 2025 journal extension, CATI++, infers 19 variable types. The ICPC 2020 numbers were not retrieved [UNVERIFIED]. — [survey listing CATI as context-aware neural model](https://arxiv.org/abs/2606.23692); [CATI++ record](https://api.crossref.org/works/10.1093%2FCOMJNL%2FBXAF004)

**StateFormer (Pei et al., ESEC/FSE 2021)**
- Works on assembly, using two-step transfer learning. Pretraining uses "Generative State Modeling", which teaches the model operational semantics of instructions. Evaluated on 33 open-source projects. The authors claim a 14.6% gain over prior ML tools for argument and variable types, and say GSM improves accuracy by 33% (the abstract does not say whether these are relative or absolute). [ABSTRACT/PAGE] — [StateFormer PDF](https://www.cs.columbia.edu/~junfeng/papers/stateformer-fse21.pdf); [GitHub](https://github.com/CUMLSec/stateformer)
- TYGR found StateFormer's public dataset to be on average 89.9–90% duplicate functions (disassembly hashed after normalizing addresses), and only about 1% of TyDa's size. — [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)

**TYGR (Zhu et al., USENIX Security 2024)**
- Lifts binaries to VEX IR with angr and runs a lightweight intra-procedural data-flow analysis per function. A GNN then classifies the type of each register or memory location (stack and heap). It treats type inference as classification over a fixed subset of C types (int32, uint64, struct*, ...), which covers 97.1% of the types in its dataset. [VERIFIED-PRIMARY] — [TYGR PDF](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- Structs are handled in two steps. A base model first predicts "is a struct"; a second model then predicts member types, for example `int_S`. Struct accuracy is computed as base struct accuracy times member-model accuracy. It does not output names or a full declared layout, and adjacent stack structs merge into one large struct. — [TYGR PDF](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- Dataset: TyDa, deduplicated, built from Gentoo and Debian packages, covering 5 ISAs (x64, x86, AArch64, Arm32, MIPS) at O0–O3. On x64 O0–O3: overall 76.6%, struct 45.2%. The authors claim at least +26.1 points overall and +10.2 points on structs over DIRTY, OSPREY and StateFormer. In the DIRTY/OSPREY comparison figure, overall accuracy is roughly 55.8 / 71.8 / 74.5 (bar labels; mapping to tools inferred from the figure order). — [TYGR PDF](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- Limitations the authors state: accuracy "peaks at around 80%" however much training data is added. Their reasons are that rare types (enum*, union*) are scarce and that "some variable types cannot be effectively differentiated by only observing how the variables are used." Only intra-procedural data flow is used, and they name "incorporating callee- and caller-access patterns" as the critical next improvement. Globals are not handled. — [TYGR PDF](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)

**VarBERT (Pal et al., IEEE S&P 2024), "Len or index or count, anything but v1"**
- A BERT model pretrained on human source code and fine-tuned to predict variable names in decompiler output. It is trained and evaluated on both IDA and Ghidra (VarCorpus dataset). O2 accuracy: 54.43% (IDA) and 54.49% (Ghidra). On a VarCorpus subset: VarBERT 50.70%, DIRE 35.94%, DIRTY 38.00%. Names only. [ABSTRACT/PAGE] — [par.nsf.gov](https://par.nsf.gov//servlets/purl/10536794)
- TYGR cites Pal et al. as finding that 52% of the functions in DIRTY's DIRT dataset are duplicates, with 56.9% duplicates and 65.5% train/test overlap. — [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)

**ReSym (Xie, Zhang, Jiang, Xu, Tan, Zhang; ACM CCS 2024, Distinguished Paper)** [VERIFIED-PRIMARY]
- Input: decompiled code from fully stripped binaries, using IDA Pro (Hex-Rays). Two fine-tuned StarCoder-3B models do the prediction. VarDecoder predicts local variable names and types, and flags variable "clusters" (stack-inlined structs and arrays). FieldDecoder predicts, for each field-access expression, the base variable name and type plus the field name and type. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Posterior reasoning: a Prolog system gathers per-function LLM predictions and IDA-derived facts (field access at offset/size) across functions. It groups variables into "type groups" by data flow, including along call edges. It resolves conflicts by backtracking, detects type-agnostic arguments such as memcpy-like overlapping accesses (a threshold of 3 overlaps guards against optimization noise), and picks names by consensus voting. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Dataset: 7,416 GitHub C/C++ projects compiled into 113,696 binaries. Binaries with fewer than 80% unique functions are removed, leaving 16,217. Because 71.1% of a project's structs appear in more than one binary, the train/test split is by project (95/5). — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Results: variable names 56.4% and types 64.6% overall. Not in train: names 37.5%, types 49.9%; in train: over 85%. Struct layout (offset and size pairs both correct): precision 72.9%, recall 28.9%, F1 41.4%. Struct-type name accuracy 46.8%; field name 16.3%; field type 16.9%. Stack-inlined struct/array cluster detection F1 85.9%. Against few-shot GPT-4 on 100 functions, ReSym is ahead by 32.5 and 33.3 points. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Stated limitations: low layout recall is blamed on functions dropped for token limits (incomplete calling contexts) and on undecidable or incomplete data-flow analysis, which splits one source type across groups. Perfect-match scoring counts `uint8_t*` vs `char*` and `bufferSize` vs `size` as wrong. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)

**GenNm (Xu et al., NDSS 2025)**
- A generative code LLM (CodeGemma-2B, CodeLlama-7B/34B) for variable names from decompiled code. Its "symbol preference" training stage (SymPO) prefers names that fit the context, for example "packet" over "array". Inference starts per function and then propagates names along the call graph to callers and callees, within the token limit. Reported gains: +5.6 to 11.4 points precision over the state of the art. When the ground-truth names never appear in training, accuracy rises from 17.3% to 22.8%. [ABSTRACT/PAGE] — [NDSS paper](https://ndss-symposium.org/wp-content/uploads/2025-276-paper.pdf); [arXiv 2306.02546](https://arxiv.org/html/2306.02546v4)

**LLM4Decompile (Tan, Luo, Li, Zhang; EMNLP 2024)**
- The End models decompile binary to C directly. The Ref models refine Ghidra pseudo-code. Evaluated on re-executability on HumanEval-derived and ExeBench sets, where it reports more than 100% improvement over GPT-4o and Ghidra; Ref gives a further 16.2% over End. The abstract describes no type or struct prediction. — [arXiv 2403.05286](https://arxiv.org/abs/2403.05286)
- The Idioms authors criticize LLM4Decompile and Nova: they do not emit UDT definitions, so their output is underspecified, and their training data often kept function names, which the models learned to copy. — [Idioms](https://arxiv.org/html/2502.04536v2)

**Idioms (Dramko, Le Goues, Schwartz; arXiv 2025, v2 June 2025)** [VERIFIED-PRIMARY from HTML]
- Input: Hex-Rays output. For the LLM4Decompile baseline, test sets were re-decompiled with Ghidra to avoid covariate shift. Fine-tuned models: CodeQwen2.5-0.5B, LLM4Decompile-1.3B, CodeGemma-2B/7B and CodeLlama-7B. The main model is CodeGemma-7B with QLoRA. It generates the function and all the UDT definitions it needs, jointly. — [Idioms](https://arxiv.org/html/2502.04536v2)
- Context: neighbouring functions, taken breadth-first over the call graph (callees and callers) up to the context window. Struct metrics: "UDT nominal" accuracy requires field names to match too; "UDT structural" accuracy compares layout only and ignores names; nested types must match recursively. — [Idioms](https://arxiv.org/html/2502.04536v2)
- Results: ExeBench tests pass at 54.4%, against 46.3% for LLM4Decompile and 37.5% for Nova. On Realtype at O0, dependency-equivalence is 33.7% vs 27.4% and 23.9%. The best UDT structural accuracy on Realtype is only 15.1%. Accuracy drops sharply from O0 to O1 and changes little at higher levels (inlining was disabled). Realtype is deduplicated by MinHash over repositories and split by project. — [Idioms](https://arxiv.org/html/2502.04536v2)
- Limitations: possible pretraining leakage from GitHub; no evaluation on obfuscated code or malware; degenerate repeated type definitions; conservative metrics. — [Idioms](https://arxiv.org/html/2502.04536v2)

**TypeForge (Wang et al., IEEE S&P 2025)**
- Recovers composite types (structs) from stripped binaries in two stages. Synthesis builds candidates from a Type Flow Graph; selection then picks the best-fit type, and its judging scripts include an "LLM-assisted double elimination" step. Reported F1: composite-type identification 81.7%, layout recovery 88.2%, relationship recovery 72.1%. That the paper (as opposed to the repo) describes an LLM phase is [UNVERIFIED]; another paper describes TypeForge as an "LLM-driven hybrid" alongside ReSym and HyRES. — [GitHub noobone123/TypeForge](https://github.com/noobone123/TypeForge); [paper PDF](https://noobone123.github.io/papers/typeforge-sp25.pdf)

### Inferences
- The field splits into (a) closed-vocabulary classifiers of primitive or coarse types (DEBIN, CATI, StateFormer, TYGR, DIRTY) and (b) generative LLMs that can emit unseen names or structs (ReSym, GenNm, Idioms). Only ReSym, TYGR (member types), Idioms ("structural" metric) and TypeForge score layouts as opposed to type names.
- Headline accuracies (66–77%) are dominated by easy primitive or in-train cases. Every system that reports struct-specific results is far lower: 15–46% depending on the metric.

### Gaps
- No per-category (primitive vs pointer vs struct) breakdown was retrieved for StateFormer, DEBIN or CATI.
- The exact TYGR-vs-StateFormer figures and the label mapping in TYGR's comparison bar chart were not cleanly extracted.
- HyRES and TRex (structural type recovery, 2025) were not checked. No primary source was read for the RecStruct (USENIX Security 2026) result beyond its title.

## Q2. Accuracy on primitives vs pointers vs structs; how struct types are scored

### Takeaway
Struct types are the weak point of all learned approaches, and the scoring varies so much that the numbers are not comparable. Metrics in use include exact type-name string match (DIRTY, ReSym annotation), offset/size pair precision and recall (OSPREY-style, ReSym layout), member-type classification (TYGR), and recursive structural vs nominal match (Idioms).

### Cited Findings
- DIRTY-style exact match: struct accuracy is 65.8% overall but 51.7% not in train on Hex-Rays. Structs are only about 1–2.5% of variables. — [Cao & Leach](https://ar5iv.labs.arxiv.org/html/2304.03854)
- ReSym's layout metric counts a field correct only if both offset and size are correct (following OSPREY). Its struct-name annotation is scored separately (46.8%), and field name and type are scored as wrong whenever the field itself is missed (16.3% / 16.9%). — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- TYGR: 76.6% overall vs 45.2% struct. Struct accuracy is the product of struct-detection accuracy and member-type accuracy. — [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- Idioms: UDT structural accuracy (layout only) peaks at 15.1% on Realtype. Nominal accuracy, which also requires field names, is stricter. — [Idioms](https://arxiv.org/html/2502.04536v2)
- TypeForge reports layout-recovery F1 88.2% on its own benchmark. — [TypeForge repo](https://github.com/noobone123/TypeForge)
- Perfect-match metrics penalize equivalent types such as `uint8_t*` vs `char*`. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf); exact match is also noted as strict in [Cao & Leach](https://ar5iv.labs.arxiv.org/html/2304.03854)

### Inferences
- Systems that predict field layouts (offsets and sizes or member types): ReSym (layout plus names), TYGR (member types, no names), Idioms (full definitions), TypeForge (layout and relationships), OSPREY (non-ML, sizes only). DIRTY, VarBERT, GenNm and DIRE predict names or type names only.
- The gap between ReSym's layout precision (72.9%) and recall (28.9%) suggests the fields it does recover are mostly right but it misses most of them. This fits a model that only sees fields the analysed code actually touches.

### Gaps
- No paper found separates pointer-to-primitive from pointer-to-struct accuracy in a way that can be compared across tools.

## Q3. Generalisation problems: decompiler mismatch, optimisation, unseen projects, leakage, synthetic code, symbol clues

### Takeaway
Leakage and duplication have inflated many reported results: DIRT has about 52–57% duplicate functions and 65.5% train/test overlap, and StateFormer's data is about 90% duplicates. Accuracy on functions not seen in training drops by roughly 20–35 points. Optimisation (O0 to O1) and decompiler choice also shift results, and models learn to copy leftover symbol names.

### Cited Findings
- DIRTY on Hex-Rays: 88.1% in train vs 54.3% not in train. ReSym: over 85% vs 37.5% (names) and 49.9% (types). — [Cao & Leach](https://ar5iv.labs.arxiv.org/html/2304.03854); [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- DIRT duplication: 52% (Pal et al., as cited by TYGR); also 56.9% duplicates and 65.5% train/test overlap. StateFormer dataset: 89.9% duplicates. "Such high rates of duplicate functions will lead to inflated prediction accuracy." — [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- 71.1% of a project's structs recur across that project's binaries, so a split by binary leaks struct definitions; ReSym splits by project. Reproduced DIRTY lost 2.1–21.3 points under this split. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Decompiler mismatch: DIRTY retrained on Ghidra performs about as well as on Hex-Rays (73.5% vs 73.9%). This contradicts the original claim that Ghidra was unsuitable. But the two decompilers' variables map very differently to DWARF (62% vs 20% of variables unmapped). — [Cao & Leach](https://ar5iv.labs.arxiv.org/html/2304.03854). Idioms re-decompiled with Ghidra for the Ghidra-trained baseline specifically to avoid covariate shift. — [Idioms](https://arxiv.org/html/2502.04536v2)
- Optimisation: Idioms accuracy drops sharply at O1 (inlining disabled). VarBERT reports O2 numbers. TYGR covers O0–O3 and five ISAs. DIRTY and OSPREY support only x64. — [Idioms](https://arxiv.org/html/2502.04536v2); [VarBERT](https://par.nsf.gov//servlets/purl/10536794); [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)
- Symbol and name clues: LLM4Decompile and Nova training data often kept function names, which the models learned to copy, inflating scores. — [Idioms](https://arxiv.org/html/2502.04536v2). DIRTY's original input was not fully stripped; ReSym's reproduction on fully stripped input was harder. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Synthetic vs real code: Idioms introduces Realtype because ExeBench-style benchmarks lack complex realistic types. On Realtype even the best model gets only 15.1% UDT structural accuracy. — [Idioms](https://arxiv.org/html/2502.04536v2)
- Names never seen in training: GenNm accuracy is only 17.3% to 22.8%. — [GenNm](https://arxiv.org/html/2306.02546v4)
- Pretraining contamination (GitHub code in base LLMs) is acknowledged as a residual leakage risk. — [Idioms](https://arxiv.org/html/2502.04536v2)

### Inferences
- When the project, the names and the optimisation level are all unseen, realistic accuracy for struct-level typing is plausibly well under 50%.
- Nearly all corpora are open-source GitHub C built with GCC. Obfuscated code and malware (beyond ReSym's Mirai case study), MSVC builds and C++-heavy code are under-tested.

### Gaps
- I found no systematic cross-decompiler transfer study (train on Hex-Rays, test on Ghidra without retraining) with numbers.
- No numbers were found for compilers other than GCC (Clang, MSVC).

## Q4. Use of inter-procedural (caller/callee) context and how much it helps

### Takeaway
Three systems use call-graph context explicitly: ReSym (Prolog aggregation across functions), GenNm (name propagation along the call graph) and Idioms (neighbour functions in the prompt). It helps mainly struct layout: ReSym gains +14 F1 and +12.1 recall; Idioms reports up to 63% better UDT structural accuracy. TYGR is purely intra-procedural and names caller/callee patterns as its key missing ingredient.

### Cited Findings
- ReSym: posterior reasoning across functions raised struct layout F1 from 27.4 to 41.4 and recall from 16.8 to 28.9 (16,411 more correct offset/size pairs). Precision fell slightly, from 74.9 to 72.9, because of noise in identifying type-agnostic arguments. Struct-name accuracy rose from 42.6 to 46.8. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- ReSym blames low recall partly on functions discarded for token limits, which "leads to incomplete calling contexts and potentially overlooked field access expressions". — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- Idioms: neighbour context (breadth-first over callers and callees) gives up to 63% improvement in UDT structural accuracy, with gains growing with model size. Code-correctness metrics move by only about 1 point. — [Idioms](https://arxiv.org/html/2502.04536v2)
- GenNm propagates names from each function to its callers and callees. — [GenNm](https://arxiv.org/html/2306.02546v4)
- TYGR: "A critical improvement ... will be incorporating callee- and caller-access patterns"; inter-procedural analysis is avoided for cost reasons. Some types "cannot be effectively differentiated by only observing how the variables are used." — [TYGR](https://www.usenix.org/system/files/usenixsecurity24-zhu-chang.pdf)

### Inferences
- The evidence that context helps type parameters a function never dereferences is indirect. ReSym's type groups pass field-access facts between callers and callees, which is exactly the mechanism by which a pass-through pointer would receive a layout. TYGR's ceiling of about 80% from "use only" information is consistent with this. But no paper isolates "never-dereferenced parameters" as an evaluated category.

### Gaps
- I found no study that measures accuracy specifically on parameters a function never dereferences, with and without caller context.

## Q5. Checking or verifying learned predictions against the binary

### Takeaway
Most learned type predictors are not checked against the binary. ReSym's Prolog reasoning is the main exception, and it checks only consistency: predicted fields must agree with IDA-observed offsets and sizes and across a type group. That is not soundness. Matching-decompilation projects provide a strong oracle in compile-and-diff (byte-identical recompilation), and LLM agents are now being used inside that loop, though agents reportedly struggle with struct field offsets.

### Cited Findings
- ReSym checks LLM-predicted fields against field-access facts (offset and size identified by IDA), detects conflicts such as overlapping fields, backtracks to the root cause, and uses consensus voting. This raises recall but cannot guarantee correctness; precision drops 2 points from noisy grouping. — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- LLM4Decompile and Idioms use executable tests (re-executability, ExeBench "passes tests") as a semantic check on generated code. SLaDe requires test cases at inference, which Idioms calls unrealistic for reverse engineering. — [LLM4Decompile](https://arxiv.org/abs/2403.05286); [Idioms](https://arxiv.org/html/2502.04536v2)
- Matching decompilation (N64 projects, decomp.me): a build tool compiles the candidate C, diffs it against the target, and reports a match from 0 to 100%. Agents "struggle to compute the correct byte offset of a struct field", and struct layouts matter because later functions share them. They also struggle with control flow and register allocation. Source is a practitioner blog, not peer reviewed. — [Chris Lewis blog](https://blog.chrislewis.au/using-coding-agents-to-decompile-nintendo-64-games/)
- Claims that whole N64 games (for example Snowboard Kids 2, 3,013 functions) reached 100% match with LLM agents come from aggregator or blog pages and were not verified against the repositories. — [capitalandcompute.net](https://capitalandcompute.net/blog/which-games-has-ai-decompiled/); [gambiconf substack 60-function test](https://gambiconf.substack.com/p/can-llms-really-do-matching-decompilation)

### Inferences
- Compile-and-compare verifies that code with a layout reproduces the binary. It does not verify that field names or semantic types are right, since many types (`uint8_t*` vs `char*`, different struct names) give identical code. It also needs the exact original compiler and flags, which is feasible for N64 (IDO/GCC versions) but rarely available for arbitrary binaries.

### Gaps
- I found no peer-reviewed paper that verifies learned struct layouts by recompilation and binary diffing, outside the matching-decompilation hobby community.
- The Mizuchi benchmark results were not retrieved.
