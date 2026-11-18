# Dynamic (Execution-Based) Type and Data-Structure Recovery, and Dynamic Front Ends for Daikon-Style Invariant Inference on Binaries

Scope note: the primary sources below were read in full text where possible: the Howard and REWARDS PDFs, the Laika, MemPick, TIE, DynComp (ISSTA 2006) and ClearView PDFs, Guo's 2006 MIT M.Eng. thesis, the Daikon user and developer manuals, the Valgrind Memcheck manual, and Fjalar's `fjalar_main.c` source. Several tools (Laika, Howard, REWARDS, TIE) were evaluated on 32-bit x86 (EBP-framed, gcc-4.x era) binaries. Applying their findings to x86-64 is flagged as inference where it comes up.

## Q1. How do REWARDS, Howard, Laika, DDE, MemPick, ARTISTE and similar tools recover types and structs from execution? What accuracy do they report, and what are their limitations?

### Takeaway
There are three families of dynamic recovery:
- **Type propagation from known "type sinks"**: REWARDS.
- **Memory-access-pattern / base-pointer analysis**: DDE, Howard.
- **Value- and shape-based classification of memory images or heap graphs**: Laika, MemPick.

All of them report high accuracy, but only on the data that was actually exercised: about 97% for REWARDS on exercised stack structures, "practically all" exercised memory correct for Howard, and only about 0.65–0.80 pairwise class accuracy for Laika. They share the same failure modes: flattening of nested and stack structs, memset/memcpy strides, unions, custom allocators, short arrays, and int/pointer confusion.

### Cited Findings

**REWARDS** (Lin, Zhang, Xu; NDSS 2010)
- Each memory location the program accesses is tagged with a timestamped type attribute. Types come from "type sinks" and propagate forward through data flow, and backward resolution recursively types variables accessed earlier. The timestamps keep separate instances that reuse the same address apart: stack frames reused by different calls, and malloc/free reuse. — [REWARDS, NDSS 2010](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- The type sinks are (1) system calls, (2) standard library calls such as strcpy, and (3) type-revealing instructions: string-movement instructions, floating-point instructions ("Floating-point instructions operate on floating-point, integer, and binary coded decimal operands"), and pointer dereferences (an indirect memory operand implies a pointer). — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- Heap objects are abstracted by the allocation PC plus the call stack: "heap structure instances allocated from the same PC in the same call stack should have the same type". Array size inside a heap region is approximated by "the maximum number of accesses by the same PC to unique memory locations". Heap abstractions from different sites with the same field types are heuristically clustered. Stack variables are named by their offset in the frame of the residence function. REWARDS reads /proc/pid/maps and PIN image-load data to decide whether a value is a code pointer or a data pointer. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- Evaluation covered 10 utilities (ps, ping, netstat and coreutils commands), with ground truth from libdwarf on recompiled -g binaries. REWARDS reports "an average of 97% accuracy ... for the data structures that get exercised" on the stack. Heap output "perfectly matches the types in the original definitions when they are exercised". Globals reached "over 85% accuracy". A partially used buffer counts as correct if its bytes are "either correctly typed or unused". — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- The paper identifies two causes of error:
  - **Hierarchy loss**: global and stack structs addressed by a section offset or frame offset rather than base+offset come out flat.
  - **Path-sensitive memory reuse**: the compiler places different locals from different paths at the same stack slot, so their types are "undesirably unified".
  - Other stated limitations: coverage limited to the structures created and accessed during the run; an offline resolution pass is needed; no kernel support; defeated by obfuscation, e.g. by avoiding the type sinks; and it "does not distinguish between sign and unsigned integers". — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)

**Howard** (Slowinska, Stancescu, Bos; NDSS 2011)
- Howard is built on an instrumented emulator (QEMU-based). Every memory location carries a tag, MBase(addr), recording which base pointer its address was derived from, and registers carry RBase. Root pointers are found separately for static memory, heap and stack. Locations that share a base pointer form a structure. Stack frames are identified by function start address. A function is a call target that returns with ret and whose stack pointer matches at call and return. — [Howard, NDSS 2011](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Arrays are detected through loops, using two complementary methods: element addresses derived from the previous element (`elem=*(prev++)`) or from a common base (`array[i]`, which covers hash tables). The detectors handle multiple loops, nested loops, unrolling, and boundary elements touched outside the loop. Type sinks are optional: the evaluation results were "obtained without turning on type sinking at all". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Results are reported in five categories: OK / flattened / missed / unused / unused array. The paper concludes that "practically all memory is either detected correctly or unused", and "for practically all arrays and structs the lengths were identified correctly". The stack shows more "unused" and "flattened" results than the heap. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Coverage achieved (Table 1):

  | Program | Functions exercised | Variables used | KLEE coverage |
  |---|---|---|---|
  | wget | 51% | 56% | 24% |
  | fortune | 71% | 77% | test suite only |
  | grep | 50% | 56% | 46% |
  | gzip | 70% | 81% | 54% |
  | lighttpd | 55% | 62% | test suite only |

  — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- The main source of "missed" results: a struct with 4-byte fields that is initialized with memset can be indistinguishable from an int array ("we have no means for discarding the array hypothesis"). Nested structs are another source, e.g. the 24-byte STRFILE inside the 88-byte FILEDESC in fortune. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Stated limitations:
  - Nested structs that are never accessed separately are merged into their parent.
  - Unions produce a "merge (or intersection)" of the member layouts.
  - Generic custom allocators (e.g. Apache's) cause misclassification; slab-like allocators are handled.
  - Locals of functions reached by jmp rather than call are not analyzed.
  - Loop unrolling can turn an int array into an "array of 4-field structures".
  - Inlining merges frames.
  - Evaluation used gcc-4.4 x86 only. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)

**DDE** (Slowinska, Stancescu, Bos; "DDE: Dynamic Data Structure Excavation", ACM SIGCOMM APSys 2010)
- DDE is the workshop predecessor of Howard. With Howard, it gives preference to "non-regular accesses and strides not equal to the word size" to counter memcpy-style word-stride accesses. — [Caballero & Lin, ACM CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

**Laika** (Cozzie, Stratton, Xue, King; OSDI 2008)
- Laika works on a memory image rather than an execution trace. It estimates object positions from potential pointers, converts each machine word to a "block type", then clusters objects with Bayesian unsupervised learning. The block types are address (points into heap/stack), zero, string, and data. — [Laika, OSDI 2008](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- Measured ground-truth noise:
  - Fewer than 1% of pointers are unaligned.
  - 1% of integers and 3% of strings "point into the heap".
  - About 80% of pointers point to the head of an object.
  - Only 45% of the heap is occupied by active objects; the rest is "malloc padding and unused or uninitialized chunks".
  - Only 30% of objects contain a pointer.
  - Without size information, Laika "can easily estimate the size of an object as eight or more times the correct value". — [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- Accuracy (Table 2), memory image only: average p(real|laika) = 0.68 and p(laika|real) = 0.65. With malloc size and location information: 0.80 and 0.70. Building ground truth was itself hard because "The problems begin with unions, continue with strange pointer accesses, and climax with bugs and buffer overflows". — [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)

**MemPick** (Haller, Slowinska, Bos; WCRE 2013)
- MemPick classifies heap data structures (singly and doubly linked lists, binary/n-ary, AVL, red-black and B-trees, graphs) in stripped binaries by analyzing the shape of the pointer graph during "quiescent periods". In the experiments these were the longest 1% of gaps between modifications.
- Small trees (7 nodes or fewer) cannot be told apart by balancedness. Above that size the error rate was 0%, and other misclassifications were under 1% of partitions.
- Limitations: allocator hooks are required, so custom allocators must be identified; "typeless pointers, unions or inner structs could confuse" it; coverage is limited to "what we execute".
- The paper explicitly cites dynamic invariant detection as a consumer: knowing pointer and value field types "helps to select the relevant values to compare and to avoid unnecessary computation". — [MemPick, WCRE 2013](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf)

**ARTISTE** (Caballero, Grieco, Marron, Lin, Urbina; tech report TR-IMDEA-SW-2012-001, 2012)
- ARTISTE generates hybrid data-structure signatures from executions. Its primitive type lattice adds floating-point and 64-bit types and treats pointers as a subtype of numbers (ptr32 refines num32). It is one of only three dynamic approaches (with Howard and BCR) that combine results from multiple executions. — [Caballero & Lin, ACM CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

**Survey view** (Caballero & Lin, "Type Inference on Executables", ACM Computing Surveys 48(4), 2016)
- Of 38 surveyed works, 21 use static analysis, 21 use dynamic analysis, and 4 combine both (WCKK, DDT, BCR, TIE).
- The advantages of dynamic analysis are "accuracy and simplicity", because addresses, operand values and control-flow targets are known. The cost is coverage. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- Every accuracy number above is conditional on exercised code. REWARDS, Howard and TIE all score unexercised or unused data separately, or exclude it. A Daikon-style front end has the same blind spot: what never runs is never typed, and so has no variables to trace.
- The 32-bit EBP-frame assumptions (stack structs addressed by frame offset, which causes flattening) probably get worse on x86-64 -O2 code, where variables live in registers and frame pointers are omitted. The papers do not measure this.

### Gaps
- I did not obtain the DDE (APSys 2010) or ARTISTE tech-report full texts. Their details here come from the CSUR 2016 survey only, and their own accuracy figures are not reported.
- Howard's Figure 11/12 percentages are given only as bar charts. The text did not yield exact numbers per program.

## Q2. Coverage: only executed paths reveal accesses. How do papers quantify the effect of low coverage, and how do they combine static and dynamic analysis?

### Takeaway
Papers quantify coverage as the fraction of functions or variables exercised: Howard reaches 50–71% of functions and 56–81% of variables even with KLEE. Unexercised data is then excluded from accuracy. TIE showed directly that single-path dynamic results can disagree across inputs, and that static analysis at 100% coverage is about as precise as REWARDS.

### Cited Findings
- Howard used KLEE (adapted for binaries by EPFL) together with test suites. KLEE line coverage was only 24% (wget), 46% (grep) and 54% (gzip). Much of the "unused" memory is attributed to "the limited coverage", and "Driving KLEE down the right execution path is not always trivial". Howard argues that it only needs each data structure to be seen once, not all paths. — [Howard, NDSS 2011](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- REWARDS Figure 2 reports three numbers per program: the percentage of functions executed, the percentage of declared structures used in those functions, and accuracy over the used ones. — [REWARDS, NDSS 2010](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- TIE (Lee, Avgerinos, Brumley; NDSS 2011):
  - Running REWARDS on two inputs to the same function "results in two different and incompatible sets of results which dynamic systems alone cannot resolve". In TIE's Figure 1, the same variable is typed `32-bit data` on one trace and `pointer` on the other.
  - In the dynamic setting at about 8.73% average coverage on 5 coreutils programs, TIE scored conservativeness 1.0 and type-lattice distance 1.15, versus REWARDS at 0.59 and 2.19.
  - TIE static at 100% coverage scored 0.93 and 1.57: "static analysis is about as precise as REWARDS but can type 100% of all variables".
  - TIE also notes that REWARDS hand-ascribes about 150 named types to about 84 libc calls. — [TIE, NDSS 2011](https://users.ece.cmu.edu/~dbrumley/pdf/Lee,%20Avgerinos,%20Brumley_2011_TIE%20Principled%20Reverse%20Engineering%20of%20Types%20in%20Binary%20Programs.pdf)
- The CSUR survey: only 3 dynamic approaches (Howard, BCR, ARTISTE) merge multiple executions. "Variables may only be used (and thus their types inferred) in some program paths", and different runs may infer different types. Static+dynamic combination is named as the open direction. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- ClearView combines static and dynamic analysis to build procedure CFGs: it symbolically executes code discovered at run time instead of finding procedure entry points statically ("a complex task in a stripped x86 executable"). Splitting a static procedure into several dynamic ones "may reduce the set of values available to the invariant inference engine". — [ClearView, SOSP 2009](https://people.csail.mit.edu/rinard/paper/sosp09.pdf)
- MemPick also proposes fusing in Howard or static analyses "to limit potential false positives". — [MemPick, WCRE 2013](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf)

### Inferences
- For a Daikon front end, low coverage has two effects. Program points that are never executed produce no invariants at all. Program points that run on few or unrepresentative inputs produce over-specific invariants (e.g. `x == 3`) and possibly incorrect type guesses (int versus pointer), which then change which invariants are even attempted.

### Gaps
- I found no paper that measures type-recovery accuracy as a function of coverage, e.g. accuracy versus number of runs or inputs. Coverage is always reported side by side with accuracy, never as a curve.

## Q3. Specific dynamic ambiguities

### Takeaway
Most of the listed ambiguities are documented in the primary literature as concrete failure modes:
- int/pointer confusion (Laika's 1%/3% false pointers; ClearView's value heuristic)
- uninitialized memory (Memcheck V-bits; Daikon's "nonsensical")
- short arrays (Howard's 4-access threshold)
- memset/memcpy strides
- unions
- interior pointers and missing base pointers
- allocation-site typing collisions (REWARDS)

### Cited Findings
- **Integers versus pointers.**
  - Laika measured 1% of integers and 3% of strings that "point into the heap", and notes some pointers are uninitialized. — [Laika, OSDI 2008](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
  - ClearView's binary Daikon front end uses a value heuristic: "if a negative value or a value between 1 and 100,000 ever appears in a variable, Daikon infers that it is not a pointer. Otherwise, Daikon infers that it is a pointer". It uses this to skip lower-bound and less-than invariants over pointers. — [ClearView, SOSP 2009](https://people.csail.mit.edu/rinard/paper/sosp09.pdf)
  - REWARDS decides pointer versus non-pointer by dereference and by checking address ranges from /proc/pid/maps. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
  - ARTISTE models pointers as a subtype of numbers so that arithmetic does not force a decision. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **NULL.** In Laika's block types, zero is its own class. As a result, a binary-tree leaf (two zero words) and an internal node (two address words) may be split into different classes. — [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- **Uninitialized memory.**
  - Memcheck tracks one A (addressability) bit per byte and one V (validity) bit per data bit, including in integer, FP and vector registers. Copying undefined data is silent. A complaint is issued only when undefinedness could affect "externally-visible behaviour", such as a conditional branch. — [Valgrind Memcheck manual](https://valgrind.org/docs/manual/mc-manual.html)
  - Fjalar includes a modified Memcheck. Its API lets tools query A- and V-bits "to ensure that memory accesses do not result in segmentation faults or invalid data". Heap array sizes are found by scanning forward and backward to Memcheck's red zones (unset A-bits). — [Guo, MIT M.Eng. thesis 2006](https://pg.ucsd.edu/publications/Philip-Guo_Masters-thesis_mixed-level-dynamic-analysis.pdf)
  - Laika found the heap only 45% live objects, the rest padding or uninitialized. — [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- **Arrays touched at few elements.** Howard "will not recognize an array if fewer than four of its elements are accessed in a loop". Such an array is classified as a structure, reported as "Missed short". Howard also merges detected arrays with trailing unused bytes, which can overestimate their length. Further, "if a structure consists of one field followed by an array, and the field and array are accessed in sequence, it is impossible to classify it correctly solely based on memory access patterns". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Wide copies (memset/memcpy).**
  - These functions "access all bytes in a structure sequentially, typically with a stride of one word". Blacklisting them cannot cover the application's own copy loops, so Howard prefers the "less common" layout (distinct fields over an int array). — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
  - The survey adds that memcpy loop iterations may move "the last two bytes of one variable and two char variables stored next to it". The listed remedies are byte-granularity constraints and ignoring propagation inside copy functions. On 32-bit x86, a double stored with two 4-byte moves is misrecovered as two 4-byte variables. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Unions.**
  - Howard reports a merge or intersection of the member layouts. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
  - The survey assigns full union support to no approach: an untagged union is fundamentally hard to tell apart from a type conflict. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
  - MemPick and Laika also list unions as confounders. — [MemPick](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf); [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- **Unknown extent: stack and interior pointers.**
  - On the stack, fields can be addressed relative to EBP instead of the struct base. Howard: "A missing base pointer is of course a fundamental limitation, as we cannot recognize what is not there". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
  - Laika: "some objects might be split in two by internal pointers"; about 20% of pointers do not point to object heads. Tail-accumulator (flexible array member) structs break the assumption of fixed-length classes. — [Laika](https://www.usenix.org/legacy/event/osdi08/tech/full_papers/cozzie/cozzie.pdf)
- **Heap allocation-site typing.**
  - REWARDS keys heap types on allocation PC plus call stack. Wrappers like my_malloc defeat simple PC keys. Howard notes that "for heap memory, such simple pointers will not do". — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf); [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
  - Custom allocators produce "mixed access patterns inherited from various different structures/arrays". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Stack slot reuse.** REWARDS unifies the types of distinct locals that share a slot on different paths. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)

### Inferences
- Tagged pointers (low-bit tags, or high bits on x86-64) are not addressed in any of these papers. A range check against /proc/pid/maps would classify a tagged pointer as an integer, and a "non-pointer if small value" heuristic like ClearView's would misfire on small integer-like handles.
- Memcheck definedness is bit-precise but does not mean "meaningful". A value can be fully defined yet stale, e.g. a dead stack slot or a register left over from an earlier call. Definedness is therefore necessary but not sufficient for deciding whether to print a value as "nonsensical".

### Gaps
- I found no primary source that quantifies tagged-pointer or NaN-boxing effects on dynamic binary type recovery.

## Q4. Floating point: SSE registers, float versus double, how dynamic tools read float return values and arguments, and known pitfalls

### Takeaway
Dynamic tools mostly treat floating point as a type sink (FP instructions imply FP operands) and rarely distinguish sizes. Kvasir/Fjalar reads the return value from the low 64 bits of xmm0 (and xmm1) and relies on DWARF to say float or double. A front end without debug info must work out from instructions whether xmm0 holds a float, a double, or nothing meaningful.

### Cited Findings
- REWARDS uses floating-point instructions as type sinks, and its binary-op rule propagates types without, for example, "associating the float point type with the integer variable" when a float and an int are added. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- The CSUR survey: x86 FP can be 32, 64 or 80 bits. It assigns "full float support" only to approaches that infer different float sizes. Among static approaches, only SecondWrite performs height analysis of the x87 FP stack. ARTISTE's lattice explicitly includes floating-point types, while TIE's is shown without them. — [CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- Fjalar source (`fjalar_main.c`): on function exit it reads "the low 64 bits of %xmm0 on amd64, and the top of the x87 FPU stack on x86" as a `double`, plus `guest_YMM1` as a second FP return. It copies Memcheck A/V bits and DynComp tags for those registers along with RAX and RDX. — [Fjalar fjalar_main.c](https://raw.githubusercontent.com/codespecs/fjalar/master/valgrind/fjalar/fjalar_main.c)
- Kvasir's DynComp has a known x86-64 ABI pitfall: structs smaller than 8 bytes passed in a register cause "all fields of the struct" to be marked comparable. — [Daikon manual §7.3.9](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)

### Inferences
- Under the SysV x86-64 ABI, a float return occupies only the low 32 bits of xmm0. A black-box tool that always reads 64 bits as a double will print garbage for float returns. Choosing correctly requires knowing the callee's instructions (movss/cvtsd2ss versus movsd) or the caller's use of the value.
- When a function returns an integer, xmm0 still holds whatever was last written there. Memcheck V-bits will usually report it as defined, so definedness cannot tell a black-box front end whether an FP return value exists. Only instruction evidence can, i.e. a write to xmm0 before ret, or a read of it after the call.
- FP arguments in xmm0–xmm7 are counted separately from integer arguments in rdi/rsi/rdx/rcx/r8/r9, so recovering arity requires watching both register classes. Variadic calls also set al to the number of vector registers used. This is standard ABI knowledge and was not confirmed in the sources read here.

### Gaps
- I found no paper that evaluates dynamic float-versus-double recovery accuracy on x86-64 SSE code specifically.

## Q5. Daikon front ends: how Kvasir uses DWARF, what it reports, and what a front end without debug info must reconstruct

### Takeaway
Kvasir gets every name, type, scope, struct layout and static array size from DWARF. It gets validity from Memcheck A/V bits and runtime array extents from heap red zones, and it reports a "nonsensical" value (modbit 2) for anything invalid. A stripped-binary front end must recover all of this from scratch. The only published Daikon-on-stripped-binaries work found is ClearView (SOSP 2009), which used instruction-level register and memory variables with no source-level types.

### Cited Findings
- **Requirements.** Kvasir requires DWARF-2/3/4 debug info and no optimization (`-gdwarf-3 -O0 -no-pie`). It cannot process PIE binaries, is "definitely incompatible with the -fomit-frame-pointer optimization", and supports only amd64-linux. It "obtains [names and types] from debugging information included in the executable in a standard format (DWARF)" rather than from source code. — [Daikon manual §7.3, §7.3.9](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)
- **What is traced.** Globals, parameters and return values are output at function ENTER/EXIT; locals are not. File-static and function-static variables are scoped to their compilation unit or function by default.
- **Pointer dereference depth.** Controlled by `--struct-depth` (default 4, for recursive types) and `--nesting-depth` (default 2).
- **Arrays.** Static arrays can be flattened. Struct variables themselves are not output unless `--output-struct-vars` is given.
- **Pointers as arrays.** Every pointer is treated as an array by default ("would print result[] rather than result[0]"). `.disambig` files or `--smart-disambig` (an observed single-element versus array heuristic) override this per variable.
- **char types.** `char` defaults to integer; `char*` defaults to "a string, possibly zero-terminated".
- **Pointer type coercion.** Allows `void*` fields to be traversed. Without it, structs are always printed by their compile-time type, so derived-class fields are missing.
- **DynComp.** Runs by default and adds abstract-type comparability sets to the .decls file. Running without it is "strongly discouraged".
- All of the above: [Daikon manual §7.3.2, §7.3.3, §7.3.5](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)
- **Nonsensical values.** These are values that "cannot be evaluated": x uninitialized or deallocated, x.y with x null, a[i] out of bounds. They are written as `nonsensical` with modified-bit 2. Reasons given: "outputting nonsense values can degrade invariant detection; patterns in the valid data may be masked by noise", and dereferencing invalid pointers can crash the program. "Determining when an expression's value is meaningless is the most challenging part of writing an instrumenter for a language like C". Daikon ignores nonsensical values, and its output is implicitly guarded (`a.b == 0` means "if a is non-null"). — [Daikon Developer Manual A.4.1](https://plse.cs.washington.edu/daikon/download/doc/developer.html); [Daikon manual](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)
- **Derived variables.** Daikon creates them itself, e.g. `a[i]` for an array a and an integer i. These expressions need not appear in the program. — [Daikon manual](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)
- **Fjalar's design.** Fjalar is "mixed-level": language-level information comes from DWARF and memory safety from binary-level Memcheck. Traversal follows a pointer only "if it points to an allocated and initialized region of memory", and names derived variables as C expressions such as `foo->bar.baz[1]`. Guo states that "A purely binary-based analysis cannot accomplish such detailed observation absent some indication of how to interpret raw binary values as data structures". The source-based predecessor Dfec failed on real C programs because of "nested pointers to structs, arrays within structs, multiple layers of pointers, and integer-to-pointer casts". — [Guo, MIT M.Eng. thesis 2006](https://pg.ucsd.edu/publications/Philip-Guo_Masters-thesis_mixed-level-dynamic-analysis.pdf)
- **ClearView** (Perkins et al.; SOSP 2009): "works on stripped Windows x86 binaries without any need for source code, debugging information". It is a new Daikon front end built on Determina/DynamoRIO-style code-cache instrumentation.
  - Variables are the operand values each instruction reads and the addresses it computes, e.g. `[ebp+12]`.
  - Variables are restricted to those computed by the instruction or a predominator, so that they are "defined in all possible executions".
  - It infers only invariants involving the target instruction's variables.
  - Duplicate variables were removed, halving the number of invariants.
  - It adds stack-pointer offset invariants (`sp1 = sp2 + c`) and uses the value heuristic above to decide pointer versus non-pointer. — [ClearView, SOSP 2009](https://people.csail.mit.edu/rinard/paper/sosp09.pdf)
- Howard's stated use case is generating debug symbol tables for stripped binaries so that tools like gdb work. MemPick proposes feeding its output into Howard's tables. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf); [MemPick](https://www.syssec-project.eu/m/page-media/3/mempick_wcre13.pdf)

### Inferences
To produce Kvasir-comparable traces, a stripped-binary front end must reconstruct each item that Kvasir currently gets from DWARF or from Memcheck:

| Must reconstruct | Kvasir's source today | Possible substitutes, or why it is hard |
|---|---|---|
| Function boundaries and ENTER/EXIT points | DWARF | Call/ret matching, as in Howard and ClearView |
| Arity, and which registers or stack slots are parameters | DWARF | ABI register reads before write; integer and xmm registers counted separately |
| Return kind: none, int in rax/rdx, FP in xmm0/xmm1, struct via hidden pointer | DWARF | Instruction evidence (Q4) |
| Pointer versus integer | DWARF types | Dereference evidence, map ranges, ClearView-style value heuristics |
| Pointee extent: array or single element (Kvasir's "A"/"P" disambiguation) | DWARF, plus `.disambig` | Memcheck red zones for heap; nothing comparable for stack or global interior pointers |
| Struct layout for `->` traversal | DWARF | Howard/REWARDS-style recovery |
| char* versus byte buffer | DWARF char type | String heuristics, as in Laika |
| float versus double | DWARF | SSE instruction evidence |
| Signedness | DWARF | REWARDS does not attempt it |
| Globals and their extents | DWARF | Section maps; REWARDS-style flat layouts |

Memcheck A/V bits and the "nonsensical" convention carry over unchanged, because they do not depend on DWARF. Names such as `arg1`, `ret` or `*(arg1+8)` would replace source names. Daikon's variable "rep-types" (int, double, hashcode, String, arrays) would have to be chosen from recovered evidence.

### Gaps
- No published work was found that runs Daikon on stripped Linux/x86-64 ELF binaries at function granularity, producing Kvasir-like ENTER/EXIT traces with recovered types. ClearView is instruction-level and on Windows x86. This is a gap in the literature as far as these searches could tell, not a confirmed absence.
- Searching for a Kvasir option or mode that works without debug info found none. The manual states DWARF is required.

## Q6. How invariant inference quality depends on variable and type recovery

### Takeaway
Direct evidence from DynComp (ISSTA 2006): coarse "representation types" yield many times more invariants, mostly spurious, than abstract types. For flex the counts are 1.41 billion versus 1.8 million, and hand inspection found nearly all the eliminated invariants were spurious. Daikon's documentation says invalid values mask real patterns. So wrong or coarse types give meaningless invariants, and missing variables (untraced, nonsensical, or unexercised) give missing invariants.

### Cited Findings
- **DynComp** (Guo, Perkins, McCamant, Ernst; "Dynamic Inference of Abstract Types", ISSTA 2006). Number of invariants per treatment (Figure 6):

  | Program | Representation types | Declared types | Lackwit (static) | Abstract types (DynComp) |
  |---|---|---|---|---|
  | wordplay | 1,081,934 | 830,676 | 48,877 | 26,385 |
  | bzip2 | 28,608,435 | 13,316,420 | 600,834 | 392,180 |
  | flex | 1,410,893,630 | 1,401,545,090 | 37,720,499 | 1,801,367 |
  | Perl (non-hot opcode implementations) | 4,157,673,644 | 585,066,116 | not run | 8,849,326 |

  Run time and memory fell as well: flex 930 s / 380 MB down to 460 s / 110 MB. For SVM-Light, the researcher whose program it was confirmed that "all but one eliminated invariant were spurious, because they all falsely related variables of different abstract types". For RNAfold, "almost all eliminated invariants were spurious". The one wrongly eliminated invariant involved a control-flow-based relation, which a dataflow-based analysis cannot detect. — [DynComp, ISSTA 2006](https://pg.ucsd.edu/publications/dynamic-inference-of-abstract-types_ISSTA-2006.pdf)
- Daikon developer manual: "outputting nonsense values can degrade invariant detection; patterns in the valid data may be masked by noise from invalid values". — [Daikon Developer Manual](https://plse.cs.washington.edu/daikon/download/doc/developer.html)
- Without pointer disambiguation, Kvasir prints `result[]` with length always 1 instead of a scalar `*result`. The resulting invariants are phrased over arrays, and fields of pointed-to structs are lost unless pointers are marked "P". — [Daikon manual §7.3.5](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)
- ClearView's type knowledge directly gates invariant templates: variables inferred to be pointers skip lower-bound and less-than invariants. Restricting attention to predominating, always-defined variables, and removing duplicates, halved the invariant count. — [ClearView, SOSP 2009](https://people.csail.mit.edu/rinard/paper/sosp09.pdf)
- Kvasir limitations that degrade invariants: structs smaller than 8 bytes passed in registers make all their fields comparable (DynComp's AMD64 ABI limitation), and generic-pointer object orientation hides derived-class fields. — [Daikon manual §7.3.9](https://plse.cs.washington.edu/daikon/download/doc/daikon.html)

### Inferences
- A stripped-binary front end starts, at best, at the "representation types" row of DynComp's table: it knows only int, pointer and FP, and has no declared types. Running DynComp-style comparability over the binary is the documented way to recover most of the lost precision. DynComp is a binary-level dataflow analysis (DynCompB ran on x86 under Valgrind), so it does not inherently need DWARF; it needs only variable boundaries.
- Misclassifying a pointer as an integer produces meaningless numeric invariants over addresses (orderings, bounds, linear relations between unrelated heap addresses), and forgoes dereferenced invariants. Misclassifying an integer as a pointer risks unsafe dereferences, or "nonsensical" values once Memcheck A-bits are checked, which suppresses real invariants.
- Reading a float as a double, or reading stale xmm0, injects noise values. These kill true invariants such as `return >= 0` and do not just add false ones.

### Gaps
- I found no paper that measures invariant quality as a function of binary type-recovery error rate, e.g. Daikon over Howard-recovered types versus DWARF types.
