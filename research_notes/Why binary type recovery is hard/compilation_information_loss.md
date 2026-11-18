# Compilation Information Loss: What Binary Type Recovery Must Reconstruct (C, x86-64 System V, stripped ELF)

Source key (all primary unless noted; PDFs fetched and read in full text):
- **Survey**: Caballero & Lin, "Type Inference on Executables", ACM Computing Surveys 48(4), Art. 65, 2016 (DOI 10.1145/2896499); it compares 38 approaches — [PDF](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **TIE**: Lee, Avgerinos, Brumley, NDSS 2011 — [PDF](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- **Retypd**: Noonan, Loginov, Cok, "Polymorphic Type Inference for Machine Code", PLDI 2016 — [arXiv PDF](https://arxiv.org/pdf/1603.05495)
- **Howard**: Slowinska, Stancescu, Bos, NDSS 2011 — [PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **REWARDS**: Lin, Zhang, Xu, NDSS 2010 — [PDF](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- **OSPREY**: Zhang et al., IEEE S&P 2021 — [PDF (NSF PAR)](https://par.nsf.gov/servlets/purl/10296833)
- **TypeForge**: Wang et al., IEEE S&P 2025 — [PDF](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **DIRTY**: Chen et al., USENIX Security 2022 — [PDF](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- **ReSym**: Xie et al., ACM CCS 2024 — [PDF](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- **Lin & Gao**: "When Function Signature Recovery Meets Compiler Optimization", IEEE S&P 2021 — [PDF](https://dbgao.github.io/oakland21.pdf)
- **SysV ABI**: System V AMD64 psABI Draft 0.95 (2005) — [PDF](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf). This is an old draft. The argument-classification rules quoted here were not changed in later versions as far as I know, but I did not check them against psABI 1.0.
- **GCC manual** — [Optimize-Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html), [Code-Gen-Options](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html); **LLVM SROA** — [doxygen](https://llvm.org/doxygen/SROA_8cpp_source.html), [8.0.1 doxygen](https://cs6340.cc.gatech.edu/LLVM8Doxygen/SROA_8cpp.html)

---

## Q1. What does a C compiler erase, and which erased facts leave a fingerprint in machine code?

### Takeaway
Stripping removes all names (variables, fields, types, typedefs) completely, and they cannot be recovered from semantics. They can only be guessed, which is what ML systems such as DIRTY and ReSym do. Type *structure* survives only indirectly, through how values are used: access widths, which instructions consume a value, and which library calls a value reaches. Signedness, pointer-ness, struct/array boundaries and qualifiers leave weak or no traces unless a "type-revealing" operation happens to touch the value.

### Cited Findings
- **The core statement of loss**: "during compilation critical information such as variables and types is lost". In binary code, data lives "in untyped CPU registers and memory". Type inference must therefore first do *variable recovery* (start offset + size) and then assign primitive types. — [Survey](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- TIE: abstractions such as "buffers, structures, unions, pointers, and local variables" are "removed, and potentially completely obliterated" during compilation. High-level types "are typically thrown away by the compiler early on". It is easy to tell that a 32-bit value sits in a register but "difficult to infer high-level types such as signed integers, pointers, unions, and structures." — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- TIE on names: SSA renaming separates the writes to a register "it does not recover the original variable names as that information is lost during compilation." — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- Retypd: "source-level types are erased very early in the compilation process. As a result, further compiler passes may convert type-safe source into type-unsafe" code. — [Retypd](https://arxiv.org/pdf/1603.05495)
- DIRTY: decompilers "never fully reconstruct the original developer-written code, since the process of compilation irrevocably destroys some information", including "comments, identifier names, and types". Unlike names, "types are constrained by memory layouts" and so in theory are easier to recover. — [DIRTY](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- ReSym: symbol information "is completely discarded in stripped binaries". Variables, including structs and arrays, "are in the form of register and memory accesses after compilation." — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- **Signedness evidence is sparse.** Yan & McCamant (2014 tech report) argue that inferring signedness "is highly challenging due to the absence of casts in binary code and that few instructions truly manifest signedness". As a result, many tools infer generic `num32` rather than `int` or `unsigned`. — [Survey §5.1](https://software.imdea.org/~juanca/papers/types_csur16.pdf); [Yan & McCamant, UMN Conservancy](https://conservancy.umn.edu/items/8f4f4066-68bd-4bd5-9fcc-3fae77a53821)
- **Fingerprints exist, but only at certain operations.** TIE generates constraints from use: "if a variable is used in signed division it must be signed", and if a "signed flag is checked after an arithmetic operation" both operands are inferred signed. Its lattice keeps an uninformative `reg32_t` for values that are never used informatively. For example, "an unreferenced variable loaded into eax but never used will have type reg32_t". — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- TIE's motivating example shows Hex-Rays typing both `unsigned int` and `unsigned int *` as `int`. TIE notes "the Hex-rays default action seems to be to report an identified variable as a signed integer." — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- REWARDS' "type-revealing instructions" are x86 string instructions (MOVS/STOS/LODS/CMPS/SCAS, with MOVZBL used in string movement), floating-point instructions, and indirect memory operands, where "the value held in the source operand must be a pointer". A target address in the .text range implies a function pointer. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- **Instruction typing rules are themselves unreliable.** For example, MYCROFT treats xor operands as integers, "but encryption algorithms may XOR any data type". TIE treats a negation operand as signed, while Yan & McCamant consider negating unsigned values legal. Shift-operand rules also differ between tools. — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Pointer vs integer**: arithmetic instructions are shared. TIE models `add` with a disjunction: the operands are either two numbers or a pointer and a number. Later lattices (ARTISTE) let `add`/`sub` "operate on numbers, regardless of whether performing integer or pointer arithmetic". A zero constant "could be both integer or NULL pointer". — [Survey §5.1](https://software.imdea.org/~juanca/papers/types_csur16.pdf); [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- Howard: pointers and scalars look alike, and "the instructions to manipulate them are the same. We only know that a particular register holds a valid address when it is dereferenced." — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Value-based pointer guessing is heuristic. Bytes that look like an address of live memory "could also correspond to an integer variable, (part of) a string, or be unrelated." — [Survey §4.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **char/bool collapse**: the surveyed tools recover only integers, floats and pointers. "Other primitive types like char and bool are considered one-byte integers." — [Survey §5.1](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **typedefs (type synonyms)**: "Their representation is identical to the parent type, so they can only be distinguished from the parent type (and from other synonyms of the parent type) by how they are used". For example, `typedef int Dollars`. No surveyed work explicitly targets typedef recovery. — [Survey §5.6](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **enum**: at the ABI level `enum` sits in the same classification and size row as `int` (INTEGER class). — [SysV ABI 0.95, Fig. 3.1 / §3.2.3](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **const** is not represented in code, but it can be inferred from absence of writes. Retypd reports reconstructing "pointer const annotations with 98% recall". — [Retypd](https://arxiv.org/pdf/1603.05495)
- **Semantic types only through library anchors**: REWARDS derives 150 semantic types (for example pid, timestamps, IP addresses) from 84 library functions. Retypd adds `#FileDescriptor`-style tags. — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf); [Retypd](https://arxiv.org/pdf/1603.05495)

### Inferences
- Taken together, the sources suggest a three-way split of the erased facts:
  - **No fingerprint at all** (only priors or guessing can restore them): identifiers, typedef names, field names, comment-level semantics, `const`/`volatile`, and fields or variables never touched. `volatile` does constrain codegen by preventing optimization, but it does not mark a value's type.
  - **Weak fingerprint**, present only if a revealing operation occurs: signedness, pointer-ness, char vs int8, bool, enum vs int, and the pointee type.
  - **Strong fingerprint**: access width (the `byte`/`word`/`dword`/`qword` operand size), float vs integer (SSE scalar ops such as `addsd`/`cvtsi2sd` vs GPR ops), and code pointers (indirect `call`).
- The x86-64 instructions that reveal signedness are, from ISA knowledge rather than any one paper above: `movsx`/`movsxd` vs `movzx`; `sar` vs `shr`; `idiv`/`imul` (one-operand form) vs `div`/`mul`; conditional jumps and sets `jl`/`jg`/`setl` vs `jb`/`ja`/`setb`; `cvtsi2sd` (signed only — unsigned 64-bit-to-float needs a multi-instruction idiom); and the `cdq`/`cqo` sign-extension before `idiv`. Add, sub, low-half imul, and/or/xor, comparisons for equality, loads/stores, and truncation are identical for signed and unsigned. This matches Yan & McCamant's point that "few instructions truly manifest signedness".
- On x86-64, writing a 32-bit register zero-extends into the 64-bit register. So `mov eax, ...` followed by 64-bit use looks like a `uint32→uint64` conversion even when the source had an `int` that was known non-negative. Compilers also pick `movzx` or `movsx` for byte loads based on convenience whenever the upper bits are dead. Extension instructions are therefore *noisy* signedness evidence.
- `char*` vs `void*` vs `uint8_t*`: these are indistinguishable except through use, such as string instructions, `strlen`/`strcpy` call sinks, or comparison with ASCII constants. `void*` in particular has no fingerprint; it is a source-level absence of commitment.

### Gaps
- I did not fetch the Yan & McCamant tech report body. The quoted claim comes via the survey and the UMN abstract.
- No found paper gives a quantitative breakdown of how often each signedness-revealing instruction appears in real -O2 code.

---

## Q2. Ambiguities that cannot be resolved even in principle

### Takeaway
Many distinct source typings compile to bit-identical code. When no revealing operation exists, the "true" type is information-theoretically absent, and any answer is a prior. TIE frames this as being "conservative". Canonical cases include struct vs array with uniform fields, a pointer to a struct vs a pointer to its first member, union members, nested structs never accessed separately, typedefs, unaccessed fields, padding, and signed vs unsigned used only in add, sub or equality.

### Cited Findings
- **struct vs array**: regularly-spaced offsets such as {0,4,8,12} "may indicate an array". To tell "a record with 4 integer variables from an array of 4 integers", tools rely on the heuristic that arrays "are more commonly processed in loops". — [Survey §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- TypeForge: "different composite data types often exhibit the same memory access patterns in stripped binaries. For example, access pattern dereference(base + offset) could originate from either structure member accesses or array element accesses". Its answer is to synthesize several candidate declarations and pick a "best-fit" one (reported F1 81.7% identification, 88.2% layout). — [TypeForge](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- **Pointer-to-struct vs pointer-to-first-member**: "there is no syntactic distinction in machine code between a pointer-to-struct and a pointer-to-first-member-of-struct". For example, X+4 passed to `fclose` implies a `FILE*` at offset 4. Retypd calls this physical or non-structural subtyping. — [Retypd §2.4](https://arxiv.org/pdf/1603.05495)
- **Unions**: "A fundamental challenge with untagged unions is how to distinguish them from a typing conflict". No surveyed tool gets full union support. Tools also *create* spurious unions to resolve constraint violations. — [Survey §5.7](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- Howard: unions "might exhibit more than one memory access pattern", so it reports a merge or intersection of the members. It "cannot recognize nested structs if the inner struct is never accessed separately". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Howard: "If a structure consists of one field followed by an array, and the field and array are accessed in sequence, it is impossible to classify it correctly solely based on memory access patterns". Howard also will not call something an array unless at least four elements are accessed in a loop. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Unaccessed fields**: memory-access-based recovery "can only recover fields that the program accesses (or accessed in an execution for dynamic approaches)". Record and array *size* is unknown in C when there is no size field, and is estimated by max offset, the next variable, or the heap allocation size. — [Survey §4.5, §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Missing base pointer**: "A missing base pointer is of course a fundamental limitation, as we cannot recognize what is not there." Fields initialized via the frame pointer look like separate locals. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- TIE: "directly accessing structure fields is indistinguishable from accessing local variables on the stack". Only pointer-based access hints at a struct. — [TIE §6](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- **Padding**: the survey lists "padding fields introduced by the compiler for alignment" as an open challenge (its Fig. 2 shows a fake padding variable). DIRTY calls padding "a fundamental limitation of decompilers": "The decompiler cannot recognize that the inserted padding data does not belong to the x array." — [Survey §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf); [DIRTY](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- DIRTY Fig. 1: a `struct point {float x; float y;}` is decompiled by Hex-Rays as two float *arrays*. — [DIRTY](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- **Ad-hoc typedef hierarchies** (Windows HANDLE/HGDI/HBRUSH typedefs of `void*`; LPARAM/DWORD as "generic 32-bit" types) need subtyping rather than unification, and the hierarchy itself must be supplied externally. — [Retypd §2.8](https://arxiv.org/pdf/1603.05495)
- **Type-unsafe source idioms** that make constraints contradictory even when recovery is perfect: hashing values as bit blocks, pointer tag bits, XOR doubly-linked lists, and the Quake3 inverse-sqrt bit trick. — [Retypd §2.6](https://arxiv.org/pdf/1603.05495)
- **TIE's principled position**: produce an upper and lower bound and be "conservative", meaning "we do not infer types that cannot be supported by the code". — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)

### Inferences
- A clean statement of the in-principle limit: **two typings are indistinguishable when the program compiles to the same machine code under both**. Examples:
  - `int` vs `unsigned` when only add, sub, low-mul, bitwise, store or `==` is used.
  - `struct {int a; int b;}` vs `int[2]`.
  - `struct S *p` vs `int *p` when only `p->first` is used.
  - `typedef int T` vs `int`.
  - `long` vs `void*` when the value is only copied.
  - a union vs whichever member is used.
- Any recovery method must then fall back on priors: corpus statistics (ML), heuristics such as "loops imply arrays", or explicit lattice tops (TIE's `reg32_t`, `num32_t`).
- For evaluation design, this implies that ground-truth comparison should either (a) score "equivalence classes under codegen" as correct, or (b) report results on a conservative and a precise metric separately, as TIE does. Exact-match accuracy over-penalizes cases that cannot be decided in principle.

### Gaps
- I found no paper that formally defines "observational equivalence of typings w.r.t. a binary" and counts how many real variables fall into undecidable classes. That would be a useful measurement.

---

## Q3. Calling-convention effects (System V AMD64)

### Takeaway
The ABI's classification algorithm maps source parameters to two separate register files (GPR and XMM), each with its own counter. Small structs are split into eightbytes that can be packed into, or spread across, registers. The source order of interleaved int and float parameters, struct boundaries in by-value arguments, and the presence of unused parameters cannot be recovered from the callee alone. Optimizations make all of this worse by eliminating unused-argument reads and changing argument widths.

### Cited Findings
- **Classification**: each argument is rounded to eightbytes. `_Bool`, `char`, `short`, `int`, `long`, `long long` and pointers (signed and unsigned alike) are class INTEGER; `float`/`double` are SSE. Aggregates larger than two eightbytes (or with unaligned fields) are MEMORY. Otherwise each eightbyte is classified by merging its fields' classes, and "If one of the classes is INTEGER, the result is the INTEGER". — [SysV ABI 0.95 §3.2.3](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **Separate register sequences**: INTEGER → "next available register of the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9"; SSE → %xmm0–%xmm7. If no register is left for any eightbyte, the whole argument goes on the stack (pushed right-to-left). — [SysV ABI 0.95](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **ABI's own example** (Fig. 3.5/3.6): `func(int e, int f, structparm s, int g, int h, long double ld, double m, double n, int i, int j, int k)` with `structparm {int a, b; double d;}` puts e→%rdi, f→%rsi, **s.a and s.b packed together in %rdx**, s.d→%xmm0, g→%rcx, h→%r8, i→%r9, m→%xmm1, n→%xmm2; ld, j and k go to memory. One struct is split across a GPR and an XMM register, two `int` fields share one 64-bit register, and int and float parameters are interleaved. — [SysV ABI 0.95](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **Return values**: MEMORY-class returns use a caller-allocated buffer whose address is passed in %rdi "as if it were the first argument". This is a "hidden" first argument, and %rax returns that address. INTEGER returns use %rax then %rdx; SSE returns use %xmm0 then %xmm1. — [SysV ABI 0.95](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **Varargs**: for calls to variadic or prototype-less functions, %al is a hidden argument giving "an upper bound on the number of SSE registers used" (0–8). — [SysV ABI 0.95](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf)
- **Optimization vs signatures (Lin & Gao, S&P 2021)**: "various compiler optimizations may violate calling conventions and result in unmatched function signatures". Optimization makes arity and type inference at callees "less accurate, because of the elimination of unused arguments and promotion/demotion of argument types". — [Lin & Gao](https://dbgao.github.io/oakland21.pdf)
- Lin & Gao's named complications include:
  - **Unread**: at -O2 an unused argument is never read, so arity is underestimated.
  - **Var2Nor**: gcc -O2 does not read unused variadic arguments, so a variadic function looks normal. Clang "always explicitly reads all variadic arguments".
  - **Nor2Var**: at -O0, any normal function with more than five arguments spills them all to the stack and looks variadic.
  - **rdx**: reading %rdx for the upper half of a two-register return value (e.g. from `lldiv`) is mistaken for a third argument.
  - **Push/lea width promotion**: `push` accepts only 64-bit operands, and `lea` prefers 64-bit registers, so 32-bit `unsigned int` arguments look 64-bit.
  - At callers, registers may be left unset, or reused because they already happen to hold the right value.

  — [Lin & Gao](https://dbgao.github.io/oakland21.pdf)
- Retypd (on 32-bit): optimized binaries contain many functions using non-standard register parameter passing. False-positive register parameters (e.g. the `push ecx` idiom that reserves a stack slot) cause over-unification in unification-based type systems. — [Retypd §2.5](https://arxiv.org/pdf/1603.05495)
- **Compilers rewrite signatures**: GCC's `-fipa-sra` performs "interprocedural scalar replacement of aggregates, removal of unused parameters" (enabled at -O2/-O3/-Os). The LWN article reports that optimizers can drop an argument entirely, pass only the used fields of a struct argument, or pass a pointed-to struct by value. Clang marks such functions `DW_CC_nocall` in DWARF. GCC usually renames them, but "some transformed functions do not receive a changed name". In one kernel build, 875 of 69,103 functions had changed signatures. — [GCC Optimize-Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html); [LWN](https://lwn.net/Articles/1073762/)
- The survey notes that mapping parameters to registers or stack requires knowing the convention, assuming one (e.g. cdecl in REWARDS), or inferring prototypes. — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- **Interleaving is not recoverable.** `f(int a, double b, int c)` and `f(int a, int c, double b)` produce identical callee code: a→%rdi, c→%rsi, b→%xmm0. Only the relative order *within* each class is preserved. A decompiler must choose a canonical order (all ints first, or similar), so exact prototype matching is impossible in principle for mixed-class signatures, unless call sites in other binaries (or headers) with source-level information exist.
- **Struct-by-value is not recoverable without priors.** A struct of {int,int} passed in one GPR is indistinguishable from a single `long`. Likewise {long,long} in rdi+rsi looks like two `long` params, and {double,double} in xmm0+xmm1 looks like two doubles. A >16-byte struct by value is indistinguishable from a pointer argument plus a callee-side copy pattern. A MEMORY-class return looks like an extra leading pointer parameter whose value is returned in %rax.
- **Unused trailing parameters are invisible** at the callee. Only caller-side register setup (which may also be eliminated) can reveal them. Decompilers therefore systematically drop them, and evaluation should follow a convention for this, as Lin & Gao and later work note.
- The upper 32 bits of a 64-bit register holding a 32-bit argument are not specified by the ABI text I read. Compilers rely on this, so the callee may legally use only `edi`, and the observed operand width is a lower bound on the declared width, not the width itself. (I did not find this stated in the 0.95 draft text I grepped; treat it as a known convention needing a citation.)

### Gaps
- I did not fetch psABI v1.0 to confirm the `_Bool`/upper-bits wording, nor `__int128`/`_Float16` details.
- I did not find a paper quantifying how often int and float parameters are interleaved in real C code. That number is needed to bound how much exact-prototype accuracy this loss costs.

---

## Q4. Compiler optimization effects (-O0 vs -O2/-O3)

### Takeaway
Optimizations run *after* type erasure and freely produce well-defined but "ill-typed" machine code. Examples: one register or stack slot holds values of different types; a struct is split into independent scalars (SROA) or never materialized in memory; functions are inlined, cloned or tail-called; constants are shared across types; narrow stores are merged into wide or SIMD moves that cross field boundaries; loops are unrolled or vectorized so stride patterns change. Every heuristic that depends on access patterns degrades.

### Cited Findings
- Retypd §2.1 "Optimizations after Type Erasure": "many compiler optimizations may take well-typed machine code and produce functionally equivalent but ill-typed results". It names three:
  - (1) **semi-syntactic constants**: `f(0, NULL)` compiled as `xor eax,eax; push eax; push eax`. One register is used for an int and a pointer, and their type variables must not be unified.
  - (2) **early-return value reuse**: `get_T` returns `get_S`'s NULL in eax, which falsely relates two incompatible return types.
  - (3) **stack-slot reuse**: the optimizer reuses a slot "even if the new variable has a different type… even applies to the stack slots used to store formal-in parameters".

  Retypd concludes: "we cannot assume that the map from program variables to physical locations is one-to-one… [nor] that the program variables inhabiting a single physical location at different times will all belong to a single type." — [Retypd](https://arxiv.org/pdf/1603.05495)
- TIE: "stack slots may be reused for different variables of different types". It uses memory SSA so that "a single stack slot may be used for many different variable instances, e.g., when designated as a generic register spill". — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- **GCC stack reuse**: `-fstack-reuse` "controls stack space reuse for user declared local/auto variables and compiler generated temporaries". The default is 'all'. — [GCC Code-Gen-Options](https://gcc.gnu.org/onlinedocs/gcc/Code-Gen-Options.html)
- **SROA**: LLVM's pass "provides both aggregate splitting and the primary SSA formation used in the compiler". It "takes allocations which can be completely analyzed (that is, they don't escape) and tries to turn them into scalar SSA values". It can also promote vector aggregates to SSA vector values. GCC's `-ftree-sra` is "enabled by default at -O1 and higher", and `-fipa-sra` at -O2+. — [LLVM SROA](https://llvm.org/doxygen/SROA_8cpp_source.html); [LLVM 8 SROA](https://cs6340.cc.gatech.edu/LLVM8Doxygen/SROA_8cpp.html); [GCC](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- **GCC flags (from the manual) that destroy type evidence, with default levels**:

  | Flag | What it does | Default level |
  |---|---|---|
  | `-finline-functions`, `-finline-small-functions` | inlining | -O2 |
  | `-foptimize-sibling-calls` | tail calls | -O2 |
  | `-fipa-cp` | interprocedural constant propagation | -O2 |
  | `-fipa-cp-clone` | specialized clones | -O3 |
  | `-fomit-frame-pointer` | no frame pointer | -O1 |
  | `-ftree-loop-vectorize`, `-ftree-slp-vectorize` | vectorization | -O2 (in current GCC) |
  | `-fipa-icf` | identical code folding of functions and read-only variables | -O2 |
  | `-fstore-merging` | "merging of narrow stores to consecutive memory addresses" | -O2 |
  | `-fstrict-aliasing` | strict aliasing assumptions | -O2 |

  — [GCC Optimize-Options](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)
- Howard: data structure recovery "becomes even more complicated in the face of common compiler optimizations (like loop unrolling, inlining, and elimination of dead code and unused variables) which radically transform the binary". Specific effects:
  - Loop unrolling makes `arr1[i]=i` look like "an array of 4-field structures".
  - Data-layout optimizations ("structure splitting and field reordering") mean recovered layouts reflect optimized code (WYSINWYX).
  - Inlining means the inlinee's "function frame extends the caller's one".
  - Arguments are passed in registers.

  — [Howard §7.1](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Wide moves across fields**: in OSPREY's gzip `huft_build` example, IDA treats a `movdqa`/`movups` pair as a 128-bit float move. "Unfortunately, modern compilers aggressively utilize these instruction patterns to optimize code generation… the two instructions are not related to floating-point value copy but rather general data movement". As a result IDA "misidentifies elem_t as a union" of a 2×64-bit array and a 128-bit field. TIE's algorithm would also produce a union for the same reason. — [OSPREY](https://par.nsf.gov/servlets/purl/10296833)
- OSPREY: rule-based tools fail because "modern compilers are diverse and feature aggressive optimizations, which may violate many instruction patterns that these rules rely on". Ghidra developers "do not consider stack offsets as reliable base addresses (potentially due to that compiler optimizations may lead to arbitrary stack addressing)", and so do not group stack offsets into structs. — [OSPREY](https://par.nsf.gov/servlets/purl/10296833)
- **memcpy/memset**: static VSA/ASI misclassifies a memcpy'd struct "as having many fields of 4 bytes, simply because memcpy accesses the memory with a stride of 4". memset and memcpy access "all fields with a stride of 4 bytes", unlike the real per-field accesses. One memcpy iteration may move "the last two bytes of one variable and two char variables stored next to it". The fixes are: prefer non-word strides, ignore propagation inside copy functions, or drop size constraints on moves. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf); [Survey §4.4, §4.5](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- A value may be moved without regard to its size: 32-bit ints byte-by-byte, or a 64-bit `long long` as two 32-bit moves on IA-32. Memory-access recovery "can only identify variables of at most the word size". — [Survey §4.4–4.5](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- ReSym notes that overlapping field accesses "might result from compiler optimizations", and it requires at least three instances before treating them as evidence of a type-agnostic argument. Ground-truth field lookup sometimes fails, which "suggests possible aggressive compiler optimization". — [ReSym](https://www.cs.purdue.edu/homes/lintan/publications/resym-ccs24.pdf)
- **ML on decompiler output looks insulated, but this is partly an artifact.** DIRTY trains on -O0. On coreutils, full-type accuracy is 48.2% at -O0 and about 46.0% at -O1, -O2 and -O3. The authors attribute the small drop to Hex-Rays "undoing" some optimizations; for example, rsp-relative vs rbp-relative addressing looks the same in decompiled C. — [DIRTY §3.5](https://www.usenix.org/system/files/sec22-chen-qibin.pdf)
- C++ note: open class-recovery problems include "inlined constructors and destructors" and "elimination of virtual table references in constructors through optimization". — [Survey §5.2](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- **SROA is the most damaging optimization for struct recovery.** If a local struct does not escape, no memory object exists at all, and its fields become unrelated SSA values in registers. That evidence is unrecoverable from the binary: what remains is a set of scalars. ReSym's reported strength at regrouping "inlined structures or arrays that the decompiler has fragmented into multiple variables" (F1 85.9%) relies on learned priors, not on evidence in the binary.
- **Inlining has two opposite effects.** It erases function boundaries, so prototypes and the parameter as a type anchor vanish, and type constraints from two functions mix in one frame. It can also *add* evidence by copying library-call sinks into the caller.
- **Constant propagation and `xor reg,reg` zeroing** create spurious int and pointer unification. ICF (`-fipa-icf`) can merge functions with identical code but different source types, for example `int` vs `unsigned` comparators, making one binary function legitimately polymorphic.
- **Vectorization** introduces SSE/AVX instructions on integer data (e.g. `movdqu`, `pxor`, `paddd`). This breaks the "SSE ⇒ float" heuristic and hides strides.
- **Experimental implication**: results at -O0 overstate real-world accuracy for any access-pattern or instruction-pattern method. Evaluations should report -O0/-O2/-O3 separately, as DIRTY and OSPREY's appendices do.

### Gaps
- I did not find an empirical study isolating the effect of each optimization (SROA vs inlining vs vectorization) on type-recovery accuracy. Most papers report only aggregate -O levels.
- I did not verify LLVM's exact SROA behaviour from the official pass docs page; the doxygen header comments were the only source.

---

## Q5. Pointer arithmetic, aliasing, and points-to analysis on binaries

### Takeaway
Machine code exposes only addresses computed by integer arithmetic. Interior pointers, multiple base pointers to the same object, base+index×scale addressing, and arrays of structs make it ambiguous which object, and which offset in which type, an access belongs to. Static points-to analysis on binaries (VSA) is sound but imprecise and does not scale. Systems therefore either avoid points-to analysis (Retypd), use best-effort analysis (SecondWrite), or go dynamic (Howard, REWARDS), at the cost of coverage.

### Cited Findings
- Static flow-based approaches "need a points-to (or alias)" analysis to propagate types through memory. DIVINE and FFE use VSA, "a sound flow-sensitive, context-sensitive, inter-procedural, abstract-interpretation algorithm that over-approximates the set of numeric values and addresses". TIE uses the DVSA variant. SecondWrite uses "best-effort pointer analysis, which sacrifices soundness". — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- DIVINE (VMCAI 2007) alternates VSA and ASI. It found about 88% of locals and 89% of heap fields, versus 83% and 0% for earlier techniques. — [DIVINE abstract](https://research.cs.wisc.edu/wpis/abstracts/vmcai07.invited.abs.html)
- OSPREY: "VSA is conservative and hence leads to a large amount of bogus data-flow… existing public VSA implementations do not scale to large programs", including gzip. TIE "cannot rule out the bogus results" and keeps all of them. — [OSPREY](https://par.nsf.gov/servlets/purl/10296833)
- Retypd: "Degradation of points-to accuracy on large programs has been identified as a source of type-precision loss". Retypd needs "no points-to analysis beyond the simpler problem of tracking the stack pointer". — [Retypd §2.7](https://arxiv.org/pdf/1603.05495)
- **Multiple base pointers**: fields of a stack struct may be accessed "through the base pointer of the stack frame, or through the base pointer of the record". In the first case "the record that stores them becomes indistinguishable". Nested records have the same problem. — [Survey §4.5](https://software.imdea.org/~juanca/papers/types_csur16.pdf); [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Arrays of structs**: in Howard's array detection, a pointer B into an array "may well point to a field in a struct, rather than an array element" when the array consists of structs. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Interior/offset pointers**: X+4 passed to `fclose` requires inferring a `FILE*` field at offset 4 of X's pointee. Derived-to-base casts are the same phenomenon. — [Retypd §2.4](https://arxiv.org/pdf/1603.05495)
- Open challenges listed by the survey: multi-dimensional arrays, arrays accessed with SIMD, and records and arrays on the stack whose elements are accessed relative to the frame base. — [Survey §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Unification vs subtyping**: unification is non-local, so "bad constraints in one part of the binary can degrade all type results". Retypd uses subtyping to avoid over-unification. — [Retypd §2.5](https://arxiv.org/pdf/1603.05495)
- Static disassembly of stripped binaries "is equivalent to the halting problem", so the IR underneath type inference is never guaranteed correct. — [Retypd §2.5](https://arxiv.org/pdf/1603.05495)
- **Dynamic analysis trade-off**: Howard and REWARDS see concrete addresses, so they need no alias analysis. They recover only what executes, and REWARDS-style online tainting "cannot handle control flow" according to TIE. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf); [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)

### Inferences
- An access `[rax + rcx*8 + 0x10]` is consistent with several layouts: an array of 8-byte elements starting at offset 16 of a struct; field 0x10 of the rcx-th element of an array of 8-byte structs; or `ptr + 2` element arithmetic on a `long*`. Telling them apart needs either the allocation site with its size or other accesses through the same base.
- Pointer provenance, meaning which allocation a pointer came from, is a source-level semantic concept. It is lost once pointers are integers in registers. The `-fstrict-aliasing` assumptions the compiler made are not recorded, so the binary-level analyst cannot use type-based alias analysis.

### Gaps
- I did not fetch the SecondWrite paper (ElWazeer et al., PLDI 2013) for its own claims about best-effort pointer analysis; I used only the survey's characterization.

---

## Q6. Stack, heap, and global memory regions

### Takeaway
Each memory region loses its object boundaries differently. Stack frames are reused over time and mix address-taken locals, spills and arguments. Heap objects carry no type, and their size is known only from the allocation argument, which wrappers and custom allocators hide. Globals are a flat section in which adjacent variables are indistinguishable from one array or struct, and they are accessed by absolute (RIP-relative) addresses with no base pointer.

### Cited Findings
- "Memory locations in the stack and the heap can be reused to store different stack frames and memory allocations over time", so analyses split them into per-function frame regions and per-allocation-callsite heap regions. — [Survey §2.2](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Heap allocation wrappers**: a `safe_malloc` wrapper's internal call site "cannot be uniquely assigned to one type, as different safe_malloc callers will request allocations of different types". Dynamic tools use the last 3–4 call-stack entries. — [Survey §2.2](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- Retypd: `malloc` is effectively `∀τ. size_t → τ*`, `free` is `∀τ. τ* → void`, and `memcpy` is `∀α,β. (β ⊑ α) ⇒ (α* × β* × size_t) → α*`. User-defined allocators and wrappers must be identified and treated polymorphically per call site. — [Retypd §2.2](https://arxiv.org/pdf/1603.05495)
- Howard "gets confused by certain custom memory allocators". A generic application allocator (e.g. Apache's) "exhibits mixed access patterns inherited from various different structures/arrays". — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **Globals**: identifying records and arrays in globals is "challenging… because a program can directly access their elements with a fixed virtual address, instead of using a base pointer and an offset". Global base pointers can be partially recovered from relocation tables and header fields. — [Survey §4.5, §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- **Size estimation** without explicit sizes in C uses the largest offset plus access size, the start of the next inferred variable, or the heap allocation size. "An incorrect estimate may miss the last elements… or may include unrelated data stored next to them". — [Survey §5.3](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- Howard merges detected arrays with trailing unused bytes, and it misclassifies arrays whose last element is accessed separately (e.g. a NUL terminator) as a struct of an array plus a field. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- Static techniques "cannot deal with functions like 'alloca'". — [Howard §2](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- **x86-64 stack specifics**: the 128-byte area below %rsp is the red zone, which leaf functions may use without adjusting rsp. `-fomit-frame-pointer` (-O1+) removes rbp as a frame anchor. — [SysV ABI 0.95 §3.2.2](https://math-atlas.sourceforge.net/devel/assembly/abi_sysV_amd64.pdf); [GCC](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html)

### Inferences
- **Adjacent globals**: `int a; int b; int c;` placed consecutively in .data/.bss produce the same layout as `int arr[3]` or `struct {int a,b,c;}`. The linker's placement order is arbitrary, so neither adjacency nor the absence of a gap is evidence of aggregation. Only a loop or index arithmetic spanning them suggests an array.
- **Address-taken locals** are the only locals that must live in memory at -O2. All others may exist only in registers, or nowhere after SROA and constant propagation. Stack-based variable recovery at -O2 therefore sees a biased sample: arrays, structs whose address escapes, and spills.

### Gaps
- I found no primary source specifically measuring global-variable aggregation errors in decompilers.

---

## Q7. Library code and dynamic linking as type anchors; static linking

### Takeaway
Known prototypes of external functions (libc, syscalls) are the main *sources* of ground-truth-like type evidence in stripped binaries. This is why dynamically linked binaries, whose imports are named through PLT/GOT and `.dynsym`, are much easier than statically linked ones, where library code becomes anonymous functions unless identified by signatures. The anchors are themselves imperfect: libc's `void*`-based APIs are polymorphic, and wrappers hide them.

### Cited Findings
- External calls are one of two "major sources of type inference constraints". For example, `size_t strlen(const char*)` types the argument location as a string pointer and the return value as an unsigned integer. 10 of 38 approaches use function sources to derive semantic types. — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- REWARDS' type sinks are "(1) system calls, (2) standard library calls, and (3) type-revealing instructions". Library calls give "richer type information than system calls – for example, Linux-2.6.15 has 289 system calls whereas libc.so.6 contains 2016 functions". Example: both `strcpy` arguments are `char*`. — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf)
- ASI likewise uses "the type information from system calls and well-known library functions", tagging arguments at each call and propagating. — [Howard §2 (related work)](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- TIE's running example infers `const char*` for a parameter "from strlen's" prototype. — [TIE](https://users.ece.cmu.edu/~aavgerin/papers/tie-ndss-2011.pdf)
- **Anchors are polymorphic**: the `void*` from malloc "is not meant to be an opaque handle". Polymorphic signatures for malloc, free and memcpy "are all strictly more informative to the reverse engineer than the standard C signatures". — [Retypd §2.2](https://arxiv.org/pdf/1603.05495)
- Semantic types from library sources "are not included in the type lattice, so it is unclear how to relate them to other types". — [Survey §4.4](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- C++ RTTI is a rare *compiler-emitted* type anchor (class name, hierarchy, partial layout). It exists only for polymorphic classes and is "often absent in commercial software". — [Survey §5.2](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- In a dynamically linked ELF, import names survive stripping, because `strip` removes `.symtab` but `.dynsym` is needed at runtime. Every call through the PLT to libc is therefore a typed anchor. In a statically linked binary, these become unnamed internal functions. They need library-function identification (FLIRT-style signatures) before their prototypes can be applied, and inlined or LTO'd library code (e.g. `memcpy` expanded to `rep movsb` or SIMD moves, `strlen` expanded inline) removes the anchor entirely.
- Anchors propagate only along data flow. Program-internal types that never reach a libc call, such as most fields of application structs, receive only primitive-level evidence.

### Gaps
- I did not find a primary-source measurement of how much type-recovery accuracy drops from dynamic to static linking. This would be a valuable experiment.

---

## Q8. Taxonomies and surveys of these problems

### Takeaway
The main systematization is Caballero & Lin (ACM CSUR 2016). It decomposes the problem into variable recovery plus typing of primitives, records/arrays, classes, strings, recursive types, type synonyms, unions, abstract types and function prototypes. It also catalogues the challenges listed above. Retypd's §2 is the most explicit "catalogue of challenging cases" from a static-analysis perspective. Recent papers' motivation and limitation sections (OSPREY, TypeForge, DIRTY, ReSym) add optimization-specific and ambiguity-specific failure modes.

### Cited Findings
- The survey "systematically compared 38 binary code type inference works", with x86 dominant (36/38 evaluated) and x86-64 used in only 7. It frames disassembly, variable recovery, data-structure identification, shape analysis, object recovery, prototype inference and protocol reverse engineering all as sub-problems of type inference. — [Survey §2](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- It notes that the ABI (type representations, alignment, calling convention, class layout), the compiler, the OS and the architecture all affect the problem. — [Survey §2.1](https://software.imdea.org/~juanca/papers/types_csur16.pdf)
- Retypd §2 lists:
  - optimizations after type erasure (semi-syntactic constants, fortuitous value reuse, stack slot reuse)
  - polymorphic functions
  - recursive types
  - offset and reinterpreted pointers
  - disassembly failures and register-parameter false positives
  - cross-casting and bit twiddling
  - incomplete points-to information
  - ad-hoc subtyping

  The authors describe this as building "a catalog of challenging cases for type reconstruction". — [Retypd](https://arxiv.org/pdf/1603.05495)
- Howard §7 is a taxonomy of the optimizations affecting data-structure detection: data layout, loop transformations, and function-frame effects (inlining, register arguments). — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf)
- TypeForge lists two limitations of prior work: L1, inaccurate or unscalable recovery of full composite declarations, including pointer and nesting relations; L2, ambiguity from identical memory access patterns. — [TypeForge](https://noobone123.github.io/papers/typeforge-sp25.pdf)
- Lin & Gao give a taxonomy of calling-convention violations due to optimization: callee-side Nor2Var, Var2Nor, Unread, rdx, Push, lea, and caller-side missing writes. — [Lin & Gao](https://dbgao.github.io/oakland21.pdf)

### Inferences
- Synthesizing across sources, a workable catalogue of fundamental losses is:
  1. **names** (unrecoverable in principle)
  2. **variable boundaries** (register/slot ≠ variable)
  3. **aggregate boundaries and kind** (struct vs array vs union vs scalars; nesting; size; padding; unaccessed fields)
  4. **primitive refinements** (signedness, char/bool/enum, pointer vs integer, pointee type, const, typedef)
  5. **interfaces** (arity, parameter order across register classes, by-value aggregates, hidden return pointers, varargs, optimized signatures)
  6. **memory-object identity** (stack slot reuse, heap allocation types, global adjacency, interior pointers, aliasing)
  7. **optimization-induced type-unsafety** (shared constants, SROA, inlining, ICF, store merging, vectorization, memcpy idioms)
  8. **anchor availability** (dynamic vs static linking, wrappers)
- Categories 1, parts of 3–5 and typedefs are *information-theoretically* lost. The remaining categories are *analysis-hard*: the evidence exists but requires precise points-to analysis, context sensitivity or coverage.

### Gaps
- No survey newer than 2016 covering the ML era (DIRTY, ReSym, TYGR, TypeForge) was found in this session. The survey's x86-32 focus means some claims (e.g. 4-byte strides, cdecl) need translating to x86-64 (8-byte strides, register arguments).
