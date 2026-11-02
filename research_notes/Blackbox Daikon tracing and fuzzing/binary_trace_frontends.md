# Binary-level / black-box front-ends for Daikon-style invariant detection, and trace-fidelity techniques

Scope: x86-64 Linux ELF, stripped, gcc -O0, non-PIE; the reference oracle is Kvasir. Research notes, 2026-11-02.

**Network caveat.** This session could reach only GitHub (raw.githubusercontent.com and git clone) and web-search snippets. Fetches of plse.cs.washington.edu, pg.ucsd.edu, doi.org, arxiv.org, futures.cs.utah.edu and rcs.uwaterloo.ca all failed with DNS errors. As a result:
- Claims about the Daikon manual and about Fjalar/Kvasir were checked against **primary sources**: the Daikon manual texinfo on GitHub, and the Fjalar C source cloned from `codespecs/fjalar` (lines quoted below).
- Claims about papers come from **search-result abstracts and snippets** and are marked as such. I could not read the full PDFs for Binvariants, ClearView, the Guo thesis, InvsCov, TypeArmor or the S&P'21 paper.
- Anything marked **[unverified]** is my own background knowledge with no source fetched in this session.

---

## Q1. Which binary or black-box front-ends for Daikon (or likely-invariant inference) exist, and what do they recover?

### Takeaway
No published tool produces Kvasir-equivalent Daikon traces from *stripped* binaries.
- **Kvasir/Fjalar is binary-level only for instrumentation.** It needs DWARF for every name, type, struct layout and static array bound. It takes the dynamic facts (pointer validity, initializedness, heap array extent) from Valgrind Memcheck's A/V shadow bits.
- **The truly debug-info-free systems are of a different kind:**
  - ClearView (SOSP'09): Daikon over x86 instruction-level variables in stripped Windows binaries.
  - Astarte: x86 instructions as program points.
  - Binvariants (FSE'26): register-level likely invariants via QEMU and AFL++.
  
  All of them trade source-level variables for machine-level ones (registers and memory operands at instructions or blocks), so none is directly scorable against Kvasir.
- **Our tool's niche is open:** recovering *function-level*, source-like variables (params, return, pointees, globals) without DWARF. The closest published methods for that are binary type and data-structure recovery (REWARDS, Howard, TIE), not invariant tools.

### Cited Findings
**Kvasir / Fjalar (the oracle)**
- Kvasir is Daikon's C/C++ front end, built on the Fjalar framework, which is built on Valgrind. It reads names and types from DWARF-2/3/4, and requires `-gdwarf-N`, no optimization and `-no-pie`. It works only on amd64-linux. — [Daikon manual, Kvasir section (texinfo)](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)
- Fjalar is a "mixed-level" approach: binary rewriting via Valgrind, plus memory-safety via Memcheck, plus source-level names from compiler debug info. Debug info "map[s] between data it collects at the memory level and language-level terms such as variable and function names". — [Guo, CSAIL abstract](https://publications.csail.mit.edu/abstracts/abstracts06/pgbovine/pgbovine.html); [Rudd MEng thesis abstract](https://plse.cs.washington.edu/daikon/pubs/rudd-mixedlevel-mengthesis-abstract.html) (search snippets)
- Fjalar 5.8.21 was released 2024-05-14 and is hosted at github.com/codespecs/fjalar. — search snippet, [Ernst software page](https://homes.cs.washington.edu/~mernst/software)

**How Fjalar recovers dynamic facts** (read directly from source, [fjalar_runtime.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/fjalar_runtime.c))
- **Pointer validity** uses Memcheck A-bits (`mc_check_writable`), and **initializedness** uses V-bits (`mc_check_readable`), via `addressIsAllocated` and `addressIsInitialized`.
- **Stack exception:** everything between the current function's FP and its lowest observed SP, minus the red zone, is treated as allocated *and initialized* automatically. The source comment: "we are ASSUMING that it is!!!". Kvasir therefore does not detect uninitialized stack locals in the current frame.
- **Heap array size** (`probeAheadDiscoverHeapArraySize`):
  - First it probes *forward* element by element while A-bits say "allocated", which bounds the array by the malloc block.
  - Then it makes a second pass *backwards* until it reaches an element that has at least one byte with V-bits set.
  - It returns `size-1` as the upper bound.
  - It is only used when the address is below the current frame's lowest SP and is not global, "since all areas on the stack and global regions are ALLOCATED so probing won't do us much good".
- **Pointers into globals or stack** (`returnArrayUpperBoundFromPtr`):
  - It searches the DWARF global array variables, then the DWARF local array/struct variables of frames on the stack, for one that contains the address. The bound is computed from that variable's static extent.
  - For global arrays only, it also trims the bound backwards to the last V-bit-initialized element. The comment explains why: "V-bits for stack variables are FLAKY!!! During function exit, all the V-bits are wiped out".
  - It "UNCONDITIONALLY RETURN[s] 0 IF WE CANNOT FIND A GLOBAL ARRAY VARIABLE".
- **Parameters at EXIT** ([fjalar_main.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/fjalar_main.c)):
  - At function entry, Fjalar `memcpy`s the stack frame (from SP minus the red zone, extended to cover formal parameters stored in the caller's frame) into a "virtualStack". It also copies Memcheck's A/V shadow state for it (`MC_(copy_address_range_state)`).
  - It snapshots entry registers when the DWARF location needs them (`entryRegs`).
  - Formal parameters at exit are read from this copy.
  - Return values come from RAX/RDX, with floating point in the low 64 bits of %xmm0 on amd64 (`read_xAX`, `read_xDX`, and a comment at line ~224).

**ClearView** (debug-info-free, Daikon-based)
- ClearView, by Perkins et al. (SOSP 2009), works on "stripped Windows x86 binaries without any need for source code, debugging information, or other external information".
- It "learns invariants from normal executions" using "an enhanced version of Daikon".
- Its monitors are Heap Guard and Determina Memory Firewall.
- In a Red Team exercise it blocked all attacks and auto-patched 7 of 10 exploits.
- Sources: [abstract](https://homes.cs.washington.edu/~mernst/pubs/automatic-patching-sosp2009-abstract.html) and search snippets. I could not read the full paper, so ClearView's exact variable and program-point model and its invariant templates are **unverified**.

**Astarte** (hardware security)
- Its "front-end treats x86 instructions as program points, so Daikon will find invariants over ISA variables for each x86 instruction". — [Mining Secure Behavior of Hardware Designs, arXiv 2108.09249](https://arxiv.org/pdf/2108.09249) (search snippet)

**Binvariants** (Zao Yang and Stefan Nagy, Utah; Proc. ACM Softw. Eng. FSE 2026, Article FSE050, DOI 10.1145/3797078)
- It proposes "register-level likely invariants: the first technique to integrate likely data invariants within binary-only fuzzing".
- The prototype is built on AFL++ and QEMU.
- Evaluation: 25 programs, 7 of them closed-source. It found 143 bugs versus 137 for coverage-only fuzzing, 20 of them missed by coverage. It triggered "over 27×" more unique invariant violations.
- It states that "current invariant-guided fuzzing universally depends on source-level abstractions".
- Sources: [citedrive record](https://www.citedrive.com/en/discovery/binvariants-enhancing-fuzzing-of-closed-source-binary-executables-via-register-level-likely-invariants/), [paper PDF (not fetchable here)](https://futures.cs.utah.edu/papers/26FSE-c.pdf). Numbers are from search snippets only, so check them against the PDF. Whether it uses Daikon, and its program points (blocks or functions), are **unverified**.

**InvsCov** (Fioraldi, D'Elia, Balzarotti; USENIX Security 2021, pp. 2829–2846)
- It learns likely invariants "over variables at the basic-block level and partition[s] the program state space accordingly".
- It is built on AFL++, LLVM 10 and Daikon. It is source-based: the target is compiled with `dump-cc`.
- Source: [InvsCov README](https://github.com/eurecom-s3/invscov).
- A CACM review reports 34–56% more bugs at about 8% overhead, and notes that tracking all invariants "will both overwhelm a fuzzer… and deteriorate its throughput". InvsCov prunes by replaying inputs and with heuristics. — [CACM Research for Practice](https://cacm.acm.org/magazines/2023/5/272291-research-for-practice-the-fun-in-fuzzing/fulltext) (secondary source)

**DIDUCE** (Hangal and Lam, ICSE 2002)
- Online, Daikon-inspired invariant checking for Java bytecode, implemented with BCEL.
- It relaxes an invariant on violation and reports the relaxation. It has a training mode and a checking mode.
- It is source-free in the sense of working on bytecode, but bytecode keeps types, so it is not a stripped-binary analogue. — [DIDUCE paper](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf); [Berkeley summary](https://people.eecs.berkeley.edu/~fox/summaries/dependable/lam1.html)

**Other Daikon front ends listed in the manual**
- Chicory (Java), Celeriac (.NET: C#, F#, VB.NET, via `CeleriacLauncher.exe`), Udon (LLVM), Takuan (WS-BPEL), CITADEL (Eiffel), Hynger (Simulink), IOA, and convertcsv.pl.
- None targets stripped native binaries. — [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)

**Binary type and data-structure recovery** (the closest technique for our "struct shapes", "globals' types" and "strings" gaps)
- **REWARDS** (NDSS 2010) tags memory with type attributes and propagates them along runtime data flow, using types revealed at "type sinks" such as syscall and libc arguments. Slides report about 55–70% false negatives on heap and global data and 0–15% false positives. — [REWARDS paper](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf) (figures from a search snippet of slides; the "type sink" detail is background knowledge, **[unverified]**)
- **Howard** (NDSS 2011) recovers data structures dynamically from memory access patterns in gcc binaries "with a high degree of precision". The later DSIbin work found Howard's types often too coarse. — [Howard](https://www.ndss-symposium.org/wp-content/uploads/2017/09/slow.pdf); [DSIbin](https://research.vu.nl/en/publications/dsibin-identifying-dynamic-data-structures-in-cc-binaries/)
- **TIE** (NDSS 2011) is static (value-set analysis plus lattice constraint solving). On 87 programs it is "up to 45% more precise" than REWARDS and Hex-Rays. — [TIE](https://www.ndss-symposium.org/wp-content/uploads/2017/09/lee.pdf)
- Caballero's survey classifies binary type inference into static, dynamic and hybrid, and notes that "only three dynamic approaches combine type inference results from multiple executions". — [Caballero and Lin, ACM CSUR 2016](https://software.imdea.org/~juanca/papers/types_csur16.pdf)

### Inferences
- **The oracle uses facts we can emulate cheaply.** Kvasir's pointer-validity, initializedness and heap-array-size logic is just a shadow-memory query. Our Unicorn tool already owns the whole address space and has an allocator model (tier 5). That makes an A-bit/V-bit shadow map the most "oracle-faithful" mechanism to add:
  - A-bits: allocated or mapped.
  - V-bits: written since allocation.
  - Track V-bits per byte via `UC_HOOK_MEM_WRITE`.
  
  Then copy Fjalar's exact heap-array procedure: probe forward to the end of the malloc block, then back to the last initialized element, and report `size-1`.
- **Kvasir's stack "assume initialized" rule matters for agreement.** Kvasir treats the current frame as fully initialized, and our `--poison-uninitialized` option does not. Where we print `nonsensical` for a stack pointee, Kvasir prints a garbage value. That is a source of disagreement that says nothing about our accuracy.
- **Kvasir's virtual-stack snapshot is the same fix as phase-3's "read the spill slot at EXIT".** Fjalar does it generally by copying the whole frame plus shadow state at entry. Snapshotting `[rsp-128, rsp+K]` at ENTER and reading params from the snapshot would cover params passed on the stack (args 7 and up) and by invisible reference too.
- **Register-level invariants (Binvariants, ClearView) are the fallback model** when function-level recovery fails, for example for optimized or non-standard code. They are not scorable against Kvasir, though.

### Gaps
- I could not read the full ClearView, Binvariants or Guo-thesis PDFs because their domains were blocked. Still unknown:
  - ClearView's variable selection and its comparability for machine variables.
  - Binvariants' program points and whether it uses Daikon.
  - Kvasir's measured slowdown.
- I found no tool named "Daikon for binaries", and no Pin, DynamoRIO, Frida or Intel PT based Daikon front end, in searches.

---

## Q2. What are the trade-offs between dynamic binary instrumentation and emulation (Unicorn, Qiling, QEMU-user) for trace fidelity?

### Takeaway
- **Bare Unicorn is the lowest-fidelity choice for real program behaviour.** It is "just a CPU emulator", with no loader, dynamic linker, syscalls or I/O.
- **Qiling** adds an ELF loader, a dynamic linker running the real `ld.so` and libc from a rootfs, and syscall emulation, with per-API and per-syscall hooks.
- **QEMU-user and DBI tools** (Valgrind, which Kvasir uses; Pin; DynamoRIO; Frida) run the real libc against real host syscalls, so input, environment and libc semantics are preserved by construction.
- **For a fuzzing loop the speed gap is about process startup, not instruction speed.** AFL++ qemu_mode and unicorn_mode solve it with a forkserver, deferred init (`AFL_ENTRYPOINT`), persistent mode and snapshot restore.

### Cited Findings
- Qiling vs Unicorn: "Unicorn is just a CPU emulator… not aware of higher level concepts, such as dynamic libraries, system calls, I/O handling or executable formats." Qiling "has executable format loaders…, dynamic linkers (so we can load & relocate shared libraries), syscall & IO handlers." — [Qiling README](https://github.com/qilingframework/qiling)
- Qiling vs QEMU-user: both emulate whole executables, but Qiling "can perform dynamic instrumentation, and can even hot patch code at runtime. QEMU does neither". Qiling also offers save and restore of execution state, and hooks at "instruction/basic-block/memory-access/exception/syscall/IO" level. — [Qiling README](https://github.com/qilingframework/qiling)
- Dynamically linked Linux ELFs under Qiling need a rootfs:

  ```python
  Qiling(argv=[BIN], rootfs=ROOTFS)
  ```

  libc functions can be hooked or replaced with:

  ```python
  ql.os.set_api("puts", hook, QL_INTERCEPT.CALL)  # CALL replaces the real function
  ```

  Arguments are read with `ql.os.resolve_fcall_params(...)`, and syscalls are overridden with `ql.os.set_syscall(name, cb)`.
  - Sources: [LRQA Qiling write-up](https://lrqa.com/en/cyber-labs/emulation-with-qiling), [Synacktiv black-box fuzzing with Qiling (2025)](https://synacktiv.com/sites/default/files/2025-02/emulation-fuzzing-black-box-qiling.pdf), [Qiling API wiki](https://github.com/qilingframework/qiling/wiki/API-Reference). These are search snippets. The official wiki describes `set_api` as Windows-oriented, which conflicts with the Linux examples. I did not verify the internal ld.so resolution path.
- AFL++ qemu_mode, built on QEMU user mode for "black-box, closed-source binaries":
  - **Deferred init:** `AFL_ENTRYPOINT` moves the forkserver past startup ("a large speed improvement"), and `AFL_EXITPOINT` ends an iteration.
  - **Persistent mode** on x86-64 "speeds up fuzzing by several factors". A futex sync "roughly doubles persistent throughput".
  - **Snapshot mode** `AFL_QEMU_SNAPSHOT=<addr>` restores writable pages and `brk()`.
  - Source: [AFL++ qemu_mode README](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md)
- AFL++ unicorn_mode exposes `uc.afl_fuzz()` and `uc.afl_start_forkserver`, plus a persistent C example. It ships C, Python and Rust speedtest harnesses for comparing binding overhead, but the results table is "TODO". — [AFL++ unicorn_mode README](https://github.com/AFLplusplus/AFLplusplus/blob/stable/unicorn_mode/README.md)
- Kvasir's own start-up "often [takes] a good fraction of a second". The manual says "When tracing short-lived programs, this overhead can dominate". Its `--output-fifo` streams to Daikon online. — [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)
- Pin and DynamoRIO "address soundness by intercepting instructions at runtime, but may incur substantial performance penalties", and DBI can be detected or evaded. — [SoK: DBI for security, ASIACCS 2019](http://www.diag.uniroma1.it/delia/papers/asiaccs2019.pdf) (search snippet)

### Inferences
- **The cheapest fidelity win is to stop skipping libc.** Options, all [unverified for our codebase specifically]:
  - (a) Move to Qiling, which runs the real glibc from a rootfs. Static linking at fixture build time is an alternative.
  - (b) Keep Unicorn but load the real `libc.so.6` and `ld.so` and implement about 20 Linux syscalls: `read`, `write`, `brk`, `mmap`, `exit_group`, `arch_prctl`, `fstat` and similar. That is what Qiling's POSIX layer does.
  - (c) Keep stubs but make them *semantic* (`strlen`, `memcpy`, `printf` to stdout) using Qiling-style `set_api` replacement.
  
  Program input (argv, stdin, files) then comes for free from the `read`/`open` syscalls.
- **Determinism is an advantage of emulation.** No ASLR (non-PIE), a fixed `brk` and fixed `AT_RANDOM` give stable addresses across runs. That matters for our address-range pointer classifier and for nonces. QEMU-user and Valgrind give this only with ASLR disabled. [unverified]
- **Fix the 11 s/iteration by keeping one process alive.**
  - Run N inputs per Unicorn instance, restoring a memory snapshot (`uc.context_save` and a writable-page copy) at `main` instead of re-loading. This is equivalent to AFL++ snapshot or persistent mode.
  - Batch all `.dtrace` files into a single Daikon JVM invocation, or stream them with `--output-fifo`.
- **Fidelity cross-check:** run the same binary under QEMU-user (`qemu-x86_64 -d in_asm,cpu` or a TCG plugin) to verify that our emulated libc behaviour matches the real one. [unverified suggestion]

### Gaps
- I found no measured head-to-head of Qiling vs Unicorn vs QEMU-user vs Pin speed on the same x86-64 workload. The AFL++ speedtest has no published numbers.
- I did not verify Qiling's glibc compatibility (TLS setup, `vdso`, IFUNC resolution) for modern glibc.

---

## Q3. How do existing tools pick variables at each program point, and how do they handle depth limits, comparability (DynComp) and modbits? How could a binary tool approximate them?

### Takeaway
Kvasir's defaults:
- **Variables:** emits params, `return`, all globals and file-statics in the same compilation unit, and pointees.
- **Depth:** `--nesting-depth=2`, `--struct-depth=4`.
- **Pointers:** **every pointer is printed as an array by default**. The `--func-disambig-ptrs` and `--disambig-ptrs` options turn pointers into single values.
- **Comparability:** DynComp runs by default and writes a separate `.decls`.
- **Modbits are NOT computed.** The source maps initialized to modbit 1 and uninitialized to modbit 2 ("nonsensical"). Our hardcoded `1` therefore already matches the oracle, and "real modbits" can only move us *away* from Kvasir. It could still improve Daikon output in absolute terms.

### Cited Findings
**Variable selection** (all from the [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo))
- "The default is to generate trace information for global and static variables" (`--ignore-globals` and `--ignore-static-vars` turn this off).
- "By default, file-static variables are only outputted at program points for functions that are defined in the same file (compilation unit) as the variable, and static variables declared within a particular function are only outputted at program points for that function" (`--all-static-vars` overrides).
- `--nesting-depth=N`: "how many levels of pointers to dereference" for structs that contain other structs or pointers to them. "The default is 2."
- `--struct-depth=N`: depth for self-referential structs (lists and trees). "The default is 4."
- "By default, Kvasir treats all pointers as arrays when outputting their contents."
  - `--func-disambig-ptrs` treats pointer params and returns as single values.
  - `--disambig-ptrs` treats all pointers as single values.
  - `--smart-disambig` runs the program and "observes whether each pointer refers to either one element or an array" to write a `.disambig` file.
- Struct variables themselves are not output (only with `--output-struct-vars`).
- Static arrays are flattened only after the single sequence level Daikon allows is used up (`--flatten-arrays` forces it).
- `--array-length-limit=N` caps array traversal.
- `--ppt-list-file` and `--var-list-file` select program points and variables. `--dump-ppt-file` and `--dump-var-file` list them, but must be run with `--no-dyncomp`.

**Nonsensical values and modbits**
- A front end "should print only variables that have valid values". Uninitialized variables and deallocated pointees should be printed as `nonsensical`, both because noise "can degrade invariant detection" and because dereferencing an invalid pointer can crash the program. — [Daikon developer manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/developer.texinfo)
- Daikon prints, for example, `a.b == 0` meaning "*if* `a.b` is sensible". Nonsensical values are ignored (`daikon.Daikon.guardNulls` makes this explicit). — [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)
- Modbit semantics from the developer manual:
  - 0 means not assigned since the last execution of this program point, and 1 means assigned.
  - "It is safe for an implementation to always set it to 1. It is also safe to always set it to 0, because Daikon corrects obviously incorrect modification bits."
  - 2 is used "only (and always)" with `nonsensical`.
  - The manual's own instrumentation example "does not compute the 'modified bits', but simply sets them all to 1, which is a safe default."
  - Source: [Daikon developer manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/developer.texinfo)
- **Kvasir's actual implementation**, from [kvasir/dtrace-output.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/kvasir/dtrace-output.c) lines 145–155:

  ```c
  // Maps init value to modbit
  // init = 1 ---> modbit = 1
  // init = 0 ---> modbit = 2
  static char mapInitToModbit(char init) {
    if (init) return 1; // Make it seem like it's "modified" by default
    else      return 2; // Garbage value
  }
  ```

  Every value line is emitted through this function.

**Comparability and DynComp**
- Format: a signed integer per variable. Variables are comparable if the integers are equal, **or if either is negative** ("comparable to every other variable"). Arrays carry `elem[index]`, for example `8[5]`. Numbers are per program point and have no meaning across program points. — [Daikon developer manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/developer.texinfo)
- DynComp runs by default under Kvasir and always writes a separate `.decls`, because comparability is "not available until the end of execution". The manual says running Daikon without it is "strongly discouraged". — [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)
- DynComp interaction modes (`--dyncomp-interactions`):
  - `all` (default): any binary operation merges its operands.
  - `units`: only comparisons, addition and subtraction.
  - `comparisons`: only comparison operators.
  - `none`: dataflow only.
  
  Other options:
  - `--dyncomp-separate-entry-exit`: by default, ENTER and EXIT share the same comparability numbers.
  - `--dyncomp-approximate-literals`: treats literals approximately, which is faster.
  - `--dyncomp-detailed-mode`: O(n²), more precise.
  - Unhandled VEX operators: in warn mode, an operator that returns a boolean with 2 data operands is treated as a comparison.
  - Source: [Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo)
- DynComp algorithm (Guo, Perkins, McCamant, Ernst, "Dynamic inference of abstract types", ISSTA 2006, pp. 255–265):
  - Each runtime value gets its own tag, and an interaction merges tags (union-find).
  - Variable-level abstract types are built from the values variables held at program points.
  - It had x86 (DynCompX) and Java (DynCompJ) implementations, and was more precise than the static Lackwit: 11 vs 7 types on the example.
  - Sources: [abstract](https://homes.cs.washington.edu/~mernst/pubs/abstract-type-issta2006-abstract.html); [slides](https://homes.cs.washington.edu/~mernst/pubs/abstract-type-issta2006-slides.pdf) (search snippets)
  - The source confirms tags mapped to per-program-point comparability numbers that reset at each program point (`g_compNumberMap`, `g_curCompNumber`), and a union-find module. — [dyncomp_runtime.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/kvasir/dyncomp_runtime.c)
- DynComp's comparability "significantly improved both the run time and precision of Daikon". — Perkins and Ernst 2006 CSAIL abstract (search snippet, [CSAIL](https://publications.csail.mit.edu/abstracts/abstracts06/jhp/jhp.html))

### Inferences
- **Modbits.** Kvasir's modbit is purely a `nonsensical` flag. The current docs/plans claim that "real modbits is where the remaining precision headroom is" is therefore **suspect as a route to agreeing with Kvasir**:
  - The oracle never emits 0, so any real modbit can only change our invariant set relative to it.
  - Real modbits may still reduce redundant `x == orig(x)` noise for the fuzzing consumer. Measure both against Kvasir and in absolute terms.
  - Emitting **2 with `nonsensical`** for invalid pointees is what Kvasir does.
- **DynComp at binary level is directly reproducible in Unicorn.** Our tracer already sees every instruction (capstone):
  - Give each register and memory byte a tag.
  - Create fresh tags for immediates.
  - Copy tags on `mov`, `push`, `pop` and loads/stores.
  - Union operand tags on `add`, `sub`, `cmp`, `imul` and similar (`units` mode = `add`/`sub`/`cmp` only).
  - At each program point, map each emitted variable's location tag to its union-find root, and number the roots.
  - Use the same numbers at ENTER and EXIT.
  
  This replaces "comparability from tier 3" heuristics with the oracle's actual algorithm. -O0 code helps, because every variable round-trips through a stack slot.
- **Pointers.** To match Kvasir, pointer params should be emitted as **arrays** (`p[]`, with `p[..]` contents) by default, not as single pointees, unless the oracle run used `--func-disambig-ptrs`. Check how `test.sh` invokes Kvasir.
- **Depth.** A recursive traversal with nesting depth 2 and struct depth 4 (self-type detection is possible once a field holds a pointer into a same-sized heap block) would align with defaults. Our tool currently does one level.
- **Globals.** Emit at every program point (Kvasir's default). Without CU info, we cannot apply the file-static scoping rule. Kvasir emits file-statics only in the same CU, which is a known source of extra false-positive globals for us in multi-file programs. A partial proxy is address proximity in `.data`/`.bss` and "accessed by this function" (`--infer-from-caller`). [unverified heuristic]

### Gaps
- I could not confirm the exact command line `test.sh` uses for Kvasir (that is, whether DynComp is on). Check it locally.
- I found no published evaluation of a binary-only DynComp re-implementation.

---

## Q4. How are function and argument boundaries recovered at binary level (calling convention, arity, return value, varargs), and how accurate are the methods?

### Takeaway
- **The standard approach is use-before-def liveness on SysV argument registers at the callee, plus set-before-call at callsites.** This is TypeArmor-style, with callee underestimation and callsite overestimation. It is what our tier 2 does.
- Published arity accuracy is about **80–84%** on general (often optimized) binaries:
  - TypeArmor: 83.26% callee, 79.19% callsite.
  - EKLAVYA (neural): about 84% count, about 81% types.
- Accuracy drops sharply with optimization and without symbols. -O0 is the easy case, since args are spilled in the prologue.

### Cited Findings
- **TypeArmor's method:**
  - It reconstructs callee prototypes by use-def analysis at possible callees.
  - It analyzes callsites backwards from the call for argument registers that are set or trashed.
  - The callsite analysis may only over-estimate and the callee analysis may only under-estimate, to stay conservative.
  - Source: [TUM lecture "A Tough call"](https://www.sec.in.tum.de/i20/assets/vorlesung/18w/tough-call-mitigating.pdf)
- **"When Function Signature Recovery Meets Compiler Optimization"** (IEEE S&P 2021):
  - Studies 8 ways optimization breaks signature recovery across 1,344 x86-64 applications.
  - Reports TypeArmor's arity accuracy as 83.26% at callees and 79.19% at callers, and questions it for optimized code.
  - Source: [IEEE CSDL](https://www.computer.org/csdl/proceedings-article/sp/2021/893400a091/1mbmHtHLPAA) (search snippet)
- **EKLAVYA** (neural, USENIX Security 2017) learns argument count and types from binaries without hand-written calling-convention rules: about 84% count and about 81% type accuracy. — [EKLAVYA](https://www.comp.nus.edu.sg/~prateeks/papers/Eklavya.pdf) (search snippet)
- **"Assessing the Effectiveness of Binary-Level CFI Techniques"**: when symbols are unavailable, argument-type accuracy drops by about 44% at callsites and about 45% for functions, compared with source ground truth. — [arXiv 2401.07148](https://arxiv.org/html/2401.07148v1) (search snippet)
- **BPA** (NDSS 2021): indirect-call target precision 34.5% higher than conservative arity matching. — [NDSS 2021](https://www.ndss-symposium.org/wp-content/uploads/ndss2021_2B-4_24386_paper.pdf)
- **Kvasir's approach for comparison:** return value from RAX/RDX, float return from low 64 bits of xmm0, and parameters from DWARF locations, with the stack frame snapshotted at entry. — [fjalar_main.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/fjalar_main.c)

### Inferences
- **At -O0, a dynamic tool can beat static arity recovery by combining:**
  - (1) the prologue spill pattern (`mov %edi,-0x14(%rbp)` and similar), which gives arity *and* width;
  - (2) callsite evidence (registers written before `call`), combined as max over observed callsites;
  - (3) xmm usage and the `%al` vector-count convention for varargs. In SysV, `%al` holds the number of vector registers used at a varargs call, and `movl $0,%eax` before `call printf` marks a varargs callee. [unverified, from SysV ABI knowledge]
- **Return-value detection.** At -O0, `void` functions typically leave RAX holding leftovers. A dataflow test helps: "RAX written in the function after its last call, and read by the caller after return". Callee-side writes alone are not enough. [unverified heuristic]
- **Signedness and width.** Prologue spill width (`movl` vs `movq` vs `movb`) gives width. The sign- or zero-extending load at the first use (`movsx` vs `movzx`, `cdqe`), and `jl`/`jg` vs `jb`/`ja`, give signedness. This is the same family of signals as TIE's lattice. [unverified mapping]

### Gaps
- I found no published arity-accuracy figure restricted to gcc -O0, the setting where the problem is nearly solved.
- I did not fetch the S&P'21 paper's per-optimization-level table.

---

## Q5. Are there published accuracy numbers for binary-level invariant inference vs. source-level?

### Takeaway
I found **no published precision/recall comparison** of a debug-info-free invariant front end against a DWARF or source-level oracle. Our measured numbers (65/92/76 own corpus; 22/17/19 Kvasir suite) appear to be novel. The nearest published numbers measure other things:
- downstream bug-finding (Binvariants 143 vs 137 bugs; InvsCov 34–56% more bugs);
- ClearView patching (7 of 10 exploits);
- type-recovery accuracy (REWARDS about 55–70% false negatives on heap/globals; TIE up to 45% better than REWARDS/Hex-Rays);
- arity (about 80–84%).

### Cited Findings
- Binvariants: 143 vs 137 bugs, 20 missed by coverage, more than 27× unique invariant violations. — [citedrive record](https://www.citedrive.com/en/discovery/binvariants-enhancing-fuzzing-of-closed-source-binary-executables-via-register-level-likely-invariants/) (snippet)
- InvsCov: 34–56% more bugs at about 8% overhead. — [CACM](https://cacm.acm.org/magazines/2023/5/272291-research-for-practice-the-fun-in-fuzzing/fulltext) (secondary source)
- ClearView: all Red Team attacks blocked, 7 of 10 auto-patched. — [SOSP'09 abstract](https://homes.cs.washington.edu/~mernst/pubs/automatic-patching-sosp2009-abstract.html)
- REWARDS false-negative and false-positive rates; TIE "up to 45% more precise". — [REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf); [TIE](https://www.ndss-symposium.org/wp-content/uploads/2017/09/lee.pdf)
- DynComp improves Daikon precision and runtime over no comparability, and is more precise than static Lackwit. — [ISSTA'06 abstract](https://homes.cs.washington.edu/~mernst/pubs/abstract-type-issta2006-abstract.html)

### Inferences
- **The scoring methodology itself is a contribution.** That means aligning names via DWARF at scoring time only, and measuring P/R/F1 over invariant sets against Kvasir.
- **The oracle has known defects that cap any agreement score:**
  - the `is_param` coefficient bug documented in docs/plans/README.md;
  - the "stack assumed initialized" rule;
  - pointers printed as arrays.
  
  Report "agreement with Kvasir" separately from "truth on samples".

### Gaps
- I could not access the full text of Binvariants or ClearView to check whether either reports per-invariant precision.
- I found no study that compares Daikon output under Kvasir vs a binary-only front end on the same programs.

---

## Ranked, concrete transferable ideas (synthesis; each tied to sources above)

1. **A/V shadow memory in Unicorn**, copying Fjalar's `addressIsAllocated`/`addressIsInitialized` semantics, including the stack-frame "assume initialized" exception. Use it for pointer validity, `nonsensical`/modbit=2, and the forward/backward heap-array probe (`size-1`). This is the most oracle-faithful fidelity fix. ([fjalar_runtime.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/fjalar_runtime.c))
2. **Tag-based DynComp re-implementation** on capstone-decoded instructions (`all`/`units` modes, union-find, numbering per program point, shared ENTER/EXIT numbers). ([Daikon manual](https://raw.githubusercontent.com/codespecs/daikon/master/doc/daikon.texinfo), [dyncomp_runtime.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/kvasir/dyncomp_runtime.c))
3. **Match Kvasir's output defaults:**
   - pointers as arrays unless the oracle used `--func-disambig-ptrs`;
   - recursive traversal to nesting depth 2 and struct depth 4;
   - globals at every program point;
   - modbit always 1, or 2 for nonsensical. Deprioritize "real modbits" for oracle agreement.
4. **Entry-time frame snapshot** (Fjalar's virtualStack) to read params, including stack-passed ones, at EXIT. ([fjalar_main.c](https://github.com/codespecs/fjalar/blob/master/valgrind/fjalar/fjalar_main.c))
5. **Real libc and syscalls** via Qiling (rootfs plus `set_api`/`set_syscall`) or a minimal syscall layer. This brings real `printf`, strings and program input. ([Qiling README](https://github.com/qilingframework/qiling))
6. **Persistent or snapshot execution** (AFL++ `AFL_ENTRYPOINT`/persistent/snapshot ideas, Unicorn `context_save` plus page restore), and a single Daikon JVM over many traces or `--output-fifo`. This attacks the 11 s/iteration startup cost. ([AFL++ qemu_mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/qemu_mode/README.md))
7. **Type sinks for globals, strings and doubles** (REWARDS-style): propagate types backwards from libc and syscall argument types (`printf("%f")`, `strlen`, SSE ops) to the memory they touched. ([REWARDS](https://www.cs.purdue.edu/homes/xyzhang/Comp/ndss10.pdf))
8. **Fallback register-level program points** (Binvariants/ClearView style) for fuzzing feedback where function-level recovery fails. ([Binvariants](https://www.citedrive.com/en/discovery/binvariants-enhancing-fuzzing-of-closed-source-binary-executables-via-register-level-likely-invariants/))
