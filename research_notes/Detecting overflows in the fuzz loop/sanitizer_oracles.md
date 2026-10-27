# Runtime bug oracles for integer overflow and memory safety (source and binary-only C targets)

Scope: tools that flag a bug at the moment an input triggers it, not only when the program crashes. The notes are written for this setup: Daikon/Kvasir under Valgrind, a Python coverage-guided fuzzer, gcc `-O0 -fwrapv` targets, and a Unicorn-based blackbox tracer that lazily maps unmapped memory.

"LOCAL TEST" marks a result I ran myself in this environment (gcc 13.3.0, clang 18.1.3, valgrind 3.22.0, unicorn 2.1.4 Python). The test file was `int abs_diff(int a,int b){return a>b?a-b:b-a;}` called with a=2147483647, b=-5.

---

## Q1. UBSan: integer checks, interaction with -fwrapv, trap/abort modes, gcc vs clang, overhead

### Takeaway
UBSan's `signed-integer-overflow` check is the direct fix for the missed `abs_diff` bug, but **gcc silently drops the check when `-fwrapv` is in effect** (LOCAL TEST). In this pipeline you must either compile a separate oracle build without `-fwrapv`, or use clang. Current clang docs say clang keeps the check under `-fwrapv`, but clang 18 in trap mode did not (LOCAL TEST), so this depends on the version. For a fuzzer, use `-fno-sanitize-recover=...` (report, then non-zero exit) or `-fsanitize-trap=...` (SIGILL/SIGTRAP, no runtime needed). gcc has no `unsigned-integer-overflow` or `implicit-conversion` checks. Those are clang-only.

### Cited Findings
**Check definitions (clang)**
- `signed-integer-overflow`: "Signed integer overflow, where the result of a signed integer computation cannot be represented in its type." It also covers `INT_MIN / -1`. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `unsigned-integer-overflow`: "Unlike signed integer overflow, this is not undefined behavior, but it is often unintentional." — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `shift`: shift amount >= the promoted bit-width (plus shift-base problems). It can be split into `shift-base` and `shift-exponent`. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `implicit-conversion` = `implicit-integer-conversion` + `implicit-bitfield-conversion`. The integer sub-checks are `implicit-unsigned-integer-truncation`, `implicit-signed-integer-truncation` and `implicit-integer-sign-change`. The docs say these are "not undefined behavior, but are often unintentional". — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `bounds`: "Out of bounds array indexing, in cases where the array bound can be statically determined". It includes `array-bounds` and `local-bounds`, and `local-bounds` is not part of `-fsanitize=undefined`. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `pointer-overflow`: pointer arithmetic that wraps, or that has a null old or new value. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- The `integer` group enables signed-integer-overflow, unsigned-integer-overflow, shift, integer-divide-by-zero and the implicit truncation/sign-change checks. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

**-fwrapv interaction**
- Clang (current docs): "Note that checks are still added even when `-fwrapv` is enabled." — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- LOCAL TEST, clang 18.1.3: `-fwrapv -fsanitize=signed-integer-overflow -fsanitize-trap=signed-integer-overflow` printed `-2147483644` and exited 0 (no check). Without `-fwrapv` the same build died with SIGILL (exit 132). So clang 18 still drops the check under `-fwrapv`, and the "checks are still added" behaviour comes from a later clang release. The exact version is unverified.
- GCC docs do not mention `-fwrapv` with respect to `signed-integer-overflow`. — [GCC Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- LOCAL TEST, gcc 13.3: `-O0 -fsanitize=signed-integer-overflow -fno-sanitize-recover=all` gave `ad.c:3:41: runtime error: signed integer overflow: 2147483647 - -5 cannot be represented in type 'int'`, exit 1. **The same build with `-fwrapv` printed `-2147483644` and exited 0, with no report.** Trap mode with `-fwrapv` also did not fire.
- LOCAL TEST, gcc `-ftrapv`: `-ftrapv` alone aborts (SIGABRT, exit 134) on the overflow. `-fwrapv -ftrapv` aborts, but `-ftrapv -fwrapv` does not: the last flag wins.
- Clang has a pattern-exclusion option, `-fsanitize-undefined-ignore-overflow-pattern=`, with the values `add-signed-overflow-test`, `add-unsigned-overflow-test`, `negated-unsigned-const` and `unsigned-post-decr-while`. It suppresses common intentional idioms such as `if (a + b < a)`. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

**Turning reports into a fuzzer signal**
- Clang `-fsanitize-trap=<checks>` executes "a trap instruction (doesn't require UBSan run-time support)". The process usually dies with SIGILL or SIGTRAP. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- Clang `-fno-sanitize-recover=<checks>` prints a verbose report and exits. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- GCC: "error recovery is turned on by default, except -fsanitize=address". With recovery, "the exit code may still indicate success". With `-fno-sanitize-recover=`, "only the first detected error is reported and program then exits with a non-zero exit code". `-fsanitize-trap` uses `__builtin_trap` and is fatal whatever the recovery setting. — [GCC Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- Runtime options: `UBSAN_OPTIONS=print_stacktrace=1` (needs `-g` and llvm-symbolizer), `log_path=` (sends reports to a file, which helps log parsing), `silence_unsigned_overflow=1`, and suppression files. Only recoverable checks can be suppressed. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- `-fsanitize-minimal-runtime` "only provides very basic issue logging and deduplication". — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

**gcc vs clang support**
- GCC's `-fsanitize=undefined` sub-options: shift, integer-divide-by-zero, unreachable, vla-bound, null, return, signed-integer-overflow, bounds, alignment, object-size, nonnull-attribute, returns-nonnull-attribute, bool, enum, vptr, pointer-overflow, builtin. GCC also has `bounds-strict`, which covers flexible-array-like arrays. — [GCC Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)
- LOCAL TEST, gcc 13.3: `-fsanitize=unsigned-integer-overflow` gives "unrecognized argument ... did you mean 'signed-integer-overflow'?", and `-fsanitize=implicit-conversion` is also rejected. These checks are clang-only.
- GCC `signed-integer-overflow` checks `+`, `*`, unary and binary `-`, and `INT_MIN / -1`. — [GCC Instrumentation Options](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html)

**Overhead and false positives**
- Clang: "The checks have small runtime cost and no impact on address space layout or ABI". "UndefinedBehaviorSanitizer is not expected to produce false positives." Note that for the non-UB checks (unsigned, implicit-conversion), every intentional wrap is reported. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- IOC, the precursor of clang's integer checks, measured on SPEC CPU2006: undefined-behaviour checking with precondition checks gave a 44% mean slowdown (range -0.5% to 191%). Flag-based postcondition checks gave a 30% mean (0.4% to 95%). Full integer checking gave a 51% mean (0.2% to 195%). — [Dietz et al., ICSE 2012](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)

### Inferences
- To catch `abs_diff` with gcc while keeping `-fwrapv` semantics for the Daikon build: make a second "oracle" build of the same source without `-fwrapv`, with `-fsanitize=signed-integer-overflow,shift,bounds,pointer-overflow -fno-sanitize-recover=all`, and replay every fuzzer input that hits new coverage (or every input) against it. Alternatively, use `-ftrapv` placed after `-fwrapv`, though it is less informative and has historically been unreliable in gcc. At `-O0`, dropping `-fwrapv` for the oracle build is semantically harmless for detection: the check fires before any UB-based optimisation could matter.
- Signal: the Python fuzzer can treat a non-zero exit plus a `runtime error:` line on stderr (pattern `file:line:col: runtime error: <kind>`) as a bug. With trap mode it can treat SIGILL/SIGTRAP as a bug. The text report gives file:line, which is good for deduplication.
- Unsigned overflow and implicit-conversion are noisy, because of legitimate wrap. OSS-Fuzz enables unsigned-integer-overflow but leaves it recoverable (see Q5). Do the same: log those reports, but do not abort on them.

### Gaps
- I could not pin down the exact clang release where `-fwrapv` stopped disabling `signed-integer-overflow` instrumentation. The local clang 18 had no UBSan runtime installed, so only trap mode was tested.
- I found no current, published per-check overhead benchmark for UBSan integer checks in clang. The IOC numbers above are from 2012.

---

## Q2. Academic integer-overflow detectors (IOC, IntScope, KINT, IntPatch, IntFlow, SoupInt, IntFinder, IO2BO tools)

### Takeaway
The central empirical result: **most integer overflows that occur at runtime are not bugs.** IOC found 219 static overflow sites in SPEC CINT2000, and "the vast majority ... were not bugs". Raw "overflow happened" is therefore a weak oracle. Later work cuts false positives by requiring that the overflowed value come from untrusted input (IntFlow, -89% FPs) or reach a sensitive sink such as a malloc size, an index or a memcpy length (IntPatch, IntScope, SoupInt, IntTracker). Detection then becomes a check at the sink, made before the sensitive operation runs.

### Cited Findings
- **IOC (Dietz, Li, Regehr, Adve, ICSE 2012)**: clang-based dynamic checker. It used three check strategies: precondition tests, CPU-flag postcondition tests (LLVM `*.with.overflow` intrinsics that read the processor overflow flag), and width-extension tests. The flag-based approach was faster on only 13 of 21 benchmarks, because "the LLVM intrinsics supporting the flag-based postcondition checks are recognized and exploited by relatively few optimization passes". — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- IOC found "219 static sources of overflow in eight of the 12 benchmarks" of SPEC CINT2000: 148 unsigned and 71 signed. The most common uses were hashing (128), "overflow check requiring fwrapv" (37), bit manipulation (25) and RNG (6). "the vast majority of overflows found (both unsigned and signed) were not bugs, suggesting occurrence of integer overflow by itself is not a good indicator of a security vulnerability". — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- IOC found undefined overflows in SQLite, PostgreSQL, SafeInt, GNU MPC and GMP, Firefox, GCC, LLVM, Python, BIND and OpenSSL. — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- IOC classifies overflows along two axes, intentional/unintentional and well-defined (unsigned)/undefined (signed). "all four combinations ... occur frequently in real codes". — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- **IntFlow (Pomonis et al., ACSAC 2014)**: combines static information-flow tracking with IOC-style checks and reports only errors tied to untrusted input. It detected all real-world vulnerabilities in the tested applications, with "a reduction of 89% in false positives over standalone static code instrumentation". — [IntFlow paper](https://www3.cs.stonybrook.edu/~mikepo/papers/intflow.acsac14.pdf) (abstract-level; I did not read the full evaluation)
- **KINT (Wang et al., OSDI 2012)**: *static*. It "generates constraints from source code and user annotations, and feeds them into a constraint solver". It found "more than 100 integer errors in the Linux kernel, the lighttpd web server, and OpenSSH", uses several techniques to reduce false reports, and proposes a NaN-integer type. It is not a runtime oracle. — [KINT, USENIX OSDI 2012](https://www.usenix.org/conference/osdi12/technical-sessions/presentation/wang)
- **IntScope (Wang et al., NDSS 2009)**: works on x86 *binaries*. It lifts disassembly to an IR and runs path-sensitive symbolic execution plus taint analysis, checking whether tainted values used at sinks (for example allocation sizes) can overflow. It found more than 20 zero-day integer overflows in QEMU, Xen, Xine and others. It is static/symbolic, not a runtime oracle. — [IntScope project page](https://web.cse.ohio-state.edu/~lin.3021/ndss09.html); [NDSS PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/wang.pdf)
- **IntPatch (Zhang et al., ESORICS 2010)**: an LLVM compile-time tool for integer-overflow-to-buffer-overflow (IO2BO). It finds candidates with type inference and dataflow analysis, then inserts runtime checks only on paths that reach memory-allocation or indexing sinks. It caught all 46 known IO2BO bugs in its suite, found 21 new ones, and has about 1% average runtime overhead. — [IntPatch, llvm.org](https://llvm.org/pubs/2010-09-ESORICS-FixOverflows.html)
- **SoupInt (Wang, Song, Lee)**: binary-level. Using dynamic binary instrumentation and dynamic dataflow analysis on a captured attack input, it diagnoses an overflow as harmful when the value flows into security-sensitive operations (for example memory allocation size), then generates an emergency patch. — [SoupInt PDF](https://www.cs.ucr.edu/~csong/soupint.pdf) (venue not confirmed in my sources)
- **IntTracker / IO2BO dynamic tracking**: does not report at the overflow itself. It replaces the overflowed value with a "dirty value" tag and reports only if a dirty value reaches a sink, which avoids false positives from the program's own sanitization code. — [Efficient Dynamic Tracking Technique for IO2BO, ACM](https://dl.acm.org/doi/10.1145/2714576.2714605)
- **Delayed Runtime Test (Huang, ARES 2021)**: "One main cause of false positives produced by dynamic techniques is that they fail to take into account existing sanitization code". It moves the overflow test to just before the sensitive operation, reports no false positives in the presence of sanitization code, and costs 1.75x on SPEC CPU2000. — [Huang, ARES 2021](https://facsrv.cs.depaul.edu/zhuang28/ARES2021.pdf)
- **IntFinder / LoongChecker**: described as static tools that "suffer from the problem of high false positive rates, and have to be used together with dynamic analysis to rule out false positives". — [ELAID, Cybersecurity 2020](https://link.springer.com/article/10.1186/s42400-020-00058-2)

### Inferences
- For the loop, a two-tier oracle fits. **Tier 1 (always report):** UB signed overflow, shift UB and division by zero, since UBSan says it has no false positives for real UB. **Tier 2 (report only with a sink):** unsigned wrap or truncation whose result flows into a malloc/calloc size, an array index, a pointer offset or a memcpy length, which is the IntPatch/IntTracker/SoupInt idea.
- `abs_diff` is a Tier-1 case: a signed `a-b` overflows, which is UB without `-fwrapv`. It is the "unintentional, undefined" quadrant in IOC's taxonomy. Under `-fwrapv` it becomes "well-defined", so a pure-UB oracle on the `-fwrapv` build must, by design, not flag it. This is another reason to run a non-`-fwrapv` oracle build, or to flag OF-flag events (Q4).

### Gaps
- I could not find the primary IntFinder paper (search returned nothing). Its description here comes from a secondary source.
- I did not confirm SoupInt's venue or its overhead numbers.
- I could not verify IntScope's false-positive rate.

---

## Q3. Memory-safety oracles: ASan, MSan, Valgrind memcheck, and binary-only options

### Takeaway
With source, ASan (about 2x slowdown, heap/stack/global OOB, UAF, double-free, no expected false positives) is the default oracle. For stripped binaries the options are:
- QASan / AFL++ `AFL_USE_QASAN` (QEMU, heap-focused, about 1.6x on top of QEMU while fuzzing)
- RetroWrite-ASan (x86-64 PIC only, about 3x faster than memcheck)
- libdislocator (guard pages, cheap but coarse)
- Valgrind memcheck (20-30x slowdown, misses stack/global overruns)
- for Unicorn, a BaseSAFE-style hook-based sanitizing allocator

Your Unicorn tracer's lazy mapping of unmapped memory removes the only "free" oracle (faulting on wild pointers). It must be replaced by explicit checks.

### Cited Findings
**ASan / MSan (source)**
- ASan: "Typical slowdown introduced by AddressSanitizer is 2x." It detects OOB on heap, stack and globals, use-after-free, use-after-return, use-after-scope, double/invalid free and leaks. "AddressSanitizer is not expected to produce false positives" (except container-overflow). It exits on the first error by design. — [Clang ASan docs](https://clang.llvm.org/docs/AddressSanitizer.html)
- Original ASan paper: average slowdown about 73% (USENIX ATC 2012). — [Serebryany et al., ATC 2012](https://www.usenix.org/conference/atc12/technical-sessions/presentation/serebryany)
- MSan: "Typical slowdown introduced by MemorySanitizer is 3x", with origin tracking adding another 1.5x-2x. It "requires that all program code is instrumented", and uninstrumented libraries cause false reports. Static linking is not supported. — [Clang MSan docs](https://clang.llvm.org/docs/MemorySanitizer.html)
- OSS-Fuzz leaves MSan off by default "due to the likelihood of false positives from un-instrumented system dependencies". — [OSS-Fuzz new project guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)

**Valgrind memcheck (works on binaries, already in your stack via Kvasir)**
- "Your program will run much slower (eg. 20 to 30 times) than normal". It "can't detect out-of-range reads or writes to arrays that are allocated statically or on the stack". — [Valgrind Quick Start](https://valgrind.org/docs/manual/quick-start.html)
- RetroWrite's authors put Valgrind at "2x-20x" overhead due to DBT, which makes it "unsuitable for fuzzing". — [RetroWrite, S&P 2020](https://www.nebelwelt.net/files/20Oakland.pdf) (via search summary)
- Fuzzer hook: memcheck has `--error-exitcode=<number>` (0 disables it) and `--exit-on-first-error=yes`. — LOCAL TEST (`valgrind --help`, v3.22.0)
- LOCAL TEST: memcheck on the `-fwrapv` `abs_diff` binary reported nothing (exit 0). Memcheck has no integer-overflow checking.

**Binary-only ASan variants**
- **QASan (Fioraldi, Delia, Querzoni, SecDev 2020)**: a modified QEMU that detects heap memory violations in closed-source binaries without recompiling. Headline result: about 1.61x average slowdown when added to AFL++. The project's own objdump example is about 2.4x native under plain QEMU and about 3.6x under QASan. — [QASan repo](https://github.com/andreafioraldi/qasan) (search summary; full paper not read)
- AFL++ integration: `AFL_USE_QASAN=1` with `-Q`. afl-fuzz sets `AFL_PRELOAD` for the runtime, so it "works just for dynamically linked binaries". For PIC x86-64, the README recommends trying RetroWrite first, and QASan for other architectures or when persistent/snapshot mode is needed. libdislocator has much lower overhead than QASan but "can catch less bugs". — [AFL++ libqasan README](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/qemu_mode/libqasan/README.md)
- AFL++ binary-only guide: QEMU mode costs about 50% speed, and QEMU persistent mode gives a "150-300% overall speed increase". Recommended setup: "run 1 afl-fuzz -Q instance with QASAN (`AFL_USE_QASAN=1`)". For Unicorn mode, "block chaining has been removed", so it is slower than AFL++'s QEMU mode. — [AFL++ fuzzing_binary-only_targets.md](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/docs/fuzzing_binary-only_targets.md)
- **RetroWrite (Dinesh et al., S&P 2020)**: static binary rewriting of x86-64 PIC binaries. Its binary ASan is about 3x faster than Valgrind memcheck and found 80% more bugs in the authors' evaluation. — [RetroWrite PDF](https://www.nebelwelt.net/files/20Oakland.pdf); [AFL++ binary-only doc](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/docs/fuzzing_binary-only_targets.md) (performance "close to compiler-instrumented binaries" for coverage)
- **libdislocator (AFL++)**: an LD_PRELOAD allocator. It places each buffer next to a PROT_NONE page, so off-by-one overruns fault immediately. A canary catches negative-offset *writes* (not reads). Freed memory and old realloc blocks become PROT_NONE and are never reused, which catches UAF. calloc overflow is checked, and malloc returns garbage to expose uninitialised reads. Costs and limits: about 4 kB physical / 8 kB virtual per allocation; nothing for stack errors; only dynamically linked targets. Variables: `AFL_LD_LIMIT_MB`, `AFL_LD_HARD_FAIL`, `AFL_ALIGNED_ALLOC`. — [libdislocator README](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/utils/libdislocator/README.md)

**Unicorn-based sanitizers**
- **BaseSAFE (Maier et al., WiSec 2020)** is a heap sanitizer built on Unicorn hooks. Before emulation, one large heap region is allocated with an access hook over all of it, and "Each time the hook triggers, a memory out-of-bounds access is detected" (read and write are distinguished, and PC is logged). Allocation removes the hook from the chunk, leaving a hooked canary region of varying size between chunks. Free re-hooks the chunk and never reuses it within a run, so "all use-after-free bugs are detected". The size field is set to 0, so a second free is a double-free. Bookkeeping lives outside emulated memory. The only miss: "writes skipping the variable-sized canary regions and accessing another already allocated chunk". Crash/sanitizer verdicts go to AFL through a `crash_validation_callback` that receives the Unicorn error code. — [BaseSAFE, arXiv 2005.07797](https://arxiv.org/pdf/2005.07797)
- BaseSAFE contrasts itself with QASan, which "patches each memory access in QEMU", whereas BaseSAFE adds instrumentation "on top of the memory access hooks already offered by Unicorn". — [BaseSAFE](https://arxiv.org/pdf/2005.07797)
- uniFuzzer (Unicorn + libFuzzer) overrides library functions via PRELOAD with a "simplified malloc()/free()". Its README documents no sanitizer mechanism. — [uniFuzzer GitHub](https://github.com/PAGalaxyLab/uniFuzzer)

### Inferences
- **Fix for the Unicorn tracer:** lazy mapping turns every wild read or write into a silent success, so no memory bug can ever be observed. Keep lazy mapping only for addresses the loader or ABI plausibly owns (stack growth, known segments). Treat a `UC_HOOK_MEM_UNMAPPED` / `UC_HOOK_MEM_INVALID` event outside those ranges, especially near 0 (NULL+offset) or far from any mapping, as a bug verdict rather than mapping a page. Add a BaseSAFE-style allocator by hooking the target's `malloc`/`free` PLT/libc entries, or the static-libc functions found by signature in a stripped binary. That gives a heap OOB/UAF/double-free oracle at a modest cost, because Unicorn memory hooks scoped to the heap region only fire on accesses in that range.
- **Source mode:** build a third variant with `-fsanitize=address,undefined -fno-sanitize-recover=all` (no `-fwrapv`) for replay. Running Kvasir/Valgrind on an ASan binary does not work well (they conflict), so ASan must be a separate replay binary and not the one Daikon traces.
- Memcheck is already "free" in your stack (Kvasir runs under Valgrind), but its heap-only coverage and 20-30x cost mean it should not be the primary oracle. Kvasir is itself a Valgrind tool, so memcheck errors are probably *not* reported during Kvasir runs. That is unverified, see Gaps.

### Gaps
- I did not read the QASan paper's full text, so its per-benchmark bug counts and the exact classes covered (stack/global vs heap) are unverified. The libqasan README does not list them.
- Whether Kvasir (Fjalar) emits memcheck-style errors is unverified. I believe it does not, since Valgrind runs one tool at a time.
- I found no primary documentation of a sanitizer in unicornafl/afl-unicorn itself, beyond the user-defined crash-validation callback pattern.

---

## Q4. Detecting signed overflow from CPU flags (OF) in an emulator or DBI

### Takeaway
It works, and it would have caught `abs_diff` in the blackbox mode. LOCAL TEST: Unicorn 2.1.4 sets EFLAGS.OF (bit 11) after `sub eax,[rbp-8]` with 0x7fffffff - (-5). Three rules matter:
1. Read the flags *after* the instruction, i.e. in the next code-hook callback.
2. Only consider flag-*writing* arithmetic (add/sub/imul/neg/inc/dec/adc/sbb), never `cmp`, which also sets OF for the same operands, or the sticky flags seen at later `mov`/`jmp`.
3. Expect false positives from intentional wrap: hashing, PRNG, overflow-check idioms, 64-bit pointer arithmetic, and (for CF/unsigned) almost everything.

IOC itself used flag-based checks (LLVM `*.with.overflow`). I found no maintained Pin/DynamoRIO "OF-flag" overflow detector. The binary-level literature (IntScope, SoupInt, IntTracker) uses taint plus sink checks instead, precisely because of false positives.

### Cited Findings
- IOC's "CPU flag postcondition test": "Most processors contain hardware support for detecting overflow: following execution of an arithmetic operation, condition code flags are set appropriately ... (result, flag) = s1 checked_op s2; if (flag) then call failure handler". — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- LOCAL TEST (Unicorn + Capstone on the gcc `-O0 -fwrapv` object of `abs_diff`):
  ```
  11: cmp eax, [rbp-8]   OF=1   <- comparison, not an overflow (must ignore)
  14: jle ...            OF=1   (sticky)
  16: mov eax, [rbp-4]   OF=1   (sticky)
  19: sub eax, [rbp-8]   OF=1   <- the real signed overflow (result -2147483644)
  ```
  So a naive "OF==1 at any point" rule fires on the `cmp` *before* the overflow. Because `mov`/`jmp` do not touch flags, OF also stays set on later instructions. Correct method: in a `UC_HOOK_CODE` callback, remember the previous instruction's mnemonic and operand size. If it was a flag-writing arithmetic instruction, read EFLAGS now (bit 11 = OF for signed, bit 0 = CF for unsigned add/sub).
- The IOC study shows the intent problem for any flag-based oracle: 71 signed and 148 unsigned overflow sites in SPEC CINT2000, mostly intentional (hashing 128, overflow checks 37, bit manipulation 25, RNG 6). — [IOC paper](https://users.cs.utah.edu/~regehr/papers/overflow12.pdf)
- Dynamic overflow detectors produce false positives mainly by ignoring the program's own sanitization checks. The remedies are tag-and-check-at-sink (IntTracker) or delaying the test to the sink (1.75x on SPEC2000). — [Huang, ARES 2021](https://facsrv.cs.depaul.edu/zhuang28/ARES2021.pdf); [IntTracker, ACM](https://dl.acm.org/doi/10.1145/2714576.2714605)
- SoupInt does binary-level overflow diagnosis with DBI and dataflow, and counts an overflow as harmful only if it reaches sensitive operations. — [SoupInt](https://www.cs.ucr.edu/~csong/soupint.pdf)
- AFL++ measures DBI frameworks for coverage at a "speed decrease of 98-99%" for DynamoRIO and 99.5% for Pin, so per-instruction DBI checking is far slower than compiled checks. — [AFL++ binary-only doc](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/docs/fuzzing_binary-only_targets.md)

### Inferences (design notes for the Unicorn tracer)
- **Operand width:** an OF on a 32-bit `sub eax,...` means `int` overflow. An OF on a 64-bit `add rax,...` in gcc `-O0` code is usually pointer or `long`/`size_t` arithmetic. Classify by width and report 64-bit OF at a lower priority.
- **Missed cases:** `lea` (often used for `a+b` or `a*k` at -O1+) does not set flags, so flag-based detection misses those additions. `imul r,r/m` sets OF/CF on signed truncation of the product, which is correct. `shl` OF is only defined for 1-bit shifts, so use explicit checks for shifts. Narrow types (`char`/`short`) are promoted and computed in 32 bits, so their overflow-on-store appears as truncation, not as OF. At `-O0`, gcc almost always uses plain `add`/`sub`/`imul`, so coverage of the target set is good.
- **Distinguishing signed from unsigned:** the binary does not say whether the C type was signed. OF means "the signed interpretation overflowed" and CF means "the unsigned one did"; both flags are set on every add/sub. Heuristic: report OF only when the next consumer is a signed op (`jl`/`jg`/`cdqe`/`movsxd`/`idiv`/`sar`) or when the result is later used as an index, size or pointer offset (sink). Treat CF alone as a low-priority note.
- **False-positive filters:** a per-PC allowlist; suppress PCs inside detected hash/CRC/PRNG loops (many wrapping ops with xor/shift/multiply constants); suppress `x + y < x` idiom sites (an OF/CF-producing add immediately followed by a `cmp`/`jb`/`jo` on the same register is an overflow *check*, not a bug). Optionally, do as IntTracker does: report only if the overflowed value reaches a malloc size, an index or a memory-access address.
- **Reporting:** record (PC, mnemonic, operands, input) and dedupe by PC. This fits the existing Python loop as a new "bug" verdict alongside crash and invariant refutation. For `abs_diff` the oracle would fire exactly once per triggering input, at the `sub` at offset 0x19.

### Gaps
- I found no peer-reviewed tool whose primary mechanism is "check EFLAGS.OF after every arithmetic instruction in Pin/DynamoRIO/QEMU/Unicorn". My searches returned only taint/sink-based binary tools. That a maintained one exists is unverified.
- I did not benchmark the cost of a per-instruction `UC_HOOK_CODE` flag check in Python Unicorn. It is likely dominated by the Python callback per instruction, but I have not measured it.

---

## Q5. Recommended practice in OSS-Fuzz / AFL++ / libFuzzer for integer-overflow detection

### Takeaway
OSS-Fuzz's standard UBSan build enables `signed-integer-overflow` and `shift` as fatal (`-fno-sanitize-recover`). It enables `unsigned-integer-overflow` but leaves it recoverable, so it is logged and does not abort. AFL++ recommends running one or a few instances with sanitizer builds, plus `AFL_USE_QASAN` for binary-only targets. So the industry pattern is: fatal for UB integer checks, non-fatal or off for well-defined wraparound, and a separate sanitizer build alongside the fast fuzzing build.

### Cited Findings
- OSS-Fuzz `SANITIZER_FLAGS_undefined` (exact): `-fsanitize=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fno-sanitize-recover=array-bounds,bool,builtin,enum,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr`. Note that `unsigned-integer-overflow` is enabled but absent from the no-recover list. — [OSS-Fuzz base-builder Dockerfile](https://raw.githubusercontent.com/google/oss-fuzz/master/infra/base-images/base-builder/Dockerfile)
- OSS-Fuzz `SANITIZER_FLAGS_address` = `-fsanitize=address -fsanitize-address-use-after-scope`, and `SANITIZER_FLAGS_memory` = `-fsanitize=memory -fsanitize-memory-track-origins`. — [OSS-Fuzz base-builder Dockerfile](https://raw.githubusercontent.com/google/oss-fuzz/master/infra/base-images/base-builder/Dockerfile)
- OSS-Fuzz supported sanitizers are `address`, `memory` and `undefined`. "address" and "undefined" are on by default, and MSan is off by default. — [OSS-Fuzz new project guide](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- The OSS-Fuzz base CFLAGS include `-O1` and `-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`. — [OSS-Fuzz base-clang Dockerfile](https://raw.githubusercontent.com/google/oss-fuzz/master/infra/base-images/base-clang/Dockerfile)
- AFL++ binary-only guidance: run one `afl-fuzz -Q` instance with `AFL_USE_QASAN=1`. libdislocator is cheaper than QASan but finds fewer bugs. — [AFL++ binary-only doc](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/docs/fuzzing_binary-only_targets.md); [libqasan README](https://raw.githubusercontent.com/AFLplusplus/AFLplusplus/stable/qemu_mode/libqasan/README.md)
- Clang pattern exclusions (`-fsanitize-undefined-ignore-overflow-pattern=...`) exist specifically to make unsigned/signed overflow checks usable on real code with idiomatic wraparound checks. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

### Inferences
- Concrete recipe for the source mode of the loop:
  1. Keep the Kvasir build (`-O0 -fwrapv -g`) for invariants.
  2. Add an oracle build: `gcc -O0 -g -fsanitize=address,undefined -fno-sanitize-recover=all` (no `-fwrapv`). With clang you can also add `-fsanitize=unsigned-integer-overflow,implicit-conversion` as *recoverable* checks and parse the `runtime error:` lines as low-severity findings.
  3. Replay each input (or each new-coverage input) on the oracle build. Verdict = exit code != 0, or a `runtime error:` / `ERROR: AddressSanitizer` line on stderr. Use `UBSAN_OPTIONS=print_stacktrace=1:log_path=...` and `ASAN_OPTIONS=abort_on_error=1` for easier parsing.
  The 5 `abs_diff` hits would have produced 5 reports at `abs.c:1:<col>`, deduplicated to one.
- For the blackbox mode, combine the OF-flag oracle (Q4) with strict unmapped-access faults and a hooked-heap sanitizer (BaseSAFE-style). This mirrors what QASan, libdislocator and BaseSAFE give AFL++ users.

### Gaps
- Whether OSS-Fuzz also sets `UBSAN_OPTIONS=silence_unsigned_overflow=1` at runtime (which would make the unsigned check effectively silent) is unverified. I did not check the runner environment.
- The `abort_on_error` / `halt_on_error` ASan options were not documented on the pages I read. Their behaviour is standard sanitizer_common behaviour, but I did not cite it from a primary page.
