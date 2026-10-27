# Sanitizer-guided fuzzing and non-crash oracles (for detecting overflows in the Daikon + fuzzer loop)

Scope: (a) fuzzers that use sanitizer or bug-oracle checks to *guide* the search (prioritize or steer toward code where a check could fire), including "distance to overflow" metrics; (b) oracles for bugs that do not crash (differential, metamorphic, property/assertion), and how fuzzers *report* such silent bugs. Primary PDFs were downloaded and grepped where possible (SAVIOR, ParmeSan, AFL-HR headroom, SmartFuzz, DIODE, Barr et al.). Line-level quotes come from those texts. Context: the user's loop computes branch-distance to invariant violation, builds targets with gcc -O0 -fwrapv, and missed a signed overflow in `abs_diff` because no `return >= 0` invariant was ever proposed.

## SAVIOR (S&P 2020): bug-driven hybrid testing using UBSan labels

### Takeaway
SAVIOR uses Clang UBSan's inserted checks as static "bug labels". It scores each seed by how many UBSan labels are reachable behind its unexplored branches, decayed by how often solving has failed. It then uses the UBSan check condition itself (e.g. `a+b > 2^n-1`) as an SMT query, which yields a witness input or a proof that the bug is infeasible on that path. Its integer-overflow example is close to the `abs_diff` case: plain coverage reaches the line, but nothing pushes the operand values toward the overflow.

### Cited Findings
- Headline results: vulnerabilities detected 43.4% faster than Driller and 44.3% faster than QSYM, and 88 / 76 more unique bugs respectively. Across 11 well-fuzzed benchmark programs, the first 24 hours produced 481 UBSan violations, of which 243 are real bugs. — [Chen et al., SAVIOR, arXiv 1906.07327 / S&P 2020](https://arxiv.org/abs/1906.07327)
- Labeling: "we use Clang's Undefined Behavior Sanitizer (UBSan) to label different families of potential bugs." The families are out-of-bound array access, oversized shift, signed integer overflow and unsigned integer overflow. Each label gets a `!saviorBugNum` metadata via a patched Clang front-end. UBSan over-approximates, which "ensures soundness since it never misses true bugs." — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- Table I trigger conditions, used directly as solver predicates: `array[x]`: x<0 ∨ x≥size; shifts: y<0 ∨ y≥n; signed `x op y` ∉ [−2^(n−1), 2^(n−1)−1]; unsigned `x op y` > 2^n−1, for op ∈ {+,−,×,÷,%}. — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- Seed score: for a seed with n unexplored branches e_i, each reaching L_i UBSan labels, after S_i failed solve attempts, the score is (1/n)·Σ e^(−0.05·S_i)·L_i. Reachable labels are counted per basic block via reachability analysis; "each basic block at most has one label after Clang's compilation." — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- Bug-guided verification: along each concolic path, SAVIOR "synthesizes the faulty constraint of triggering each vulnerability". If it is SAT, the solver produces a test input as proof; if UNSAT, the bug is proved infeasible on that path. Worked example: the integer-overflow predicate `section->size + 1 > 0xffffffff` is solved to the witness 0xffffffff, which "classic hybrid testing misses". — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- With bug-guided verification added, Driller, QSYM and SAVIOR each find at least 22.2%, 25% and 4.5% more UBSan violations respectively. — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- False-label pruning: a label is removed when it is provably dead (its conditions conflict with dominating checks). This "conservatively" removes about 5.36% of labels on average (Table IX). — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)
- ASan is not usable as a label source in SAVIOR, because its checks depend on red-zone state rather than input-dependent conditions. — [SAVIOR paper](https://arxiv.org/pdf/1906.07327)

### Inferences
- In the user's loop, every arithmetic op in the target would be an "implicit invariant" (`INT_MIN ≤ a op b ≤ INT_MAX` in mathematical integers), which exists independently of Daikon. Adding these UBSan-style predicates as always-present targets in the existing distance-to-violation machinery would have caught `abs_diff` without needing Daikon to propose `return >= 0`.
- SAVIOR's e^(−0.05·S) decay is a simple, citable way to stop the fuzzer from spending too long on overflow targets it cannot reach.

### Gaps
- I did not extract per-program tables (Table IX label counts, per-program TTE).

## ParmeSan (USENIX Security 2020): sanitizer-guided greybox fuzzing

### Takeaway
ParmeSan turns sanitizer instrumentation into directed-fuzzing targets. It diffs the LLVM IR of a sanitized build against an unsanitized build, prunes the resulting targets, and runs an Angora-based fuzzer that prioritizes conditionals by CFG distance to those targets. It does not use operand-value distance inside the check: it gets you to the check, and Angora's gradient solving then flips it. Picking the right sanitizer matters. UBSan targets found a libpng integer overflow in 32 minutes, where other sanitizers' targets were an order of magnitude slower.

### Cited Findings
- Headline: bugs found 37% faster than Angora and 288% faster than AFLGo (geomean TTE speedup), "while still covering the same set of bugs". The reported range is "between 37% to 876% faster". — [Österlund et al., USENIX Sec 2020 page](https://www.usenix.org/conference/usenixsecurity20/presentation/osterlund); [paper PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Target acquisition: "we run the llvm-diff tool between the sanitizer-instrumented and the uninstrumented version … and label all the conditionals added by the instrumentation as candidate targets." Example listing: UBSan pointer-overflow check (`icmp` and then `__ubsan_handle_pointer_overflow`). — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Pruning, two heuristics:
  - Profile-guided (built on ASAP): remove checks on hot paths reached by profiling inputs. ASAP notes that ≥80% of bugs are still detected.
  - Complexity-based: score functions by how many instructions the sanitizer added. On LAVA-M base64, the top 2 of the top 3 targets were the injected-bug functions. — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Distance: d(c)=0 if c is a target, ∞ if no successor reaches a target, and otherwise the harmonic-mean-style recursion ((Σ_{n∈N(c)} d(n)^−1)/|N(c)|)^−1 + 1, over a dynamic CFG refined at runtime using DFSan taint for indirect calls. The queue is sorted by the tuple (runs, distance), so it "does not get stuck on a single conditional with a low distance". — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Coverage you can skip: for libxml2 with TySan, "we can disregard 80% of the basic blocks and still find the bug". UBSan and TySan give small target sets; ASan instruments almost everything. — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Choosing the sanitizer: for the libpng integer overflow, "using UBsan, we trigger the bug in an average time of 32 minutes", and other sanitizers were an order of magnitude slower. For the freetype2 integer overflow, UBSan targets found the bug in 20 h versus 47 h. — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- New bugs: 736 crashes, 47 unique by call stack (37 in pbc, 10 in up-to-date OSS-Fuzz libraries). The authors caution that new-bug counts are only a case study. — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)
- Implementation: Angora fork, about 2,500 LoC of changes; the blackbox sanitizer analysis is Python plus LLVM passes. — [ParmeSan PDF](https://download.vusec.net/papers/parmesan_sec20.pdf)

### Inferences
- The "diff sanitized vs. unsanitized build" trick works at any IR level. For the user's source mode, compiling once with `-fsanitize=signed-integer-overflow` and listing the check sites would give a cheap target list.
- Blackbox mode (Unicorn on stripped binaries) has no sanitizer. Target sites there have to come from instruction semantics, such as `add`/`sub`/`imul` followed by a flag. See SmartFuzz below.

### Gaps
- I did not verify ParmeSan's exact per-benchmark tables (Google fuzzer-test-suite, LAVA-M) beyond the quoted numbers.

## Overflow-specific "distance" metrics: AFL-HR headroom, DIODE, SmartFuzz, value profile

### Takeaway
Yes, there is work that treats an overflow check's operands as a distance. The closest published match to the user's design is the **headroom** fitness of AFL-HR (Medicherla, Komondoor, Roychoudhury, ICSE Workshops/SBST 2020). It computes, per arithmetic site, how far the widened result is from INT_MAX as a ratio. It keeps a second queue population of inputs that lower headroom without adding coverage, and it found SV-COMP overflows about 4–6x faster per bug than AFL/AFLGo. DIODE and SmartFuzz use symbolic execution with overflow predicates instead of a distance. libFuzzer's value profile is a generic, weaker version of the same signal.

### Cited Findings
- AFL-HR headroom definition: for a max-wraparound site with ideal (widened) value i_o, h = 0 if i_o > I_max; h = (I_max + 1 − i_o)/I_max if 0 < i_o ≤ I_max; otherwise h = 1. Per run, take the minimum over all visits; h = 1 if the site is not visited. Min-wraparound is defined analogously. — [Medicherla et al., "Fitness Guided Vulnerability Detection with Greybox Fuzzing", ICSEW 2020](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
- Instrumentation: CIL source-to-source on `v1 = v2 + v3`, `v2 * v3`, `v2 - v3`, using the width-extension test (compute in 64-bit `long`, compare with the 32-bit range). Headroom goes into a separate shared-memory table of 8-bit entries alongside AFL's bitmap. — [AFL-HR paper](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
- Two populations: (1) AFL's coverage-retained inputs; (2) "test inputs that don't reach new code regions, but reduce headroom at vulnerability locations more than other previously generated test inputs." — [AFL-HR paper](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
- Integer-overflow results on 177 SV-COMP 2019 overflow benchmarks (900 s, 5 runs, seeds {0, INT_MIN-ish, INT_MAX}):
  - In the first 15 s: AFL-HR 143, AFLGo 118, AFL 110 (statistically significant).
  - At 900 s: 148 / 146 / 147, i.e. about the same.
  - Mean time per vulnerability: 7 s (AFL-HR) vs 27 s (AFLGo) vs 42 s (AFL).
  - Buffer overruns (MIT benchmarks, 3 h): 29 of 46 vs 19 (AFLGo) and 16 (AFL). — [AFL-HR paper](https://www.csa.iisc.ac.in/~raghavan/ReadingMaterial/sbst20.pdf)
- A 2024 directed-greybox-fuzzing survey names AFL-HR and HDR-Fuzz as using the "headroom" vulnerability-oriented fitness, and argues that hard-to-manifest bugs need multi-dimensional fitness. — [Wang et al., STVR 2024](https://onlinelibrary.wiley.com/doi/10.1002/stvr.1869) (secondary; from search snippet, not fully read)
- DIODE (ASPLOS 2015) works on x86 binaries. It extracts a symbolic target expression for allocation-size sites and solves for overflow plus the relevant sanity checks ("goal-directed conditional branch enforcement"). On 5 applications (Dillo, VLC, SwfPlay, CWebP, ImageMagick) it found 40 target sites:
  - 17 had an unsatisfiable target constraint.
  - 9 were blocked by sanity checks (confirmed manually).
  - Overflows were triggered at all remaining 14 sites, 11 of them new.
  - 9 of the 14 needed no branch enforcement; the other 5 needed 2–5 enforced branches. — [Sidiroglou-Douskos et al., DIODE, ASPLOS 2015](https://people.csail.mit.edu/fanl/papers/diode-asplos2015.pdf)
- SmartFuzz (USENIX Security 2009) does dynamic test generation on Linux x86 binaries, without source, and targets overflow/underflow, width conversions and signed/unsigned conversions. It infers signedness by type inference over binary operations, solves for inputs that trigger those conditions, then only reports inputs that Valgrind memcheck or a crash confirms ("We only report test cases that are verified to trigger incorrect behavior"). Result: about 77 distinct bugs in 864 compute hours (about $2.24 per bug on EC2), including bugs zzuf missed. — [Molnar, Li, Wagner, USENIX Sec 2009](https://people.eecs.berkeley.edu/~daw/papers/smartfuzz-use09.pdf); [USENIX page](https://usenix.org/conference/usenixsecurity09/technical-sessions/presentation/dynamic-test-generation-find-integer)
- SmartFuzz's authors explain why they did not treat every overflow as a bug: "many overflows are benign and harmless", and "occasionally the code intentionally relies upon overflow". — [SmartFuzz paper](https://people.eecs.berkeley.edu/~daw/papers/smartfuzz-use09.pdf)
- libFuzzer value profile: with `-fsanitize-coverage=trace-cmp` plus `-use_value_profile=1`, every CMP is hooked. The feature `(caller_pc&4095) | (popcnt(Arg1^Arg2) << 12)` sets a bit, and a new bit counts as new coverage. Cost: up to 2x slowdown and a corpus several times larger. — [libFuzzer docs](https://llvm.org/docs/LibFuzzer.html)
- CDGF (constraint-guided DGF, USENIX Sec 2021) uses comparison distances that are 0 when a constraint holds and grow as the operands move apart. It was surfaced by search and not verified in full text. — [Lee et al., CAFL](https://www.usenix.org/system/files/sec21fall-lee-gwangmu.pdf)
- Other "vulnerability-oriented" metrics (snippets only, not read in full):
  - MemLock (ICSE 2020) uses memory-consumption guidance; 14 programs; reports 15 new CVEs. — [MemLock](https://research.tees.ac.uk/en/publications/memlock-memory-usage-guided-fuzzing/)
  - TortoiseFuzz (NDSS 2020) uses "coverage accounting" that weights edges by security sensitivity; 30 applications; 18 new vulnerabilities and 8 CVEs; comparable to QSYM at about 2% of its memory. — [NDSS](https://www.ndss-symposium.org/ndss-paper/not-all-coverage-measurements-are-equal-fuzzing-by-coverage-accounting-for-input-prioritization/6289)

### Inferences
- The user's "distance to violation" for a Daikon invariant `x ≤ c` is structurally the same as headroom. Adding a synthetic invariant per arithmetic instruction, `a op b ∈ [INT_MIN, INT_MAX]` evaluated in wider precision, plugs straight into the existing "keep inputs that get closer" retention. This is AFL-HR's population 2.
- In the Unicorn blackbox mode, OF/CF flags after `add`/`sub`/`imul` give the oracle. A distance can be computed from the operands (e.g. INT_MAX − (a+b) in 64-bit) at each such instruction. SmartFuzz shows binary-level signedness inference is needed to tell signed from unsigned overflow, and that many hits will be benign (compiler idioms, hashes).
- With `-O0 -fwrapv`, overflow produces a defined wrapped value. A crash oracle will never fire on it, so an explicit arithmetic oracle is required.

### Gaps
- "IntFuzz", "UBfuzz" and "SanRazor" were not verified. Per my training knowledge, SanRazor is about removing redundant sanitizer checks for performance, not guidance, and UBfuzz is about testing sanitizers themselves. Both should be confirmed before citing.
- UAFuzz (RAID 2020, use-after-free directed fuzzing) and Dowser (USENIX Sec 2013, buffer-overflow-directed via taint + symbolic) were not covered by fetched sources.
- I found no published AFL++ mode that converts each UBSan check into a cmplog/redqueen target automatically. Cmplog only logs comparisons that exist; UBSan's overflow checks use `llvm.sadd.with.overflow` intrinsics, not plain cmps, so cmplog may not see them. This is unverified.

## Non-crash oracles: differential, metamorphic, property/assertion (and the test oracle problem)

### Takeaway
Barr et al. (TSE 2015) classify oracles as specified (specs, assertions, contracts), derived (pseudo-oracles/N-version/differential, metamorphic relations, regression, *inferred invariants such as Daikon*) and implicit (crashes, sanitizer reports), plus human oracles when none exists. The user's loop is a derived oracle (Daikon) feeding a fuzzer. Its blind spot is that a derived oracle only covers properties that were inferred, so it is worth adding cheap implicit oracles (overflow checks) and differential oracles alongside it.

### Cited Findings
- Barr et al. define the test oracle problem as distinguishing "the corresponding desired, correct behaviour from potentially incorrect behavior". Literature counts by category: specified 317, derived 245, implicit 76, "no test oracle" 56. — [Barr, Harman, McMinn, Shahbaz, Yoo, "The Oracle Problem in Software Testing: A Survey", TSE 41(5) 2015](https://discovery.ucl.ac.uk/id/eprint/1471263/1/06963470.pdf)
- Barr et al. explicitly place Daikon under derived oracles (§5.4.1 Invariant Detection). They formalize it as "an unsound test oracle that gathers likely invariants", where "only those likely invariants remain that no observation invalidates". — [Barr et al. 2015](https://discovery.ucl.ac.uk/id/eprint/1471263/1/06963470.pdf)
- The fuzzing survey by Manès et al. defines a bug oracle as the component that checks whether an execution violates a specific security policy. — [Manès et al., "The Art, Science, and Engineering of Fuzzing: A Survey"](https://arxiv.org/pdf/1812.00140)
- NEZHA (S&P 2017) does differential testing "using different programs of the same functionality as cross-referencing oracles" to find semantic bugs. — [NEZHA](https://www.ieee-security.org/TC/SP2017/papers/390.pdf)
- A DBMS-fuzzing survey classifies oracles as crash, differential, metamorphic and constraint-solving. It notes that differential oracles "cannot detect common bugs" shared by the target and the reference implementation. — [DBMS fuzzing survey, arXiv 2311.06728](https://arxiv.org/pdf/2311.06728)
- Differential oracles are noisy: a 2026 paper reports that most output differences come from unspecified behavior, optimization differences or evolving specs, so triage is a central cost. — [arXiv 2601.15074](https://arxiv.org/pdf/2601.15074) (snippet only)
- Clang's `-fsanitize=signed-integer-overflow` "checks are still added even when -fwrapv is enabled". Signed `INT_MIN/-1` is included. `-fsanitize=unsigned-integer-overflow` exists but flags defined behavior that is "often unintentional". — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)

### Inferences
- Concrete differential oracle for the user: run each input on the existing `-fwrapv` build and on a second build with `-fsanitize=signed-integer-overflow -fno-sanitize-recover` (or `-ftrapv`). A divergence (abort vs. normal exit) is the bug report, and the `-fwrapv` build stays as Daikon's/Kvasir's view.
- A second option compares the C result with a Python big-int reference evaluation of the same expression. That is a pseudo-oracle, effective for small arithmetic targets like `abs_diff`.
- Metamorphic relations for `abs_diff`-style functions, e.g. `f(a,b) == f(b,a)` and `f(a,b) >= 0`, are properties a human or LLM can state once. They catch exactly the wrong-value class that Daikon missed from a single seed.
- The `abs_diff` miss is a known weakness of derived oracles: Daikon only proposes invariants that the observed corpus supports (`return == 2` from one seed). Seed diversity before the inference step (several varied seeds) would likely have yielded `return >= 0`. This is an inference, not tested.

### Gaps
- I found no single recent survey dedicated to oracles in general-purpose C fuzzing beyond Barr (2015) and Manès (2019). Domain surveys (DBMS, protocol, kernel) cover it piecemeal.
- I did not verify whether GCC's `-fsanitize=signed-integer-overflow` still instruments under `-fwrapv`. The Clang docs confirm it for Clang only; GCC behavior should be tested locally.

## How silent-bug reports combine with coverage in practice (AFL++, libFuzzer)

### Takeaway
Fuzzers keep the reporting channel ("crashes/") separate from the guidance channel ("queue/"). Silent bugs reach the reporting channel by being turned into a signal or a designated exit code: UBSan with `-fno-sanitize-recover`/trap, explicit `abort()` on a property check, or AFL++'s `AFL_CRASH_EXITCODE`. Guidance comes from coverage plus optional comparison feedback (cmplog, value profile). Research fuzzers like AFL-HR add a third, separate retention criterion (headroom).

### Cited Findings
- AFL++ output: `queue/` holds "test cases for every distinctive execution path"; `crashes/` holds "unique test cases that cause the tested program to receive a fatal signal (e.g., SIGSEGV, SIGILL, SIGABRT)", grouped by signal; `hangs/` holds timeouts. — [AFL++ afl-fuzz_approach.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/afl-fuzz_approach.md)
- AFL++ detects faults by "the first spawned process dying due to a signal". For non-crashing bugs it advises modifying targets "to call `abort()`" when a sanity check fails. — [AFL++ fuzzing_in_depth.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)
- `AFL_CRASH_EXITCODE`: "each input resulting in a `-1` return code … will be treated as if a crash had occurred. This may be beneficial if you look for higher-level faulty conditions in which your target still exits gracefully." — [AFL++ env_variables.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/env_variables.md)
- `AFL_USE_UBSAN=1` makes afl-cc add `-fsanitize=undefined -fno-sanitize-recover=undefined`, so a UBSan report aborts and lands in `crashes/`. The trap variant is commented out in the current source. — [AFL++ src/afl-cc.c](https://github.com/AFLplusplus/AFLplusplus/blob/stable/src/afl-cc.c)
- By default UBSan "prints a verbose error report and continues execution". `-fno-sanitize-recover=` exits, and `-fsanitize-trap=` executes a trap instruction (SIGILL/SIGTRAP) with no runtime needed. — [Clang UBSan docs](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
- libFuzzer exit codes: `-error_exitcode` defaults to 77, used "if libFuzzer itself (not a sanitizer) reports a bug"; `-timeout_exitcode` defaults to 70; OOM uses a fixed 71. — [libFuzzer docs](https://llvm.org/docs/LibFuzzer.html)
- AFL++ CMPLOG (Redqueen input-to-state) is "very fast and good – if the target does not transform input data before comparison". It runs as a separate `-c` binary and costs about 15% speed. — [AFL++ fuzzing_in_depth.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md)

### Inferences
- In the user's Python fuzzer, a recoverable UBSan (default) or a custom overflow hook in Unicorn, logged to a side channel, gives both signals at once. The first hit becomes a report ("crash" bucket, deduplicated by site), and the operand distance at non-hitting visits becomes guidance (headroom bucket). A non-recovering build would kill the run and lose Kvasir's trace.
- Overflows should be reported independently of Daikon refutation, so that the 5 `abs_diff` hits would have been surfaced even with no `return >= 0` invariant.

### Gaps
- I did not find documentation of a standard AFL++/libFuzzer feature that treats a *non-fatal* UBSan report as a separate "finding" class without aborting. Users typically abort or trap. Unverified whether any fork does this.
