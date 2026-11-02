# Fuzzing harness around binary-level invariant inference

Method note: in this session WebFetch could not reach arxiv.org, s3.eurecom.fr, futures.cs.utah.edu or any GitHub repo outside the project (DNS / allow-list refusals). Every finding below comes from **web-search result summaries** of the cited pages, not full-text reads. Exact tables (InvsCov throughput, FuzzFactory Table 4, Nyx Figure 6) were **not** retrieved. Claims from background knowledge that were not confirmed this session are marked **[unverified]**.

Project context (from docs/plans/review-2026-09-17.md, docs/VERIFICATION.md, docs/TOOL.md): Python + Unicorn tracer for stripped x86-64 ELFs that emits `.dtrace`. There is no input mechanism yet (`rdi=1`, argv pointer never populated), and one iteration takes ~11 s, mostly Python + JVM startup, for ~650 emulated instructions. VERIFICATION.md frames the fuzzer as "a refutation engine" for the inductive invariants.

## 1. Invariant-guided / invariant-aware fuzzing (InvsCov, Binvariants, IJON, FuzzFactory, PerfFuzz)

### Takeaway
There are two direct precedents. InvsCov (USENIX Sec 2021) is source-based, using LLVM + AFL++ + Daikon. Binvariants (FSE 2026) is binary-only and closest to this project: it learns register-level likely invariants and turns their violations into fuzzer feedback. Both use the same three steps: learn invariants on a seed corpus, freeze them, then fuzz with "violation = new coverage". Both learn offline and do not update invariants during fuzzing.

### Cited Findings
- **InvsCov**: Fioraldi, D'Elia, Balzarotti, USENIX Security 2021, "The Use of Likely Invariants as Feedback for Fuzzers". The prototype is built on LLVM and AFL++. — [USENIX](https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi)
- InvsCov mines likely invariants per basic block with Daikon and uses them to partition the program state. An input that violates an invariant counts as new state and is rewarded. — [USENIX](https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi); [thesis arXiv 2012.11182](https://arxiv.org/pdf/2012.11182)
- InvsCov reported results:
  - Finds "more and different" bugs than coverage-only AFL++, "with a reasonable performance overhead".
  - Found two vulnerabilities in a library tested daily on OSS-Fuzz that were still present in its latest version.
  - Slides say 67% of the bugs only InvsCov found were distinct (snippet truncated).
  - pcre2 is named as a target where it performed well.
  - No Magma evaluation was found.
  - Sources: [EURECOM](https://www.eurecom.fr/en/node/4901514); [USENIX slides](https://www.usenix.org/system/files/sec21_slides_fioraldi.pdf)
- InvsCov pipeline from its repo README:
  1. Compile the target with a "dump" wrapper.
  2. Run the learner over an initial corpus to mine invariants.
  3. Generate constraints.
  4. Recompile with an instrumentation wrapper.
  5. Fuzz with AFL++.

  It requires LLVM 10 and is Apache-2.0 licensed. — [github.com/eurecom-s3/invscov](https://github.com/eurecom-s3/invscov)
- InvsCov reduces throughput: the paper compares AFL vs InvsCov execution speed. The exact numbers were not retrieved. — [USENIX slides](https://www.usenix.org/system/files/sec21_slides_fioraldi.pdf)
- **Binvariants**: Zao Yang and Stefan Nagy (Utah). "Enhancing Fuzzing of Closed-Source Binary Executables via Register-Level Likely Invariants", Proc. ACM Softw. Eng. (FSE 2026), pp. 1104–1127, DOI 10.1145/3797078.
  - Claimed as the first technique to integrate likely data invariants into binary-only fuzzing.
  - Violations are exposed to the fuzzer through runtime instrumentation.
  - The abstract argues that existing invariant-guided fuzzing "universally depends on source-level abstractions".
  - Source: [ACM DOI](https://doi.org/10.1145/3797078)
- Binvariants reported results:
  - Benchmark: 25 applications (7 closed-source, 18 open-source compiled as binary-only).
  - More than 27× more unique invariant violations than coverage-only fuzzing.
  - A mean of 52% more distinct code regions exercised.
  - 143 bugs vs 137 for coverage-only, including 20 that coverage-only missed.
  - Self-reported; no independent replication found.
  - Source: [ACM DOI](https://doi.org/10.1145/3797078)
- Binvariants limitations stated in its repo: invariants are learned before fuzzing and fuzzing runs separately (no online re-learning), and only single-block invariants are supported. — [github.com/FuturesLab/Binvariants](https://github.com/FuturesLab/Binvariants)
- **IJON** (S&P 2020): a human expert inserts annotations that give the fuzzer extra state feedback. Examples:
  - Maze: each new (x, y) position counts as new state.
  - Super Mario Level 1.1: about 2.4× faster on average (76.0 → 31.2 min) with a position annotation, per the AFL++ IJON doc.

  Sources: [IJON paper](https://nyx-fuzz.com/papers/ijon.pdf); [AFL++ docs/IJON.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/IJON.md)
- Follow-ups automate IJON-style annotation:
  - SandPuppy infers state-representative variables automatically and solves Super Mario and maze levels. — [SandPuppy](https://par.nsf.gov/servlets/purl/10536810)
  - AIJon (2026 preprint) reports that LLM-generated annotations perform comparably to the human annotations on IJON's Super Mario target. — [AIJon arXiv 2609.18457](https://arxiv.org/html/2609.18457v1)
- **FuzzFactory** (OOPSLA 2019, PACMPL vol. 3, art. 174) uses "waypoints": intermediate inputs saved because a domain-specific feedback map improved.
  - Its "perf" domain re-implements PerfFuzz and is evaluated on "max hot spot" (maximum execution count of any edge).
  - Results are "similar to or slightly better than" standalone PerfFuzz.
  - Table 4 numbers were not retrieved.

  Sources: [FuzzFactory PDF](https://rohan.padhye.org/files/fuzzfactory-oopsla19.pdf); [repo](https://github.com/rohanpadhye/FuzzFactory)

### Inferences
- The project's design (learn with Daikon, then fuzz to refute) matches the InvsCov/Binvariants pipeline. The project adds a step neither paper describes: refuted invariants are reported back as false, not only used as feedback. The novelty claim should be about the refute-and-report loop and the richer Daikon invariant grammar (pointer/struct derived variables from deref.py), not about "invariants as feedback". Binvariants already owns "binary-only".
- Feedback can be FuzzFactory-shaped: one extra map indexed by invariant ID, set when that invariant is violated. In AFL++ terms, a violation hashes to a coverage-map slot, so stock scheduling rewards it (InvsCov does this **[unverified mechanism detail]**).
- Binvariants' limits point to two cheap differentiators: online re-learning (drop refuted invariants, re-run Daikon on the enlarged corpus) and procedure-level ENTER/EXIT invariants, which are Daikon-native and which the tracer already emits.
- Because the invariants come from a small seed corpus, many will be refuted quickly. Each refutation then counts as one coverage event. The violation-feedback channel must be de-duplicated by invariant ID: count each invariant once, not once per violating input.

### Gaps
- InvsCov's throughput overhead, invariant counts and per-target bug tables were not obtained (full text was unreachable).
- How Binvariants instruments binaries (QEMU vs. static rewriting) and its overhead were not obtained from the snippets.
- No measured "refutation rate over time" curve was found in any paper. This is a gap in the literature, not just in this search.

## 2. Binary-only fuzzing infrastructure: input feeding, speed, embedding Unicorn

### Takeaway
For this project the natural host is **unicornafl** (AFL++ Unicorn mode), because the emulator is already Unicorn. Its persistent-mode API passes each input to a `place_input` callback that writes bytes into emulated memory or registers. That callback is exactly where the missing argv/stdin mechanism should go. Real-process modes (QEMU and FRIDA persistent mode, LibAFL QEMU) are faster, but they would replace the tracer rather than host it.

### Cited Findings
- unicornafl `uc_afl_fuzz(uc, input_file, place_input_callback, exits, …, persistent_iters, …)`:
  - The callback receives `(uc, in_buf, in_len, iteration, data)`.
  - It returns a bool that accepts or rejects the input.
  - Optional crash-validation callback.
  - Persistent mode loops without re-forking.
  - The forkserver caches Unicorn's JIT (translated blocks), an idea taken from AFL QEMU mode.

  Sources: [Trolldemorted/unicornafl](https://github.com/Trolldemorted/unicornafl); [afl.c](https://github.com/domenukk/unicornafl/blob/master/afl.c)
- The AFL++ paper says persistent mode can reach about a 10× speedup and is recommended. — [AFL++ WOOT 2020](https://aflplus.plus/papers/aflpp-woot2020.pdf)
- AFL++ docs:
  - Unicorn cannot inherit the speedups of AFL++'s patched QEMU mode, because Unicorn is a QEMU fork without full system or user emulation.
  - "FRIDA mode and QEMU mode in persistent mode are the fastest."
  - FRIDA is usually slightly faster than QEMU.
  - Persistent QEMU mode gives a 150–300% overall speed increase ("3-8x").

  Sources: [AFL++ binary-only docs](https://aflplus.plus/docs/fuzzing_binary-only_targets/); [android mirror](https://android.googlesource.com/platform/external/AFLplusplus/+/89c4fa30/docs/fuzzing_binary-only_targets.md)
- Unicorn JIT warm-up: in firmware fuzzing on UnicornAFL, early executions run "orders of magnitude slower" than later ones until blocks are translated and cached. — [Seidel et al., USENIX Sec 2023](https://www.usenix.org/system/files/usenixsecurity23-seidel.pdf)
- In Unicorn, hooks must use API calls (`reg_read`, `mem_read`) to reach state. The authors' rewriting approach needs only about 5 instructions for context save/restore. — [Seidel et al.](https://www.usenix.org/system/files/usenixsecurity23-seidel.pdf)
- Unicorn 2.1.4 release notes: "Optimize memory handling and notdirty writes for faster memory access and snapshots, especially useful for fuzzing". — [unicorn releases](https://github.com/unicorn-engine/unicorn/releases)
- unicornafl provides a low-level C API with Rust and Python bindings. — [Seidel et al.](https://www.usenix.org/system/files/usenixsecurity23-seidel.pdf)
- One UnicornAFL user reported AMD EPYC being 3× faster than Intel Xeon. — same source; anecdotal.
- **LibAFL QEMU** (NDSS BAR 2024, Malmain et al.): a Rust library wrapping QEMU in system and user mode. It "outperforms AFL++ qemu mode both in terms of speed and coverage" on an Android library (self-reported). — [LibAFL QEMU paper](https://www.s3.eurecom.fr/docs/bar24_malmain.pdf); [NDSS](https://www.ndss-symposium.org/ndss-paper/auto-draft-432/)
- Qiling wraps Unicorn with OS/loader emulation. Its docs say to use `afl.ql_afl_fuzz` rather than importing unicornafl directly, and warn that demo code may be outdated. — [Qiling demo docs](https://docs.qiling.io/en/latest/demo/)
- **Snapshot fuzzers:**
  - Nyx (USENIX Sec 2021): fast snapshot restore "thousands of times per second", orders of magnitude faster than QEMU loadvm. — [Nyx paper](https://www.usenix.org/system/files/sec21-schumilo.pdf)
  - Nyx-Net: about 12,000 VM resets/s on small targets; incremental snapshots cost about one reset. — [Nyx-Net](https://arxiv.org/pdf/2111.03013)
  - Snapchange (AWS, KVM) restores only dirty pages. Its sample TUI shows 29,620 exec/s across cores, an illustrative figure, not a benchmark. The repo is reported archived by mid-2026 (unconfirmed). — [Snapchange architecture](https://github.com/awslabs/snapchange/blob/main/docs/ARCHITECTURE.md); [AWS blog](https://aws.amazon.com/blogs/opensource/announcing-snapchange-an-open-source-kvm-backed-snapshot-fuzzing-framework/)
  - wtf: backends are bochscpu (slowest, most precise), WHV, and KVM (fastest); Linux user-mode support is experimental. A 2021 IDA case study reported about 0.1 exec/s on bochscpu vs about 64 exec/s on KVM across 8 nodes. — [wtf](https://github.com/0vercl0k/wtf); [doar-e blog](https://doar-e.github.io/blog/2021/07/15/building-a-new-snapshot-fuzzer-fuzzing-ida/)

### Inferences
- **Input mechanism (directly fixes blocker 1):** follow the unicornafl `place_input` pattern. Before each run, restore a snapshot taken at `main` (or `_start`), then write into emulated memory:
  - argc and the argv pointer array, plus strings in a reserved region, set into `rdi`/`rsi`;
  - or an stdin buffer that a `read(0, …)` / `fgets` hook serves from;
  - or a fake file that open/read hooks serve from.

  The libc-skip mechanism in elfload/emulate already intercepts PLT calls. It needs real models for the input-related calls (read, fgets, getchar, fopen/fread, strlen/strcmp, atoi/strtol); everything else can keep the skip. This is the Qiling approach in miniature. **[design inference]**
- **Speed expectation:** 650 instructions is tiny. With startup removed, per-run cost is dominated by the per-instruction Python hooks the tracer uses (register/memory reads for each traced instruction). A coverage-only run with block hooks (or unicornafl's native edge instrumentation, which is in C) should be several orders of magnitude cheaper than the full trace path. No measurement exists for this project. Benchmarking `uc.emu_start` with and without hooks on test08 is the first experiment to run.
- Python unicornafl keeps the Python harness in the loop only for `place_input` and crash validation. Coverage is collected in C. **[unverified: from AFL++ unicorn_mode docs, not re-read this session]**
- LibAFL (Rust) is the better long-term host if custom feedbacks are needed: an invariant-violation map as a second `MapFeedback`, or a refutation objective. LibAFL composes feedbacks and observers, and has Unicorn support via a `libafl_unicorn` crate **[unverified — not confirmed this session]**.

### Gaps
- No published exec/s figure for unicornafl was found, Python or C.
- Qiling snapshot/fuzz throughput was not found.
- Whether a maintained `libafl_unicorn` exists in 2026 was not verified.

## 3. Harness generation and function-level (in-memory) fuzzing

### Takeaway
Library harness generators (FuzzGen, OSS-Fuzz-gen) all need source or headers. For stripped binaries, the practical route is function-level fuzzing in the emulator: snapshot at a function entry, write fuzzed register arguments, and back pointer arguments with fuzzer-controlled buffers laid out by the struct/array recovery that deref.py already does.

### Cited Findings
- FuzzGen (USENIX Sec 2020, Ispoglou, Austin, Mohan, Payer) runs a whole-system analysis to infer a library's API and synthesizes libFuzzer harnesses.
  - Tested on 7 Debian/AOSP libraries; found 17 previously unpatched vulnerabilities, 6 CVEs.
  - Average edge coverage 54.94% vs 48.00% for manual harnesses.
  - Manual harnesses found more bugs (29 vs 17).
  - Setup: 24 h × 5 trials with ASan.

  Sources: [FuzzGen paper](https://www.usenix.org/system/files/sec20-ispoglou.pdf); [slides](https://www.usenix.org/system/files/sec20_slides_ispoglou.pdf)
- OSS-Fuzz-gen (Google):
  - January 2024: valid LLM-generated targets for 160 C/C++ projects, with up to 29% line-coverage gain over human targets.
  - November 2024: 272 projects, 370k+ new lines covered, 26 new vulnerabilities including CVE-2024-9143 (OpenSSL). The largest single gain was 77 → 5,434 lines.
  - The repo says effectiveness varies widely by project and LLM.

  Sources: [Google Security Blog, Nov 2024](https://security.googleblog.com/2024/11/leveling-up-fuzzing-finding-more.html); [oss-fuzz-gen repo](https://github.com/google/oss-fuzz-gen)
- Harness quality degrades over time, and quality-assurance frameworks for LLM harnesses are an active topic. Findings were not extracted. — [Harness degradation, arXiv 2505.06177](https://arxiv.org/pdf/2505.06177); [Four Principles, arXiv 2605.21824](https://arxiv.org/pdf/2605.21824)
- BaseSAFE fuzzes individual baseband firmware functions/tasks in Unicorn via unicornafl. This is a precedent for function-level emulator fuzzing of binary code. — [BaseSAFE, arXiv 2005.07797](https://arxiv.org/pdf/2005.07797)

### Inferences
- **Argument synthesis for function-level fuzzing:** use what the tracer already infers. infer.py gives arity and widths; deref.py gives pointer targets with struct/array layouts.
  - Map scalar arguments straight from fuzz bytes.
  - For each inferred pointer argument, allocate in the emulated heap a region of the recovered size, fill it from fuzz bytes, and recurse one level for inferred pointer fields.
  - The ENTER-site invariants Daikon learned (e.g. `arg1 != null`, `arg2 >= 0`, `size(arg1[]) == arg2`) are themselves a precondition spec. Generate inputs that satisfy them for "valid" calls, and deliberately violate them for robustness probing.
- Function-level fuzzing has a false-positive risk: violations from impossible argument combinations refute invariants that hold in every real call. Refutations from function-level fuzzing should be labelled "context-free" and kept separate from whole-program refutations. This matches the project's tier/D-class honesty framing in VERIFICATION.md.
- LLMs can help mainly with what an LLM can see in a decompiled binary: guessing input formats and seed files, and IJON-style annotation points (AIJon precedent, §1). They are not a substitute for layout recovery.

### Gaps
- No published system was found that generates harnesses for stripped binaries from inferred types. Precedents may exist, e.g. GraphFuzz, Hopper, "binary harness" work **[unverified, not searched]**.

## 4. Making an emulator-based tracer fast enough

### Takeaway
The 11 s per iteration is almost all fixed startup cost. Making both processes long-lived removes most of it: a resident Python emulator with snapshot restore, and a resident or batched Daikon JVM. Then split each execution into a cheap coverage path for every input and an expensive full-trace path only for a small sample of inputs.

### Cited Findings
- Daikon can stream traces:
  - Front ends can write to a FIFO or stdout piped into Daikon (`kvasir-dtrace --dtrace-file=- … | java daikon.Daikon -`).
  - Chicory's `--daikon-online` avoids writing a trace file.
  - Daikon has a server mode that reads trace files from a directory as they appear (sorted) until a file ending in `.end`, then outputs invariants.

  Sources: [Daikon manual, Running Daikon](https://plse.cs.washington.edu/daikon/download/doc/daikon/Running-Daikon.html); [Daikon tool paper, SCP 2007](https://homes.cs.washington.edu/~mernst/pubs/daikon-tool-scp2007.pdf)
- Daikon's `--conf_limit 0` prints every property that has not been falsified. This is useful for seeing which invariants survived a run, as opposed to which were justified. — [Daikon Troubleshooting](https://plse.cs.washington.edu/daikon/download/doc/daikon/Troubleshooting.html)
- The Daikon manual lists an InvariantChecker tool in its index. Its exact interface was not retrieved this session. — [Daikon General Index](https://plse.cs.washington.edu/daikon/download/doc/daikon/General-Index.html)
- Unicorn snapshot support and JIT caching: see §2 (Unicorn 2.1.4 notes; unicornafl forkserver JIT cache; warm-up cost).

### Inferences
- **Remove JVM startup from the loop:** Daikon should not run for each input. Options, cheapest first:
  - (a) Learn invariants once from N traces, then check new traces against the serialized `.inv.gz` with InvariantChecker. **[unverified interface: from background knowledge, it takes an invariant file plus dtrace files and reports violations; confirm in the local daikon checkout's manual.]**
  - (b) Better still, compile the frozen invariant set into a Python predicate checker inside the emulator process. This works because the invariants are simple and the derived variables are known. It gives in-process refutation with no JVM at all, which is the InvsCov/Binvariants design (the learn-time tool is separate from the fuzz-time checker).
  - (c) Re-learn periodically in batch with one long-lived JVM (server mode) over the accumulated surviving-and-refuting corpus.
- **Remove Python startup:** a long-lived process takes one ELF load and one `Uc` instance, and calls `context_save()` plus a memory snapshot at the entry point. Each iteration then does: restore registers and dirty pages → `place_input` → `emu_start`. Unicorn 2.x `uc_ctl` snapshot APIs, and the 2.1.4 dirty-page optimizations, make memory restore cheap **[exact API names unverified]**.
- **Two-tier execution:**
  - Fast path for every input: block/edge coverage plus the in-process invariant checker on the few program points with frozen invariants. No dtrace serialization.
  - Slow path: full tracing with all derived variables and dtrace writing, only for inputs that (i) hit new coverage, (ii) violate an invariant, or (iii) are selected by a sampling policy.

  This mirrors "coverage-guided tracing" (Full-Speed Fuzzing, Nagy & Hicks, S&P 2019 **[unverified details]**): pay tracing cost only for inputs that are already interesting.
- Expected scale: 650 instructions with block-level hooks in Python should take sub-millisecond to low-ms per run. Full per-instruction tracing will be far slower, but rare. Even 100 exec/s in pure Python is about 1,000× better than 11 s and enough for refutation on these small corpus binaries. **[estimate, not measured]**

### Gaps
- InvariantChecker's exact CLI and output format were not verified (the manual page could not be fetched; Daikon is not checked out locally).
- No published measurement of Unicorn Python-hook overhead per instruction was found this session.

## 5. Oracles: refuted invariants as signals, differential testing

### Takeaway
An invariant violation does two jobs. It is a coverage-like novelty signal that keeps the input (InvsCov, Binvariants), and it is a refutation verdict on the invariant (this project's goal). Neither precedent treats violations as bug oracles by themselves; bugs are still found by crashes and sanitizers. Violations should therefore be triaged, not reported as bugs.

### Cited Findings
- InvsCov and Binvariants use violations as feedback to find bugs. Binvariants found 20 bugs that coverage missed, but bug detection was still by crash/sanitizer, not by the violation itself **[the "not by violation" part is an inference from snippets]**. — [ACM DOI Binvariants](https://doi.org/10.1145/3797078); [USENIX InvsCov](https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi)
- FuzzFactory's domains (perf, memory allocation, comparisons) show feedback that maximizes a quantity rather than reaching a boolean state. A PerfFuzz-style "maximize per-edge count" domain matched dedicated PerfFuzz. — [FuzzFactory](https://rohan.padhye.org/files/fuzzfactory-oopsla19.pdf)
- IJON-style "max" annotations steer toward extreme values of a variable. — [AFL++ IJON.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/IJON.md)

### Inferences
- **Refutation-directed scheduling:** for invariants of the form `x <= c`, `x != 0` or `x == y`, use an IJON/FuzzFactory "max distance toward violation" feedback. For example, maximize `x` for `x <= c`, or minimize `|x-y|` for `x == y`. This turns a boolean refutation target into a gradient, the same idea as FuzzFactory's cmp domain. It directly serves "try to refute".
- **Trust score:** record for each invariant the number of fuzzer-generated executions at its program point that it survived, and the coverage diversity of those executions. That gives the "surviving invariant is more trustworthy" metric VERIFICATION.md wants. Daikon's statistical confidence measures only the learn-time samples.
- **Differential testing between traces:**
  - (i) Compare this tracer against Kvasir on the same inputs. test.sh already does this; the fuzzer can drive it to find tracer/Kvasir disagreements, which are bugs in the tracer, not the target.
  - (ii) Compare the emulated run against a native run (ptrace/QEMU-user) for the same input. Divergence in exit code or output exposes emulator or libc-model infidelity, a known risk of skipping libc calls.
  - (iii) Compare invariant sets learned from seed corpus vs. fuzzed corpus. The diff is the list of refuted invariants.
- Pitfall: with modelled libc and stub argv, a refutation may be caused by the emulator model rather than by the program. Validate a refuting input by re-running it on the slow path, and preferably confirm it natively, before declaring an invariant false (analogous to unicornafl's crash-validation callback).

### Gaps
- No paper was found that evaluates "invariant refutation" itself as the output metric, i.e. the precision of Daikon invariants after fuzzing. This appears to be open; at most, invariant-filtering work in the testing literature exists **[unverified]**.
