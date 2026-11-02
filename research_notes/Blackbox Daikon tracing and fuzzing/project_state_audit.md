# Project state audit: our black-box Daikon tracer, accuracy gaps and fuzzing-harness gaps

Sources are the local repository files (paths relative to /home/user/daikon_stuff; line numbers as of 2026-11-02, HEAD 2137177). No web sources were needed. One timing measurement was taken by this researcher and is labelled as such.

## Q1. What does the tracer recover today, and how?

### Takeaway
The tracer runs a stripped x86-64 ELF under Unicorn starting at `main`, gets every fact from machine state (register use-before-def, address-range pointer classification, read/write footprints, malloc sizes, `.symtab`/section headers for globals), and writes a Daikon `.dtrace`. It is organised as an opt-in tier ladder 0-9. It scores 65/92/76 P/R/F1 on its own 10 fixtures but only 22/17/19 (24/17/20 with the strided-access discriminator) on Daikon's 29-program Kvasir suite.

### Cited Findings
- Pipeline: binary -> Unicorn emulation -> .dtrace -> Daikon (Java). Kvasir (Valgrind plus DWARF) is the reference oracle; the tracer has to recover names, types, layouts and bounds "from machine state alone" — [docs/TOOL.md:9-22](docs/TOOL.md)
- Module layout: log, schema, memmap, alloc, writer, deref, infer are pure (no third-party imports); elfload uses pyelftools; emulate.py (1937 lines now, documented as 1288) is the Unicorn/Capstone driver. Purity is enforced by `tests_py/test_purity.py` via a subprocess meta_path blocker — [docs/TOOL.md:44-82](docs/TOOL.md); line counts from `wc -l scripts/tracer/*.py`
- Tier ladder (every tier opt-in via `--tier N`, cumulative; lower tiers stay byte-identical): 0 fixed 11-slot register/stack window; 1 `subexit`/`EXIT0`/nonce; 2 arity via use-before-def; 3 return value, signed values, comparability; 4 skipped (measured no-op); 5 malloc/free model; 6 dereference/struct fields; 7 array bounds; 8 globals; 9 float args/returns — [docs/TOOL.md:86-101](docs/TOOL.md); [docs/plans/README.md:7-24](docs/plans/README.md). The CLI default is `--tier 0` — [scripts/tracer/cli.py:105](scripts/tracer/cli.py)
- Phase 8 added five mechanisms on top of tier 7: array detection from allocation size, signedness from consuming opcodes, pointer-valued returns, a global access map (`--infer-from-caller`), and definedness poisoning (`--poison-uninitialized`) — [docs/TOOL.md:103-108](docs/TOOL.md)
- Mechanisms, with code:
  - Arity, widths, spills, signedness and void detection: `ArityTracker` [scripts/tracer/infer.py:184-404](scripts/tracer/infer.py), fed per instruction from `_note_arity` [scripts/tracer/emulate.py:1086](scripts/tracer/emulate.py); EXIT argument values are read from -O0 spill slots, not from clobbered registers, in `_read_exit_args` [scripts/tracer/emulate.py:1042](scripts/tracer/emulate.py)
  - Pointer classification by address range against the live map (image/stack/heap): `MemoryMap.classify` and `classify_slot` [scripts/tracer/memmap.py:38,56](scripts/tracer/memmap.py). NULL is neutral in aggregation (review bug B1, fixed) — [docs/plans/review-2026-09-17.md:16-39](docs/plans/review-2026-09-17.md)
  - Struct/array layout from read and write footprints (the WRITE hook was added for out-params, B2): `FootprintTracker`, `GlobalAccessMap`, `uniform_layout`, `array_width_from_allocation`, `strided_access_seen`, `looks_like_array` [scripts/tracer/deref.py:25-312](scripts/tracer/deref.py); hook registration [scripts/tracer/emulate.py:1904-1908](scripts/tracer/emulate.py)
  - Array vs struct: (a) a correlated length argument; (b) `length*width == allocation size` on every call; (c) the strided-access discriminator (one PC touching two or more offsets means array). (c) is on by default and "cost nothing": 148 fewer facts, 20 more matched, suite precision 22% -> 24% — [docs/TOOL.md:374-454](docs/TOOL.md)
  - Heap model: PLT resolution survives stripping (`.rela.plt` plus a `ff 25` scan) [scripts/tracer/elfload.py:258](scripts/tracer/elfload.py); arena that never reuses memory, chosen because Kvasir/Valgrind gives 10 distinct addresses for 10 malloc/free cycles [docs/TOOL.md:346-367](docs/TOOL.md); interception at the call site [scripts/tracer/emulate.py:354-391,1352-1366](scripts/tracer/emulate.py)
  - Globals: data-section bounds from section headers plus `.symtab` extents when present (`--scan-prologues` forces the stripped path) [scripts/tracer/emulate.py:294-313](scripts/tracer/emulate.py); `GlobalTable` [scripts/tracer/globalvars.py:153-327](scripts/tracer/globalvars.py)
  - Uninitialised memory: fill with 0xAB and emit `nonsensical` (modbit 2) when the poison survives, behind a flag [scripts/tracer/emulate.py:269-274](scripts/tracer/emulate.py); [docs/TOOL.md:456-475](docs/TOOL.md)
  - Writer: `modbit_for` returns "2" only for `nonsensical` and "1" for everything else [scripts/tracer/writer.py:52-53](scripts/tracer/writer.py); `validate()` runs on every `close()` (it checks enclosing-var presence, var-kind field relative names and duplicates) [scripts/tracer/writer.py:125](scripts/tracer/writer.py); [docs/plans/phase10.md:53-68](docs/plans/phase10.md)
  - `--layouts N` re-runs with the stack and heap relocated by 16 MiB so that layout-dependent invariants break — [scripts/tracer/emulate.py:76-79,1876-1884](scripts/tracer/emulate.py)
- Headline numbers:
  - Own 10-fixture corpus, tier 7 + `--infer-unobserved-fields --poison-uninitialized`: 239 facts, 155 matched, P 65%, R 92%, F1 76%; 8/10 binaries at 100% recall — [docs/EVALUATION.md:13-50](docs/EVALUATION.md)
  - Kvasir suite (29 no-input programs): tier 7 13/4/6; tier 8 3576 facts, 802 matched, 22/17/19; tier 8 + strided discriminator 3428 facts, 822 matched, 24/17/20 — [docs/EVALUATION-KVASIR-SUITE.md:449-460](docs/EVALUATION-KVASIR-SUITE.md)
- Fidelity: 198/198 program points have identical sample counts versus Kvasir on real hardware. Soundness audit at tier 8: 4217 facts, 1001 TRUE, 0 FALSE, 3216 (76.3%) undecidable by the checker — [docs/VERIFICATION.md:108-153](docs/VERIFICATION.md)
- Test suite: 356 `def test` functions in tests_py (count taken by grep); the docs cite 333, then 384 — [docs/TOOL.md:65-66](docs/TOOL.md); [docs/EVALUATION-KVASIR-SUITE.md:372](docs/EVALUATION-KVASIR-SUITE.md)

### Inferences
- The suite gap between 822 matched and the oracle's 4777-4778 facts is mostly a vocabulary problem, not an observation problem. In the docs' words: "observation is perfect and its vocabulary is small" — [docs/EVALUATION-KVASIR-SUITE.md:390-394](docs/EVALUATION-KVASIR-SUITE.md)
- The grep count (356) sits between the two documented totals (333 and 384), so the docs' test counts are not current. Parametrised tests could explain the difference. Not verified.

### Gaps
- No doc gives per-tier numbers on the suite for tiers 5-7 individually.
- 32-bit has never been executed above tier 1 — [docs/plans/review-2026-09-17.md:91-93](docs/plans/review-2026-09-17.md)

## Q2. Documented accuracy gaps: size, status and planned remedy (which are largest, which are cheapest?)

### Takeaway
After tier 8 there are 3975 oracle misses. 88.6% of them are type information already present in the execution. The largest block is pointers inside structs at depth 2 or more (2142, 53.9%), then pointer/array globals (809, 20.4%) and struct globals (355, 8.9%). The cheap, already-built work is mostly flag-gated or measured harmful. The best tested cheap win, the strided discriminator, is already default.

### Cited Findings
- Phase 10 classification of all 3975 remaining oracle misses, by the single missing fact — [docs/plans/phase10.md:76-92](docs/plans/phase10.md):

| count | share | missing fact | observable? | status / remedy |
|---|---|---|---|---|
| 2142 | 53.9% | pointer inside a struct, 2+ levels deep | yes | Mechanism A (recursive walker, depth 2, visited-set): **not started**; estimated ~3200 facts (later ~2400 in the order table) — [phase10.md:178-232,290-296](docs/plans/phase10.md) |
| 809 | 20.4% | global that is a pointer/array -> sequence | yes | B `--deref-globals`: **landed, off by default** (+176 matched, recall 17->20%, precision 22->16%, facts 3576->6111) — [phase10.md:12-23](docs/plans/phase10.md) |
| 355 | 8.9% | bytes are a struct with members | yes | C `--struct-globals`: **measured harmful** (-123 matched, P 17%, F1 15%; struct shape 0/8) — [phase10.md:25-51](docs/plans/phase10.md) |
| 215 | 5.4% | local pointer/array -> sequence | yes | covered by A — [phase10.md:86](docs/plans/phase10.md) |
| 254 | 6.4% | other/plain scalar | mixed | — |
| 110 | 2.8% | 8 bytes are a double, not a long | only via a consuming opcode | D runtime SSE tagging: **not started**; the static scan found 0 hits, redesigned; "well under 110" — [phase10.md:154-175,261-273](docs/plans/phase10.md) |
| 90 | 2.3% | `char*` is a string | only via its target | E `.rodata` strings: **not started**, to be flag-gated; "cheap, self-limiting" — [phase10.md:275-284](docs/plans/phase10.md) |

- The top four rows are "ONE bug": the tracer already knows whether a value is a pointer (memmap) and what is behind it (GlobalAccessMap). What is missing is recursion; the deref path is special-cased per root (`_pointee_layout`, `_return_pointee_layout`, `_global_specs`) — [docs/plans/phase10.md:94-107,206-209](docs/plans/phase10.md); code at [scripts/tracer/emulate.py:1542,1583,569](scripts/tracer/emulate.py)
- Depth distribution of oracle facts: depth 0 32.0%, 1 30.8%, 2 25.9%, 3 4.4%, 4+ 6.9%. A depth limit of 2 covers 88%, a limit of 3 covers 93% — [docs/plans/phase10.md:113-129](docs/plans/phase10.md). 65 of the 85 globals emitted are pointers printed as integers — [phase10.md:131-135](docs/plans/phase10.md). There are cycles (`n1->next->prev`), so a visited-set is mandatory — [phase10.md:137-142](docs/plans/phase10.md)
- A's acceptance criterion: NestedStructTest (565 oracle facts, 10 matched) must exceed 150 — [docs/plans/phase10.md:230-232](docs/plans/phase10.md)
- Earlier (pre-tier-8) decomposition of all 4778 oracle facts: 80% globals not emitted; 9% 2+ deref levels; ~4% wrong noun (array as struct, by-value struct as N args); ~2% functions never touching their args; ~1% floats/strings/multi-level pointers; ~4% matched — [docs/EVALUATION-KVASIR-SUITE.md:378-387](docs/EVALUATION-KVASIR-SUITE.md)
- Information-theoretic residue: about 5% of the oracle (a double never used as a double, an unsigned never compared or shifted, interleaving of mixed int/float args, depth 3+ is 7%, names) — [docs/plans/phase10.md:333-341](docs/plans/phase10.md); [docs/VERIFICATION.md:213-218](docs/VERIFICATION.md)
- Other stated limits (all open) — [docs/TOOL.md:642-687](docs/TOOL.md):
  - by-value struct breaks arity: a 252-byte param is seen as 18 args; 6/6 wrong on the suite. Flagged as "the one way to hand a consumer something actively wrong" — [docs/EVALUATION-KVASIR-SUITE.md:414-416](docs/EVALUATION-KVASIR-SUITE.md)
  - tier 9 mixed int/float arg order (FloatTest +9 facts, everything else -12, so opt-in)
  - fixed-size array without a length param stays a struct
  - one deref level only (`char **`)
  - dead trailing args invisible at -O1+ (corpus is all -O0)
  - global types not recovered (`double[5]` reads as five longs)
- Formal-methods measurement on 72 globals: 0/72 shapes are forced by extent alone; 16/72 with extent plus a uniform 4-byte width. The tracer's shape is 88% correct, but structs are 0/8 (all called arrays) — [docs/FORMAL-METHODS.md:33-60](docs/FORMAL-METHODS.md)
- Fixture-corpus open items in value order — [docs/EVALUATION.md:450-475](docs/EVALUATION.md):
  1. whether to default-on `--infer-unobserved-fields` and `--poison-uninitialized` (+11 matched, +3 precision points, no measured downside; a policy call)
  2. bound a stack pointee (worth 6 facts, costs 136 false ones today)
  3. modbits hardcoded to 1, "the clearest remaining precision lever" (would suppress the `argN == orig(argN)` class)
  4. attribute an access to every matching pointer, not just the first (the memcpy two-buffer blind spot; `_hook_mem_deref` returns after the first match [review-2026-09-17.md:94-96](docs/plans/review-2026-09-17.md))
  5. make the 64-byte `DEREF_WINDOW` configurable ([scripts/tracer/emulate.py:69-73](scripts/tracer/emulate.py))
- Indirect calls are "named by call site rather than target" — [docs/plans/review-2026-09-17.md:140](docs/plans/review-2026-09-17.md). In code, any `call` whose operand is not a literal hex address (i.e., indirect) gets `target=None` and is skipped with RAX=0 when `--skip-unknown-calls` is on (the default) — [scripts/tracer/emulate.py:1352-1385](scripts/tracer/emulate.py)
- Precision cost of B scales with its output: 6111 facts for +176 matched. Phase 10 warns that A "should be expected to be worse, not better" for precision and must be built behind a flag and measured at depth 1 first — [docs/plans/phase10.md:180-185](docs/plans/phase10.md)

### Inferences
- **Largest by fact count:** depth-2+ struct pointers (2142), then pointer globals (809), struct globals (355), local sequences (215). All four depend on the unbuilt recursive walker (A) plus a layout function shared by B and C.
- **Cheapest:**
  - Strings E (90 facts, independent; the docs call it cheap) and runtime float tagging D (under 110; reuses tier-9 SSE width logic). Both are small in absolute terms.
  - Defaulting the two fixture flags (+11 matched, +3 points of precision on the fixtures) is a one-line policy change. Its suite effect is not documented separately.
  - Modbits is the documented precision lever with no measured size.
- B's 809-fact block yields only +176 matched at a 6-point precision cost, so it already sits below the 20% floor (16%). Any harness that wants B needs a precision-preserving filter first, for example certification of entailed facts per FORMAL-METHODS (d).

### Gaps
- No measured size exists for modbits, indirect-call naming, or the memcpy multi-pointer attribution on the suite.
- Mechanism A's real yield and precision are unknown (not started). The ~3200 vs ~2400 estimates in phase10.md are inconsistent.

## Q3. What blocks a fuzzing harness: input, libc/syscalls, per-iteration cost, determinism, data flow

### Takeaway
There is no program-input mechanism. Emulation starts directly at `main` with RDI=1 and an argv pointer into unpopulated (zeroed) stack. Every non-allocator external call, and every indirect call, is skipped with RAX forced to 0. There is no syscall handling at all, and unmapped accesses silently get zero pages. The ~11 s per iteration is documented only as "almost entirely Python and JVM startup" against ~650 emulated instructions; the per-iteration loop is a fresh Python process plus a fresh Daikon JVM over a file.

### Cited Findings
- **Input.** "No input mechanism. `rdi=1` with an argv pointer that is never populated, and no fixture reads input. The fuzzing loop cannot start." — [docs/plans/review-2026-09-17.md:133-134](docs/plans/review-2026-09-17.md). In code, `_setup_memory` writes RSP=RBP=stack_top, RDI=1, RSI=stack_top-0x100, RDX=stack_top-0x200, and nothing is written at those addresses (fresh Unicorn pages are zero, or 0xAB under poisoning) — [scripts/tracer/emulate.py:276-287](scripts/tracer/emulate.py)
- 17 of the 46 Kvasir-suite programs (bc, gzip, bzip2, perl, space, tcas, replace, print_tokens, tot_info, wordplay) are unmeasured because they need argv, stdin or data files — "the closest thing available to the fuzzing target" — [docs/EVALUATION-KVASIR-SUITE.md:420-425](docs/EVALUATION-KVASIR-SUITE.md). The REA plan notes "the tracer reached 6 program points in `cat`" because ReSym binaries need input — [docs/plans/rea-type-checker.md:156-162](docs/plans/rea-type-checker.md)
- **Start point.** The start is `--start-func` (default main) by symbol, otherwise main recovered by emulating `_start` for 200 instructions and reading RDI at the `__libc_start_main` call, otherwise the ELF entry point — [scripts/tracer/emulate.py:82-160,1810-1858](scripts/tracer/emulate.py). libc initialisation (`__libc_start_main`, TLS, stdio) is never run, and emulation stops when the start function returns — [scripts/tracer/emulate.py:1335-1349](scripts/tracer/emulate.py)
- **libc calls.**
  - Only `malloc`/`calloc`/`realloc`/`free` are modelled, and only at tier 5+. The rationale: "printf and friends stay generically skipped - modelling output has no bearing on invariants" — [scripts/tracer/emulate.py:59-61](scripts/tracer/emulate.py); resolution via `resolve_plt_stubs` [scripts/tracer/emulate.py:1782-1795](scripts/tracer/emulate.py)
  - Any other call to an address outside the traced function set is skipped: RAX=0, RIP=next — [scripts/tracer/emulate.py:1352-1385](scripts/tracer/emulate.py). `--no-skip-unknown-calls` disables this — [scripts/tracer/cli.py:86](scripts/tracer/cli.py)
  - Consequences: `strlen`, `strcmp`, `fgets`, `read`, `atoi` and the like all "return 0" and have no memory effects. A NULL from the allocator is logged when the arena is exhausted — [scripts/tracer/emulate.py:383-384](scripts/tracer/emulate.py)
- **Syscalls.** emulate.py registers no `UC_HOOK_INTR` or syscall instruction hook. The only hooks are UC_HOOK_CODE, MEM_READ/WRITE (debug and deref) and the unmapped-access handler — [scripts/tracer/emulate.py:22-25,1901-1912](scripts/tracer/emulate.py) (a grep for "syscall" finds nothing). A raw `syscall` instruction (e.g., inline or from statically linked code) therefore runs with no OS model.
- **Unmapped memory.** `_hook_mem_unmapped` maps a fresh zero page at any faulting address and continues — [scripts/tracer/emulate.py:1406-1413](scripts/tracer/emulate.py). For a fuzzer this hides wild pointer dereferences that would be a crash natively.
- **Limits.** `--max-insns` default 200,000; `--timeout` default 10 s (passed to `emu_start` in µs); stack 1 MiB at 0x7fff00000000; heap 1 MiB at 0x20000000 — [scripts/tracer/cli.py:78-84,134-140](scripts/tracer/cli.py); [scripts/tracer/emulate.py:1886,1915](scripts/tracer/emulate.py). The binary must be built `-no-pie` — [docs/EVALUATION-KVASIR-SUITE.md:24-27](docs/EVALUATION-KVASIR-SUITE.md)
- **Per-iteration cost.**
  - "~11s per iteration, almost entirely Python and JVM startup against ~650 instructions of actual emulation" — [docs/plans/review-2026-09-17.md:135-136](docs/plans/review-2026-09-17.md); [docs/plans/README.md:38-40](docs/plans/README.md)
  - Emulation itself is "642 instructions per binary — roughly 5ms"; Capstone `detail=True` costs 5x (640k -> 128k insn/s); the 200k-insn cap is about 1.6 s — [docs/plans/phase2.md:156-161](docs/plans/phase2.md); [scripts/tracer/emulate.py:316-321](scripts/tracer/emulate.py)
  - The docs separately cite "2.5-second startup" for running the emulator on a binary — [docs/TOOL.md:65](docs/TOOL.md)
  - The hot path is a Python `UC_HOOK_CODE` callback on every instruction that re-reads and re-disassembles the instruction with Capstone, plus Python MEM_READ/WRITE hooks at tier 6+ — [scripts/tracer/emulate.py:1208-1220,1904-1908](scripts/tracer/emulate.py)
  - The whole-suite run "already takes ~15 minutes" — [docs/plans/phase10.md:311-312](docs/plans/phase10.md)
  - Daikon on the oracle's larger programs takes 7-45 s per run (tot_info 8 s, space 45 s) — [docs/EVALUATION-KVASIR-SUITE.md:513-521](docs/EVALUATION-KVASIR-SUITE.md)
- **Researcher's own measurement (this machine, 2026-11-02, not a project figure).** Tier-7 trace of tests/test08.exe: 0.40 s wall, 548 instructions, 1 skipped call, 42 samples. A cold `import unicorn, capstone, elftools` took 1.12 s. Daikon/JVM time could not be measured because no Daikon build is present under daikon/. So the Python side is ≤ ~1.5 s, and the rest of the ~11 s is presumably JVM startup plus Daikon inference. That attribution is an inference, not a documented split.
- **Determinism.** Two runs are byte-identical (phase-0 gate, a standing e2e test) — [docs/plans/phase0.md:75-79](docs/plans/phase0.md); [docs/VERIFICATION.md:156-160](docs/VERIFICATION.md). Goldens pin tiers 0, 1, 2, 3, 5 and 6 for test08 (`tests_py/golden/test08.tier{0,1,2,3,5,6}.dtrace`). A single execution is deterministic, which is why `--layouts` exists: constant incidental addresses would otherwise look like invariants — [scripts/tracer/emulate.py:1876-1884](scripts/tracer/emulate.py)
- **Trace and invariant flow.**
  - The tracer buffers samples in `self.pending` and decides schemas in `_finalize` after all layouts ([scripts/tracer/emulate.py:1711,1917-1922](scripts/tracer/emulate.py)), then writes one .dtrace file
  - `test.sh` runs tracer -> dtrace -> `java daikon.Daikon` per binary, with optional Kvasir, writing `traces/` and `invariants/` (the .inv.gz goes to a temp dir) — [test.sh:1-45,140-147](test.sh)
  - No in-process or incremental path exists: each iteration is a file handoff between two fresh processes
- **Oracle scaling.** Trace size tracks samples x variables (print_tokens: 565 LOC -> 14.5 MB, 5261 samples, 501 vars); "Fuzzing multiplies the sample count directly". The tracer's own scaling past ~650 instructions is "untested and will bite sooner" — [docs/EVALUATION-KVASIR-SUITE.md:513-578](docs/EVALUATION-KVASIR-SUITE.md)

### Inferences
- A harness needs, at minimum:
  1. a populated argv/envp (and auxv if starting at `_start`) or a stdin/file model
  2. libc stubs with real semantics for input-consuming and string functions (read/fgets/getc/strlen/strcmp/atoi), because RAX=0 means "EOF/empty/equal" and silently steers control flow
  3. a syscall hook if any path reaches raw syscalls
  4. a policy for unmapped access (treat as crash, not as a zero page)
  5. a persistent process (snapshot/restore of the Unicorn context instead of re-loading) so Python import and ELF parse are paid once
  6. batching many inputs into one .dtrace per Daikon run, or a long-lived JVM, since JVM plus Daikon dominates
- Determinism is a strength for a harness (reproducible crashes). The default `--layouts 1` makes address-valued facts spurious unless `--layouts` > 1 is used.

### Gaps
- No documented breakdown of the 11 s (how much is JVM startup vs Daikon inference vs Python import vs ELF parse). It could not be re-measured here without Daikon.
- No doc covers how the tracer behaves on programs that run beyond 200k instructions, or on tcas/replace-sized inputs.

## Q4. Existing tooling a harness could reuse

### Takeaway
There is a content-based scorer, a decidable soundness audit, a trace-format validator, goldens and a determinism gate, a corpus runner, a REA/Ghidra collection and scoring harness, and a static p-code type checker. The checker met all three of its pre-set criteria.

### Cited Findings
- `scripts/score_invariants.py`: maps tracer names to Kvasir's using DWARF at scoring time only, canonicalises linear relations, set-compares, and separates oracle defects (`--show-oracle-bugs`) — [scripts/score_invariants.py:1-29](scripts/score_invariants.py). Eight scorer bugs were found, all one-directional (each made the tracer look worse), so the scores are lower bounds; replacing canonicalisation with a decision procedure or SMT is called "the highest-value formalization" — [docs/VERIFICATION.md:166-186](docs/VERIFICATION.md)
- `scripts/audit_soundness.py DIR`: checks that every emitted fact is TRUE on our own recorded samples. It handles equalities, `one of`, comparisons, `has only one value` and linear relations, but not sequence predicates. It found the `sign_extend` >= 2^63 bug — [scripts/audit_soundness.py:1-25](scripts/audit_soundness.py); [docs/VERIFICATION.md:108-140](docs/VERIFICATION.md)
- `DaikonTraceWriter.validate()` runs on every close — [scripts/tracer/writer.py:125,175](scripts/tracer/writer.py). Format contract rules (value in rep-type range, enclosing-var present, sample length, modbit 2 only for nonsensical, nonce not declared) — [docs/VERIFICATION.md:188-205](docs/VERIFICATION.md)
- Goldens in `tests_py/golden/` (test08 tiers 0, 1, 2, 3, 5, 6); tier 0 is the frozen baseline — [docs/plans/README.md:46-48](docs/plans/README.md). e2e tests per tier: `tests_py/test_e2e_tier{1,2,3,5,6,7}.py`, `test_phase8.py`, `test_cli_compat.py` and others (directory listing)
- `test.sh`: corpus runner (tracer + optional Kvasir + Daikon), per-tier output names, `--` passthrough to the tracer; refuses `--tier` in the passthrough so filenames stay honest — [test.sh:1-110](test.sh)
- REA harness ([scripts/rea_eval/](scripts/rea_eval/)):
  - `ground_truth.py` is the only DWARF reader and keys records by address
  - `collect.py` / `collect_pcode.py` drive one `rea mcp` import per binary, passing addresses only; output is cached and resumable
  - `mcp_client.py` is a stdio JSON-RPC client
  - `observe.py` is a pure p-code -> per-variable evidence pass
  - `check.py` holds rules R1, R3-R7 (R2 width and R8 void are not implemented because the evidence would be circular)
  - `score.py` scores kind/size/sign/pointee and counts `undefinedN` as abstain
  - `libc_protos.py` holds libc arg/return classes
  - Sources: file headers at [scripts/rea_eval/check.py:1-25](scripts/rea_eval/check.py), [collect.py:1-15](scripts/rea_eval/collect.py), [observe.py:1-30](scripts/rea_eval/observe.py), [score.py:1-18](scripts/rea_eval/score.py), [ground_truth.py:1-12](scripts/rea_eval/ground_truth.py)
- REA baseline on ReSym (94 binaries, 18,551 functions, 44,366 params, 3,363 globals): Ghidra-through-REA is fully exact for ~22% of params, ~49% of returns, ~6% of globals. It is confidently wrong about kind for 22% of params, mostly pointer-called-`long` (8,977) and never building structs (pointee right 35%) — [docs/plans/rea-type-checker.md:3-12](docs/plans/rea-type-checker.md)
- Stage 1 checker result (2026-10-18) — [docs/plans/rea-type-checker.md:104-134](docs/plans/rea-type-checker.md):
  - p-code collected for 24,428 functions; 0.36% errored or truncated
  - Wrong answers caught: params 63.8%, returns 16.9%, globals 87.4%. False rejects: 0.7%, 2.9%, 0.7%
  - Pointer-called-integer caught: 86.2% of 8,969 params and 37.7% of 416 returns
  - Wrong kind before -> after: params 22.9% -> 4.5%, returns 8.2% -> 6.7%, globals 6.6% -> 0.8%
  - Any wrong detail before -> after: params 34.4% -> 12.4%
  - Where Ghidra abstained, evidence proposes a kind for 32.8% of params at 95.9% right
  - Per-rule params: R1 7,894 catches / 45 false rejects; R6 1,080/10; R3 408/42
  - Hand check: 20/20 correct
  - Weak spot: returns (3,153 of 4,806 have no evidence; R3 from callers is 137/78)
- Unbuilt next stages: Stage 2 is an AI proposes / checker verifies loop (needs an API key); Stage 3 is a run-time checker using the tracer, gated on coverage because ReSym binaries need input; Stage 4 is a recompile spot-check — [docs/plans/rea-type-checker.md:138-168](docs/plans/rea-type-checker.md). The planned write-up `docs/REA-EVALUATION.md` does not exist yet (ls). Data sits in gitignored `bench/`.
- Formal-methods proposals relevant to a fuzzer: quantify, constrain, certify and bracket; (d) a Houdini-style WP+SMT certification of linear facts is "the fuzzing-loop payoff", telling the fuzzer where budget can pay off — [docs/FORMAL-METHODS.md:14-25,143-156,223](docs/FORMAL-METHODS.md)

### Inferences
- A fuzzing harness can reuse `audit_soundness.py` as a per-iteration sanity gate, `score_invariants.py` for regression against Kvasir, `validate()` to stop the silent "8-fact stub" failure mode, and the checker's evidence and proposals as a static prior on which arguments are pointers or strings when generating inputs and stubs.
- The tracer-as-runtime-checker (Stage 3) and the fuzzing harness share the same blocker: input.

### Gaps
- The tracer's facts have not been scored against the ReSym truth (only REA's have). The tracer's coverage on the 94 binaries is unmeasured beyond the `cat` anecdote.

## Q5. Stated project rules, and what failed before (C struct globals, --infer-from-caller)

### Takeaway
The rules are: invented facts are worse than absent ones (for a fuzzing consumer); precision must not fall below 20%; speculative heuristics are flag-gated and measured separately; tier 0 and lower-tier goldens never change; DWARF is used only at scoring; no stack locals are emitted; acceptance criteria are set in advance and must be falsifiable. Both `--infer-from-caller` and `--struct-globals` were correctly motivated and implemented, then measured as net losses.

### Cited Findings
- "Precision must not fall below 20%... reverted and flag-gated, on the standing rule that for a fuzzing consumer an invented fact is worse than an absent one" — [docs/plans/phase10.md:327-331](docs/plans/phase10.md). "Invented structure is worse than absent structure" — [docs/TOOL.md:494-495](docs/TOOL.md). "A fuzzer can disprove a bad invariant but cannot recover one that was never emitted" (the reason `is_param` was dropped) — [docs/plans/README.md:91-97](docs/plans/README.md)
- Tier 0 output never changes; all tiers are opt-in. DWARF is read only at scoring time. Stack locals are not emitted (Kvasir reports params, pointees, return and globals) — [docs/plans/README.md:44-60](docs/plans/README.md). Speculative heuristics stay gated so their contribution is separately measurable — [docs/EVALUATION.md:452-460](docs/EVALUATION.md). Mechanisms are measured separately and reverted if they don't pay; acceptance includes "Daikon exits 0 on all 29" and the own corpus at 65/92/76 or better — [docs/plans/phase10.md:305-331](docs/plans/phase10.md). "A criterion that cannot fail teaches nothing" — [docs/TOOL.md:499-513](docs/TOOL.md)
- Deliberate divergence from the oracle: `flags is_param` makes Daikon drop non-unit coefficients (`2a+1` becomes `return - orig(a) - 1`, which is false). Tier 3+ does not set it, at the cost of roughly doubled counts (test10 14 -> 37) — [docs/plans/README.md:73-104](docs/plans/README.md)
- **`--infer-from-caller` failure.** On the fixtures, facts went 239 -> 375 and matched 155 -> 161; P 65% -> 43%, R 92% -> 95%, F1 76% -> 59% ("136 extra facts bought 6 matches"). The cause is temporal aliasing: a stack address holds different objects over time, and nothing bounds a stack object the callee never touched. On `identity_ptr` the 64-byte window swallowed neighbouring locals and invented three fields. On test14, facts went 43 -> 98 with 55 invented. The default uses the global map only where an allocation size bounds it exactly — [docs/plans/phase8.md:48-66](docs/plans/phase8.md); [docs/TOOL.md:477-495](docs/TOOL.md); [docs/EVALUATION.md:73-83](docs/EVALUATION.md). The proposed remedy is to bound a stack pointee (frame-lifetime scoping, or only caller accesses between its frame setup and the call) — [docs/EVALUATION.md:461-467](docs/EVALUATION.md). The suite showed that "identity_ptr is not a corner case", which changes the calculation for leaving the flag off — [docs/EVALUATION-KVASIR-SUITE.md:410-411](docs/EVALUATION-KVASIR-SUITE.md)
- **C `--struct-globals` failure.**
  - Three discriminators against DWARF on 72 globals all scored below baseline: baseline 88% / structs 0/8; + heterogeneous widths 87% / 0/8; + pointer-shaped slot 86% / 0/8
  - Root cause: "a statically-initialised struct is never written at run time" (loader-initialised, so no heterogeneous accesses), while int arrays copied 8 bytes at a time do produce mixed widths
  - Net -123 matched facts, and it subtracts from B (978 alone vs 973 combined)
  - The struct branch of `_global_specs` was dead code: "we emit zero `.offK` on any global"
  - Sources: [docs/plans/phase10.md:25-51,249-259](docs/plans/phase10.md)
- Other measured no-ops and failures:
  - tier 4 covariance pointer classification was skipped (the range classifier already gets 7/7 and misclassifies 0/118) — [docs/plans/README.md:26-30](docs/plans/README.md)
  - addressing mode to tell array from struct does not work at -O0 — [docs/TOOL.md:381-387](docs/TOOL.md)
  - D's static SSE scan returned zero hits — [docs/plans/phase10.md:154-167](docs/plans/phase10.md)
  - a pilot "AI type recovery for globals" was committed and then reverted (commit 3291e3f, reverted in a94a57f; `git log`). Its results are not documented in the docs read.
- Format traps that silently zeroed results: `var-kind field` without a relative name (2 binaries to zero); an `enclosing-var` naming an undeclared var (9 binaries to 8-fact stubs) — [docs/plans/phase10.md:53-68](docs/plans/phase10.md)
- Process lesson: "Aggregate metrics hide instrument bugs; per-unit ones expose them" — [docs/EVALUATION.md:477-493](docs/EVALUATION.md)

### Inferences
- Any harness-side heuristic (e.g., libc stubs that invent return values or string contents) falls under the same rule. Stubs that fabricate plausible-but-wrong memory would be "invented facts" in the trace, so they should be flag-gated and measured against the 20% floor.
- B `--deref-globals` (16% precision) already violates the floor, which is why it is off. Mechanism A is expected to be worse unless gated by layout evidence.

### Gaps
- Why the AI-globals pilot was reverted is not recorded in the docs read; only the commit pair exists.
