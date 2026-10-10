# Every inference the tracer makes: strengths, flaws, soundness

A catalogue of the 42 rules the tracer uses to turn an emulated run of a
stripped binary into Daikon variables, such as "`rax` at `ret` is the return
value". For each: what it gets right, how it fails, and whether it is sound.
Written 2026-10-03.

[VERIFICATION.md](VERIFICATION.md) classifies 21 of these by verifiability.
This list is complete, and adds the return-value, void, float, pointer-ownership,
global and library-call rules. [RELATED-WORK.md](RELATED-WORK.md) gives the
methods behind the proposed fixes.

Evidence is a measurement, a test, or a code line. Two flaws, H16 and H38, were
found by reading the code and have not yet been reproduced; they say so.

## Verdicts

| verdict | meaning |
|---|---|
| **SOUND** | Reads a specification, or observes the run directly. Wrong only if the emulation is wrong. |
| **PREMISE** | Sound if a compiler or ABI convention holds. Every premise here has been checked only at `-O0`. |
| **HEURISTIC** | Can be wrong on ordinary programs. Measured; keep it, but improve it. |
| **UNSOUND** | Gives wrong answers on ordinary programs as designed. Replace it. |
| **INCOMPLETE** | Right as far as it goes, but stops early. |

Count by verdict: 9 SOUND, 9 PREMISE, 16 HEURISTIC, 6 UNSOUND, 1 INCOMPLETE,
and H21, which is SOUND for heap pointers and HEURISTIC otherwise.

---

## 1. Functions and program points

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H1 | functions come from `.symtab`; if stripped, from scanning code for the standard frame-pointer prologue | exact with symbols | stripped: misses functions without that prologue, which is common at `-O1` and above | PREMISE |
| H2 | `main` is `rdi` at `call __libc_start_main`, found by emulating `_start` | works on stripped binaries | glibc-specific | PREMISE |
| H3 | ENTER when execution reaches a known function start; EXIT at `ret` with that frame on our stack | 198 of 198 program points have Kvasir's sample counts | tail calls, `longjmp` and `exit` break pairing; a mismatched return address is only logged | PREMISE |
| H4 | ENTER and EXIT paired by a nonce we issue | recursion scores 100% (test11) | none | SOUND |

## 2. Parameters

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H5 | a parameter is one of the six integer argument registers read before written | exact arity on 81 of 99 suite functions | a dead parameter is invisible at `-O1` and above | PREMISE |
| H6 | after a `call`, all caller-saved registers count as written | stops a nested call's result posing as an argument | none | SOUND |
| H7 | arity is the highest register used plus one; any stack argument means all six registers are arguments | recovers dead middle arguments | a struct passed by value breaks it: a 252-byte struct becomes 18 arguments, an untouched one 0; 6 of 6 wrong | **UNSOUND** for structs |
| H8 | stack arguments are reads of `[rbp+0x10+8k]`, up to 12 slots | 12-argument fixture 14 of 14 | needs a frame pointer; silently stops at 12 slots | PREMISE |
| H9 | an argument's width is the sub-register named on its first read, the prologue spill | fixed -1 reading as 4294967295 | at `-O1` the first read may not name the declared width | PREMISE |
| H10 | integers are sign-extended unless proven unsigned | right for `int`, the common case | a large `unsigned` that nothing compares reads negative | HEURISTIC |
| H11 | float arguments are `xmm0`-`xmm7` read before written; width from `movss` or `movsd`, double if unseen | FloatTest went from arity 0 to right | numbered after all integer arguments, so mixed lists are scored under swapped names; an unseen `float` is read as a `double` | PREMISE, misnumbered |
| H12 | values at EXIT come from the prologue's spill slot, frame base `rsp-8` at entry | removed `arg0 == arg2` artefacts | no spill slot exists at `-O1` | PREMISE |

## 3. Return values

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H13 | the return value is `rax` at `ret`, its width from the last `rax`-family write | `return == 0` and similar facts match Kvasir | a struct returned in `rax:rdx` loses `rdx`; a struct returned through a hidden pointer looks like a pointer return | HEURISTIC |
| H14 | `--detect-void`: if a caller reads `rax` within 12 instructions the value is used; void only if callers were seen and none read it | removes garbage `return` from void functions | opt-in, so by default every void function reports leftover `rax`; a function whose callers all ignore its result is called void | HEURISTIC |
| H15 | the caller's consuming opcode sets signedness: `shr`, `seta`, `movzx` unsigned; `sar`, `setg`, `movsx` signed | `big_unsigned` now matches Kvasir exactly | when callers disagree, the last one wins; with no consumer it stays signed | PREMISE |
| H16 | a function returns a float or double if any SSE instruction ever wrote `xmm0` in it | FloatTest returns recovered | never cleared by a later integer result, so `int f(double x)` that does SSE math is declared to return a double read from `xmm0` ([infer.py:257](../scripts/tracer/infer.py#L257), [emulate.py:1658](../scripts/tracer/emulate.py#L1658)). Found by reading; not yet reproduced | **UNSOUND** as written |

## 4. Values and pointers

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H17 | a value inside a mapped region is a pointer; 0 is NULL and neutral; one non-pointer sighting demotes the slot | 7 of 7 pointers right, 0 of 118 variables wrong on the fixtures | an integer that lands in a mapped range is called a pointer, with no evidence the program uses it as one | HEURISTIC |
| H18 | fields wider than 8 bytes, and values outside 64-bit range, print as `nonsensical` | never prints an untrue number | none | SOUND |
| H19 | uninitialised memory: by default Unicorn's zero fill is reported as data; `--poison-uninitialized` fills with `0xAB` and reports leftovers as `nonsensical` | with the flag, `fill`'s samples match Kvasir | the default prints values the program never wrote; the poison misreads a genuine `0xAB` pattern | **UNSOUND** by default |

## 5. Memory behind pointers

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H20 | an access at address A belongs to argument N when A minus N's value is between 0 and the bound | works through the register copies `-O0` makes | two pointers into one object: the first match takes every access | HEURISTIC |
| H21 | the bound is the allocation size for heap pointers, a fixed 64 bytes otherwise | heap is exact | the window can swallow neighbouring stack locals | SOUND for heap, HEURISTIC otherwise |
| H22 | fields are the offsets and widths the program read or wrote through the pointer | test08 31 of 31; out-parameters work | fields never touched are invisible; `--infer-unobserved-fields` guesses tail widths | HEURISTIC |
| H23 | dereference goes one hop, from arguments and return values | invents no structure | **54% of all remaining misses**; going further by value costs precision: `--deref-globals` 6 points, `--infer-from-caller` 22 | INCOMPLETE |

## 6. Arrays versus structs, behind pointers

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H24 | a footprint is a struct unless a second signal says array | safe for `pair_t` | a stack array with no length argument stays a struct | HEURISTIC |
| H25 | an integer argument equal to the element count on every call makes it an array | yields `arg1 == size(arg0[])` | a constant argument could coincide | HEURISTIC, strong |
| H26 | length times width equal to the allocation size on every call makes it an array | needs no footprint coverage | heap only | HEURISTIC, strong |
| H27 | one instruction touching 2 or more offsets makes it an array | the only change that cost no precision | once `memset` is modelled, it must not count as this evidence | HEURISTIC, strong |
| H28 | `--tile-implies-array`: any tiling footprint is an array | slightly better on Daikon's suite | fixtures drop from 155 to 98 matched facts | HEURISTIC, off |

## 7. Globals

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H29 | `.data`, `.bss`, `.rodata` bounds from section headers | survives stripping | none | SOUND |
| H30 | each global's start and end: RIP-relative targets and observed accesses, split at gaps over 16 bytes; `.symtab` sizes when present | exact with symbols | stripped: adjacent same-width globals merge | HEURISTIC |
| H31 | a global's width at each address is the widest access seen there ([globalvars.py:203](../scripts/tracer/globalvars.py#L203)) | none | a copy's 8-byte loads erase the 1-byte store beneath; behind 2 of the 4 wrongly forced shapes | **UNSOUND** as evidence |
| H32 | up to 8 bytes is a scalar; tiling into 2 or more elements is an array; a struct only with `--struct-globals` | scalars 50 of 50, arrays 14 of 14 | structs 0 of 8; no array-of-structs hypothesis; phase 13's offline "equal widths, so not a struct" rule was unsound | HEURISTIC |
| H33 | `--deref-globals` follows pointer globals one hop | +176 matched facts | -6 precision points | HEURISTIC, off |
| H34 | every global is declared at every program point | matches Kvasir on single-file programs | Kvasir shows file-static variables only in their own file's functions (daikon/doc/daikon.texinfo:4514-4523). On multi-file `bc` our 112 globals everywhere cost Daikon 841 s | HEURISTIC |

## 8. Library calls and input

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H35 | library calls named from `.rela.plt` and the `ff 25` stub pattern | identical on stripped builds | none | SOUND |
| H36 | modelled: `malloc` family with no address reuse, as under Valgrind; `atoi`, `atol`; `exit`, `_exit`, `abort` | real heap pointers; tcas 94/90/92 | a small set | SOUND |
| H37 | every other call is skipped: `rax` set to 0, no side effects | keeps emulation going | 9 of 29 programs call `memcpy`, `memset`, `strdup`, `strlen` or `toupper`, so values can differ while counts match | **UNSOUND** for fidelity |
| H38 | any `call` through a register or memory operand counts as unknown and is skipped ([emulate.py:1488-1516](../scripts/tracer/emulate.py#L1488-L1516)) | none | a function-pointer call into the program never runs its callee. Found by reading; the corpus's only function pointer targets `printf` | **UNSOUND** as written |
| H39 | `argv` input vectors, many runs merged in one emulator | 30 times faster than Kvasir over 501 runs | no stdin or files | SOUND |

## 9. Output choices

| # | rule | strength | flaw | verdict |
|---|---|---|---|---|
| H40 | comparability: one class per kind (scalar, pointer, float, global, and so on) | `return` shares a class with same-typed arguments | coarser than Kvasir's DynComp, but measured to cost only 56 of 1,955 unmatched facts ([RELATED-WORK.md §1a](RELATED-WORK.md#1a-kvasirs-output-is-dyncomp-filtered-and-ours-is-not-yet-that-costs-us-almost-nothing)) | HEURISTIC, adequate |
| H41 | never set `flags is_param`, unlike Kvasir | avoids Daikon emitting false coefficient facts | more trivial `x == orig(x)` facts | SOUND |
| H42 | pointees written as one-element sequences, `arg0[].offK`, as Kvasir does | facts comparable with Kvasir's | none | SOUND |

---

## Evaluation

### Unsound — replace

| # | fix | cost |
|---|---|---|
| H16 float return | whichever of `rax` and `xmm0` was written last before `ret` wins; confirm with what the caller reads | hours, plus a fixture that reproduces it first |
| H38 indirect calls | read the target from the register or memory operand at the `call`; run it if it is a program function | hours, plus a fixture |
| H37 skipped calls | model the five state-changing functions, each also logged as type evidence; add a value-by-value check against Kvasir's trace | days |
| H19 default zero fill | mark bytes as defined when written: stack bytes become undefined when the frame grows, heap bytes on `malloc`; never-written bytes print `nonsensical`. The memory hook already sees every write | days |
| H31 widest-access merge | store every access as `(pc, offset, width)` ([phase 13](plans/phase13.md) A1) | days |
| H7 arity with structs | recognise the call site's copy block: `sub rsp, N`, then a copy from one object, is one parameter of N bytes ([RELATED-WORK.md §3.4](RELATED-WORK.md#34-calling-conventions)) | 1-2 weeks, needs provenance tracking |

The H19 fix approximates Memcheck rather than reimplementing it. It is exact for
bytes never written, and differs only where an undefined value is copied, which
Memcheck tracks and this would treat as written.

### Heuristics to improve, by impact

1. **H23 depth.** Follow a pointer only when the program dereferences it, to
   Kvasir's default depths of 2 and 4. Targets the 54%.
2. **H32 and H24 shapes.** Phase 13: report every surviving shape, eliminate
   only for sound reasons, add array of structs with the periodicity test, and
   check against generated programs.
3. **H34 global scoping.** Copy Kvasir's rule from `.symtab` file and binding
   records when present; keep every global everywhere when stripped.
4. **H17 pointers.** Add use evidence: a value the program dereferences is a
   pointer. Keep the range test as fallback.
5. **H13 struct returns.** Detect `rax:rdx` returns and hidden-pointer returns.
6. **H11 numbering.** Align by ABI class in the scorer now; number by first read
   at `-O0`.
7. **H14 void.** Add callee-side evidence, then measure turning it on by default.
8. **H15 conflicts.** Keep every caller's vote and report disagreement instead of
   taking the last.
9. **H20 and H21 ownership.** Decide which pointer an access came from by
   tracking where its base address was loaded from, not by address windows.
10. **H1 stripped discovery.** Read function ranges from `.eh_frame`, which
    survives stripping, plus observed call targets.

Items 1, 4, 5 and 9 need the provenance tracking described in
[RELATED-WORK.md §2](RELATED-WORK.md#method-p-a-provenance-shadow).

### Premises to test off `-O0`

H1, H3, H5, H8, H9, H12 and H15 hold at `-O0` and have never been tested
elsewhere. Rebuilding the corpus at `-O1` and `-O2` and measuring is still, as
VERIFICATION.md says, the cheapest falsification experiment available.

### Sound — keep as is

H4, H6, H18, H29, H35, H36, H39, H41, H42, and H21 for heap pointers.

### Limits no rule can remove

- **Names**, destroyed by stripping.
- **Code that never runs.**
- **Types the program never tells apart.** These include a `double` never used as
  one, an `unsigned` never compared, and a `char*` never walked. They can be
  guessed with a stated probability, never known.
- **Daikon's own generalisation**, from samples to "always". It is inductive by
  nature, and refuting it is the fuzzer's job.

---

## Order of work

| step | heuristics | why here |
|---|---|---|
| 1 | H16, H38 | hours each; reproduce first with a fixture, then fix |
| 2 | H11 in the scorer; H34; a fair `bc` baseline | corrects the numbers every later decision uses |
| 3 | H37, H19 | fidelity: what we observe must match the program |
| 4 | H31, H32, H24 | phase 13 part 1, no new infrastructure |
| 5 | provenance tracking | one investment that unlocks the next row |
| 6 | H23, H7, H13, H17, H20, H21 | the 54%, structs by value, real pointer evidence |
| 7 | the `-O1`/`-O2` experiment; H1 | tests every PREMISE row |
| 8 | stdin and files; the fuzzing loop | the end goal, on a sound base |

**A note on the `bc` baseline in step 2.** Earlier docs compared our 841 s with
Kvasir's 36 s on `bc`. That Kvasir run used `bc`'s own Makefile, which passes
`--ignore-globals`, and Daikon's reference declarations for `bc` contain no
globals: 14.9 variables per entry point. Ours declared all 112 globals at every
point, so the two runs are not comparable, and a fair comparison has not been
made.
