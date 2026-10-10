# What the tracer observes, and which cases it covers

A reference. [TOOL.md](TOOL.md) explains *how* techniques work and the bugs
behind them; this says precisely **what raw signals exist**, **what is derived
from each**, and **case by case what happens to a given C construct**.

Every coverage claim below cites a measured result. Where a case has never been
exercised, it says so rather than guessing.

---

## 1. The raw signals

Four hooks and six ELF reads. Everything the tool knows comes from these.

### From execution

| signal | hook | recorded as |
|---|---|---|
| every executed instruction, disassembled with operand detail | `UC_HOOK_CODE` | — |
| **which registers an instruction reads and writes** | `UC_HOOK_CODE` + `insn.regs_access()` | `ArityTracker.note_instruction` |
| the mnemonic that consumes `rax` after a `call` | `UC_HOOK_CODE` | `note_return_signedness`, `note_caller_observation` |
| a prologue store of an argument register to a frame slot | `UC_HOOK_CODE` | `note_spill` |
| a read of `[rbp+0x10+8k]` (a stack argument) | `UC_HOOK_CODE` | `stack_slot=` |
| **RIP-relative operand targets** landing in a data section | `UC_HOOK_CODE` | `GlobalTable.add_start` |
| **every memory read and write**: address and width | `UC_HOOK_MEM_READ\|WRITE` | four separate places, below |
| the **program counter** of each memory access | same hook, `reg_read(RIP)` | `Tracer.access_pcs` |
| a call to a resolved PLT stub, plus its register arguments | `UC_HOOK_CODE` | `alloc_stubs`, `libc_stubs` |
| an access to unmapped memory | `UC_HOOK_MEM_*_UNMAPPED` | maps a page and continues |

Each memory access is recorded four ways, because each answers a different
question:

```
global_access.note(addr, size)                    every access by ABSOLUTE address
global_table.note_access(addr, size)              ... restricted to .data/.bss/.rodata
global_touch[func].add(addr)                      which FUNCTION touched which global
footprints.note_access(func, slot, delta, size)   offset within a pointer ARGUMENT
access_pcs[(func, slot)][pc].add(delta)           which INSTRUCTION touched which offset
```

### From the ELF file

| read | survives `strip --strip-all`? | used for |
|---|---|---|
| program headers (segments) | yes | the memory map |
| section headers (`.data`, `.bss`, `.rodata` bounds) | **yes** | where globals can live |
| `.rela.plt` + PLT stub scan | **yes** | intercepting `malloc`, `atoi`, … |
| `.symtab` function symbols | no | function discovery (falls back to prologue scanning) |
| `.symtab` object symbols (`st_size`) | no | **exact global extents** |
| DWARF | — | **never read by the tracer.** Only by the scorer, only to align names |

The two `.symtab` rows are the only places the tool is better off unstripped,
and both have a stated fallback. `--scan-prologues` forces the stripped path for
both, so the degradation is measurable rather than theoretical.

---

## 2. What each signal is turned into

| derived fact | from | tier |
|---|---|---|
| this register is an **argument** | read before written, and caller-saved | 2 |
| **how many** arguments | highest argument-register index used, + contiguity | 2 |
| an argument's **width** | the sub-register named on its first read (`edi` vs `rdi`) | 3 |
| the **return value** | last write to the `rax` family before `ret` | 3 |
| the return is **void** | the caller never reads `rax` afterwards | 3 (`--detect-void`) |
| the return is **unsigned** | the consuming opcode is `shr`/`seta`/`movzx` rather than `sar`/`setg`/`movsx` | 8 |
| this value is a **pointer** | it lands inside a mapped region | 3 |
| a pointee's **fields** | offsets and widths accessed through that pointer | 6 |
| an object's **extent** | the `malloc` argument, or `st_size` | 5, 8 |
| a pointee is an **array** | `length x width == extent` on every call, **or** a correlated length argument, **or** one instruction walking several offsets | 7, 10 |
| a **global** exists here | a RIP-relative target, an observed access, or an object symbol | 8 |
| a global is a **pointer** | its value lands in a mapped region | 10 (`--deref-globals`) |
| a **float/double** argument | `xmm0`–`xmm7` read before written; width from `movss` vs `movsd` | 9 |
| memory was **never written** | it still holds the `0xAB` fill pattern | 6 (`--poison-uninitialized`) |

---

## 3. What is *not* observed

Stated plainly, because these bound everything else.

- **Types.** Nothing in the machine says `int` or `struct`. Every type fact
  above is inferred from behaviour.
- **Names.** Destroyed by stripping, permanently.
- **Definedness.** Valgrind tracks it bit-by-bit; Unicorn zeroes fresh pages.
  `--poison-uninitialized` approximates it and is wrong for a genuine
  `0xABABABAB`.
- **Unexecuted paths.** Code that never runs leaves no trace. A parameter the
  callee never reads is *not* in this class at -O0, because the prologue spills
  it; at -O1 and above it is.
- **Anything inside a library call.** An unmodelled `call` is **skipped**: `rax`
  is set to 0, `rip` advances past it, and a counter increments (reported as
  `Skipped calls:`). The call's real effects never happen.

That last point is the biggest hidden assumption in the tool. Modelled so far:

```
tier 5   malloc  calloc  realloc  free        a real arena; sizes are recorded
phase 12 atoi  atol  exit  _exit  abort       atoi parses; exit stops the run
everything else                               skipped, returns 0
```

`exit` being modelled matters more than it looks: without it, a program that
bails out would *continue executing* and every later sample would describe code
the real program never runs. Confirmed against Kvasir — on `tcas` neither side
records `main:::EXIT`, because `main` calls `exit()`.

---

## 4. Case coverage

Status meanings: **covered** = measured at high recall; **partial** = some facts
recovered, named limitation; **not covered** = structurally missed.

### Parameters and returns

| case | status | evidence |
|---|---|---|
| `int`/`long`/`char` parameters | **covered** | arity exact on **81 of 99** functions across Daikon's suite |
| negative values | **covered** | width-correct sign extension, tier 3; `negate` reports −1…−5 |
| `unsigned` with the high bit set | **partial** | recovered when a consuming opcode reveals it (`big_unsigned` matches Kvasir exactly); otherwise reads negative |
| dead / unused parameter | **covered at -O0** | the prologue spills every parameter, so `pick_first` reports 2 like Kvasir (`test_dead_parameters_recovered_at_O0`); at -O1+ the callee never reads it, and only a call-site analysis could recover it |
| more than 6 arguments (stack-passed) | **covered** | `test10` twelve arguments, 14/14 |
| `float`/`double` parameters | **partial**, tier 9 | were **arity 0** on 8 of 8 functions before tier 9; `FloatTest` recall 24% → 35% |
| **mixed `int` and `float` parameter list** | **not covered** | values right, *order* wrong — the ABI numbers the two sequences independently, the tracer puts floats last, and the scorer aligns by position. At -O0 the prologue's first reads follow declaration order ([RELATED-WORK.md §1e](RELATED-WORK.md#1e-at--o0-argument-registers-are-first-read-in-declaration-order)) |
| `struct` passed **by value** | **not covered** | **6 of 6 wrong**: a 252-byte struct becomes 18 arguments; an untouched one becomes 0 |
| integer return | **covered** | tier 3 |
| pointer return | **partial** | emitted; its pointee needs a layout (`identity_ptr` 47%) |
| `void` return | **covered** | `--detect-void` |
| `struct` returned by value (`rax:rdx`) | **not covered** | `makepoint`'s `return.x`/`return.y` have no counterpart |
| recursion | **covered** | `test11` **100% / 100%** — the invocation nonce pairs ENTER/EXIT correctly |
| varargs | **untested** | no fixture exercises it |

### Pointers and memory

| case | status | evidence |
|---|---|---|
| pointer to a scalar, dereferenced | **covered** | tier 6 |
| pointer to a struct, 1 level | **covered** | `test08` **31/31**, the fixture the whole dereference effort targeted |
| pointer never dereferenced by the callee | **partial** | needs `--deref-globals`/`--infer-from-caller`; measured at −22 precision for +3 recall, so off by default |
| **pointer inside a struct (2+ levels)** | **not covered** | **54% of all remaining missed facts**. `local-ptr` 4% recall, `pointer-levels` 9% |
| out-parameter (written, never read) | **covered** | the memory hook watches writes as well as reads, for exactly this |
| `NULL` argument | **covered** | classified as `NULL`, not scalar — one NULL used to destroy pointee recovery for every other call |
| two pointers into the same object | **not covered** | an access is attributed to the first matching pointer only; confirmed, has not yet cost the corpus anything |
| uninitialized memory | **partial** | `--poison-uninitialized`; `fill`'s samples become byte-identical to Kvasir's |

### Arrays and structs

| case | status | evidence |
|---|---|---|
| heap array with a length argument | **covered** | `arg1 == size(arg0[])`, the buffer-length contract |
| heap array, length varies per call | **covered** | `varying_len` yields `[1 2 3 4 5]` and `[10 20 30]` from one program point |
| array iterated in a loop | **covered** | one instruction walking many offsets — the only signal that cost nothing to add |
| **fixed-size array, no length argument, on the stack** | **not covered** | nothing bounds the object; modelled as a struct |
| struct with mixed-width members | **partial** | recovered as `.offK` fields; the scorer maps them to DWARF names |
| **global struct** | **not covered** | **0 of 8** correct; three separate discriminators failed to improve it |
| multi-dimensional array | **not covered** | `MultiDimArrayTest` 10% recall |
| `union` | **not covered** | `UnionComp` 1% recall — the same bytes have several valid readings and nothing selects one |

### Globals

| case | status | evidence |
|---|---|---|
| global scalar | **covered** | `SelectGlobalsTest` **83% / 87%**, `GlobalTest` 54% |
| global array of scalars | **covered** | `IntTest` reproduces `::globalIntArray[] == [1..18]`, `size(…) == 18`, and the derived `[::globalX]` facts |
| global read via `argv` | **covered** | `tcas` **94% / 90% / 92%**, 12 globals set from arguments |
| global holding a pointer | **partial** | `--deref-globals`; 65 of 85 globals are pointer-shaped and printed as integers by default |
| global struct | **not covered** | see above |
| `double` global | **not covered** | reported as an integer; nothing distinguishes it from `long` unless an SSE instruction touches it |
| string (`char*`) contents | **not covered** | `string-arrays` 30% recall; the pointer is right, the text is not read |

### Control flow and the rest

| case | status | evidence |
|---|---|---|
| function pointer / indirect call | **partial** | `function-pointer` 50% recall; the callee is named by **call site**, not target |
| `exit()` on an error path | **covered** | modelled; stops the run |
| library input (`fgets`, `fopen`, `read`) | **not covered** | skipped, so the program sees no input. Blocks `replace`, `print_tokens`, `wordplay`, `space` |
| 32-bit binaries | **untested** | gated off above tier 1; never executed |
| optimised builds (`-O1`+) | **untested** | six inference premises assume the `-O0` prologue; the corpus is entirely `-O0` |

---

## 5. The three ways a case fails

Useful because the fix differs completely.

**1. Not observed.** The information is absent from the execution. A parameter
the callee never reads, at -O1 and above; a `double` never loaded as a double;
an unexecuted branch. Measured at
roughly **5%** of a real oracle. No technique recovers these, and saying so is
the correct output.

**2. Observed but not traversed.** The bytes were seen; we stopped looking. A
pointer inside a struct, a global holding a pointer. **~89%** of what remains.
Fixable, and the cost is precision rather than information — measured at +176
facts for −6 precision points one level deeper.

**3. Observed but mis-described.** Right bytes, wrong noun. Six correct integers
called a struct instead of an array. This is where type inference sits: applying
every currently-computable signal forces **33 of 72** shape decisions, of which
**4 are forced onto the wrong answer**, for three reasons rather than the one
first diagnosed: a copy's wide loads erase narrower stores in the evidence, a
rule admits a struct only when member widths differ, and an array of structs is
not a hypothesis at all
([RELATED-WORK.md §1b](RELATED-WORK.md#1b-the-four-forced-but-wrong-shapes-have-three-causes-not-one)).
Planned as [plans/phase13.md](plans/phase13.md).

---

## 6. Two things that are known-good

Worth separating from the coverage gaps, because they bound what kind of bug is
possible.

**The execution is faithful.** Across 29 binaries, **198 of 198 program points**
record an identical number of samples under our emulation as under
Kvasir/Valgrind on real hardware, including a 1000-iteration loop. Whatever is
lost is lost in description, not observation - with one known exception. Those
are sample *counts*. Where a skipped library call would have changed memory,
the values differ: `memcpy`, `memset`, `strdup`, `strlen` or `toupper` is
called in nine of the 29 programs ([RELATED-WORK.md
§1f](RELATED-WORK.md#1f-skipped-library-calls-change-program-state-in-9-of-29-programs)).

**The output is sound against what was observed.** Of every fact the tool emits,
1000 are decidable against the samples it recorded itself, and **all 1000 hold**
— see `scripts/audit_soundness.py`. The audit found one real defect when first
run: 64-bit values were emitted outside the range of their declared type and
Daikon was silently wrapping them.
