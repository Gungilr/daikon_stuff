# ReSym VarDecoder, run locally (no API tokens)

Date: 2026-11-03. Scripts: `scripts/rea_eval/resym_infer.py`, `scripts/rea_eval/resym_score.py`.

## Setup
- Model: ReSym's official VarDecoder checkpoint (Zenodo record 13923982, `vardecoder.zip`,
  md5 verified) - StarCoderBase-3B fine-tune, bf16, CPU (4 cores, no GPU).
- Tokenizer: `bigcode/tiny_starcoder_py`, byte-identical tokenizer files to the gated
  `bigcode/starcoderbase-3b` the authors load.
- Prompt and decoding as in the authors' `vardecoder_inf.py` (beam 4, input cut to 7168
  tokens); output length capped at 40 tokens per asked variable (no answer hit the cap).
- Data: 200 functions sampled (seed 0) from ReSym's own `vardecoder_test.jsonl`
  (IDA Hex-Rays pseudocode - the style the model was trained on).

## Results (200 functions, 778 labelled variables; 31 unlabelled `-` skipped)
| | local run | authors' published predictions, same vars |
|---|---|---|
| type exact | 66.5% | 66.8% |
| type coarse class (pointer depth + void/named/float/double/int width+sign) | 85.9% | - |
| missing answer | 0% | - |
| identical to authors' prediction | 93.6% | - |

- Time: 7.7 h total, median 86 s per function.
- Most common class errors (truth -> predicted): `int` -> a project type name (14),
  struct -> struct pointer (6), `void*` -> named-struct pointer (6), struct pointer -> struct (5).
- Typical wrong answers are plausible project names: `hashtab*` -> `hashmap_t*`,
  `dict*` -> `const wpabuf*`, `usb_dev*` -> `uint8_t*`.

## Reading
- The CPU setup reproduces the paper's model faithfully (within 0.3 points).
- The model always answers: one third of its stated types are not exactly right, and
  about 14% are in the wrong coarse class. Under this project's rule (an invented fact
  is worse than an absent one) its output would need a confidence filter before use.
- Not yet measured: the model on Ghidra/REA pseudocode (out of its training style).

## Filtering ReSym's parameter types with evidence from the binary (2026-11-04)

Question: ReSym always answers. If every answer the binary contradicts is dropped,
how good are the types kept?  Script: `scripts/rea_eval/resym_check.py`.

- Predictions: the authors' published `vardecoder_pred.jsonl`, restricted to the 94
  test binaries we hold (13,444 functions matched by the `sub_<ADDR>` in the IDA
  prompt; skipped: 607 where Ghidra's parameter count differs from IDA's, 326 with
  float parameters, whose register numbering need not line up).
- Static evidence: the Stage 1 checker's rules (`check.py`, Ghidra high p-code of
  the stripped binary: dereferences, arithmetic, signed/unsigned ops, libc call
  arguments). Ghidra's own type guesses are not used.
- Trace evidence: the tracer (`--tier 10`, started at `main`, no input) on each
  stripped binary; its ENTER declarations type an argument `void*` when the value
  pointed into mapped memory.
- Scoring: DWARF. "Facts right" = kind, pointee kind, signedness and size agree
  where both state them (coarse: a named type counts right when the truth is a
  struct or integer; pointee width is not checked).

### All 30,865 parameter answers (static evidence)
| | kept | facts right | exact string |
|---|---|---|---|
| ReSym alone | 30,865 (100%) | 81.5% | 57.7% |
| drop answers the code contradicts | 29,118 (94.3%) | 84.8% | 58.1% |
| keep only answers the code supports | 20,244 (65.6%) | 90.7% | 58.2% |

Caught 22.9% of the wrong answers and rejected 1.7% of the right ones. Per rule
(catches / false rejects): R1 pointer-ness 890/180, R3 signedness 197/98,
R5 pointee width 216/156, R6 struct 17/4, R4 float 2/1.

### The 680 answers in functions the tracer reached (2% of the total)
| | kept | facts right |
|---|---|---|
| ReSym alone | 680 | 81.2% |
| drop if static evidence contradicts | 654 | 83.5% |
| drop if the trace contradicts | 657 | 82.6% |
| drop if either contradicts | 636 | 84.4% |
| keep only if static evidence supports | 452 | 90.9% |

- Trace rule "value pointed into memory, so not a scalar": 14 catches / 9 false
  rejects (the false rejects are integers holding guest addresses, `__virtio64`).
- The reverse rule ("never an address, so not a pointer") was dropped: 23 catches /
  41 false rejects, because a NULL or a tagged pointer (`tagged *` in a Scheme
  interpreter) reads as an integer.

### Reading
- Binary evidence makes ReSym's kept types more trustworthy (81.5% -> 84.8% when
  dropping contradictions, 90.7% when keeping only supported ones), but it cannot
  fix the exact type (57.7% -> 58.2%): ReSym's main error is the type NAME, which no
  instruction or trace reveals.
- Traces add little here, because a run from `main` with no input reaches only 2%
  of the functions, and per answer they say less than the static rules (pointer vs
  not, from the values seen). The static evidence covers every function.
