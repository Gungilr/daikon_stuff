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
