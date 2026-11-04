# Plan — pick among ReSym's candidate answers using evidence from the binary

Status: **pilot done (2026-11-04): gate passed narrowly; main run not started.** Prerequisite: `docs/RESYM-LOCAL.md` (local
VarDecoder run, and the evidence filter `scripts/rea_eval/resym_check.py`).

## Why

ReSym's beam search already computes 4 candidate answers per function, but only
the top one is kept. The evidence filter showed that when the top answer is
contradicted by the binary, all we can do today is drop it:

| (30,865 parameter answers, 94 binaries) | kept | facts right |
|---|---|---|
| ReSym alone | 100% | 81.5% |
| drop contradicted answers | 94.3% | 84.8% |
| keep only supported answers | 65.6% | 90.7% |

**Question:** when the top answer is contradicted, is one of the other 3
candidates consistent with the evidence, and is it right? If so, part of what
retraining-with-evidence would buy is available with no training at all.

**Main risk, stated up front:** the 4 beams usually differ in variable *names*
and small details, not in types. If the alternatives for a contradicted variable
are mostly the same type, there is nothing to pick from. The pilot (step 2)
measures this before the long run.

## Design

Only contradicted answers can change: an answer the evidence does not
contradict keeps candidate 1 (the top beam). So the experiment needs model runs
**only on functions with at least one contradicted parameter**, and the effect
on all 30,865 answers can be computed exactly from that subset (every other
answer is unchanged).

### Selection rule (fixed before running)

For each parameter, walk the candidates in beam order (best score first) and
take the first whose type the evidence does not contradict. Evidence is exactly
what `resym_check.py` uses now: the static p-code rules R1, R3–R6, plus the
trace rule T-ptr (value pointed into memory, so not a scalar). If all 4
candidates are contradicted, **abstain**.

Variant reported alongside: take the first candidate the evidence **supports**
(PASS), abstaining otherwise. This is the high-precision mode.

### Matching

As in `resym_check.py`:
- the function address comes from `sub_<ADDR>` in the IDA prompt;
- parameter `aN` is ordinal N−1;
- skip functions whose Ghidra parameter count differs from IDA's, or that have
  float parameters.

DWARF is read only at scoring.

## Steps

1. **List the target functions.** Add `--list-contradicted OUT` to
   `resym_check.py`. It writes the test-set index of every function with ≥1
   contradicted parameter answer, plus the count. The predictions file is
   line-aligned with `vardecoder_test.jsonl`.
2. **Pilot: 20 functions, about 30 min.**
   - Add `--candidates K` and `--only-idx FILE` to `resym_infer.py`.
     `--candidates K` sets `num_return_sequences=K` with the same 4 beams, so
     the cost is about the same as now. Store every candidate's text and beam
     score.
   - Run K=4 on 20 randomly sampled target functions (seed 0).
   - Measure the share of contradicted parameters for which some other
     candidate has a different coarse type class, i.e. whether there is
     anything to pick.
   - **Gate:**
     - If fewer than 15% of contradicted parameters have a different-class
       alternative, stop and report. Reranking cannot help much.
     - Optional fallback, which I'll ask you about first: 8 beams, about 2× the
       cost.
3. **Main run: 200 random target functions, about 5 h.**
   - Resumable and detached, like the earlier run.
   - Sample with seed 0, excluding the pilot functions.
4. **Score.** Add `scripts/rea_eval/resym_rerank.py`, which reuses
   `resym_check`'s claim parsing, evidence and DWARF scoring. On the sample it
   reports, for contradicted answers:
   - the share replaced versus abstained;
   - facts right and exact-type rate of the replacements;
   - how often the replacement is right but the original was wrong (a fix), and
     the reverse (a regression).

   It then extrapolates to all 30,865 answers. Contradicted answers are scaled
   by the sample rates, with a 95% confidence interval; all others are
   unchanged. The final table has rows for ReSym alone, dropping contradicted
   answers, reranking then abstaining, and keeping only supported answers after
   reranking.
5. **Write up** the results in `docs/RESYM-LOCAL.md` and add a row to
   `docs/plans/README.md`. Commit and push. Data and outputs stay in `bench/`,
   which is gitignored.

## Success criteria (set before running)

Reranking is worth keeping if, on contradicted answers:
1. at least 30% get a non-contradicted replacement;
2. those replacements have facts right at least 70% of the time (the original
   top answers there are wrong about 75% of the time: 1,308 of 1,747);
3. overall facts right after reranking is at least the drop filter's 84.8%, at
   strictly higher coverage than 94.3%.

If criterion 1 or 2 fails, the answer is "no cheap gain: candidates do not
carry the alternative".

## What this does not test

- Exact type names. The evidence cannot tell `hashtab*` from `hashmap_t*`, so
  reranking cannot fix ReSym's main error.
- Out-of-style input. This uses ReSym's own IDA prompts, not Ghidra/REA output.
- Locals. Only parameters have binary evidence wired up.

## Cost

About 5.5 h of CPU for model runs in total, no network beyond what is already
downloaded, and no tracer changes.

## Pilot result (20 functions, seed 0, 4 candidates)

- 94 parameter answers; the top candidate is contradicted on 26, and only 26.9%
  of those are right.
- **Gate:** an alternative of a different type class exists for 6 of 26 (23.1%).
  That passes the 15% gate, but on a small sample.
- **Rerank:** 2 of 26 replaced (7.7%), both right, 0 regressions; 24 abstained.
  Of the abstained, 7 had a right top answer.
  - `rtnl_get_ts_device_callback a1`: `uint8_t*` -> `void*`, right.
  - `_dwarf_write_sleb128 a3`: `uint64_t` -> `u64`. The truth is `int64_t`. The
    scorer counts it right only because it treats an unknown name like `u64` as
    "right if the truth is an integer". It is really a signedness miss.
- "Keep only supported" picked the same 2.
- Time: median 21 s per function, 9 min in total. Contradicted functions are
  shorter than average.
- **Reading:** the 4 beams almost never disagree on a parameter's type; they differ
  in names. Criterion 1 (at least 30% replaced) is far off at 7.7%. With n = 26
  its 95% interval is roughly 1–25%, so even the top of that range misses 30%.
