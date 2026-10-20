---
name: fuzz-loop-report
description: How to run this repo's Daikon + fuzzer loop (scripts/fuzz_loop.py, source or blackbox front-end) and how to report the results. Use whenever the user asks to run, rerun, compare or measure the fuzz loop, fuzz a target, or report fuzz-loop results.
---

# Running the fuzz loop and reporting results

The user wants every fuzz-loop run reported in the same shape, written in
plain English (assume the reader knows nothing about fuzzing), and backed by
numbers that come from the run's own output files.

## 1. Setup (once per machine or container)

Check first, and install only what is missing:

```bash
ls daikon/daikon.jar                                   # Daikon
ls daikon/fjalar/valgrind/inst/bin/valgrind            # Kvasir (source front-end only)
python3 -c "import unicorn, capstone, elftools"        # tracer front-end only
```

- **Daikon:** download `daikon-5.9.0.tar.gz` from
  https://plse.cs.washington.edu/daikon/download/ and extract it as `daikon/`
  (gitignored).
- **Kvasir:** `apt-get install -y binutils-dev` (for `bfd.h`), then
  `make -C daikon kvasir MAKEFLAGS=-j8` (several minutes). Run it in the
  background.
- **Python packages:** `pip install pytest pyelftools unicorn capstone`.
- Always `export DAIKONDIR=$PWD/daikon`.

## 2. Running

**Default for now: source code with regular Daikon (`--frontend kvasir`).**
The user asked to work this way until they say otherwise. Use the blackbox
front-end only when they ask for it by name.

| front-end | flag | traces | coverage from |
|---|---|---|---|
| source | `--frontend kvasir` (default) | debug build, via Kvasir | native build |
| blackbox | `--frontend tracer --tier N` | **stripped** build, via scripts/tracer | the tracer |

Standard runs (the defaults used for every result reported so far):

```bash
# source
python3 scripts/fuzz_loop.py fuzz/targets/arith.c -o fuzz-out/arith-src \
    --rounds 10 --batch-size 1000 --seed 0
# blackbox: tier 3 for scalar targets, tier 7 when pointers or arrays matter
python3 scripts/fuzz_loop.py fuzz/targets/buffer.c -o fuzz-out/buffer-bb \
    --frontend tracer --tier 7 --rounds 6 --batch-size 300 --batches 2 --seed 0
```

- Runs take one to three minutes each. Use a timeout of 20 minutes or more,
  and run in the background when doing several.
- **Comparisons:** run every mode on the **same seeds**, using at least 3
  (`--seed 0`, `1`, `2`). One seed is an anecdote.
- **Ablations:** `--no-guidance` keeps inputs for coverage only;
  `--no-coverage` keeps them for invariants only.
- Never report a number you did not get from a run in this session. If a run
  failed or was cut short, say so.

## 3. Collecting the numbers

Always use the helper rather than reading the files by eye:

```bash
python3 .claude/skills/fuzz-loop-report/summarize.py fuzz-out/arith-src [more dirs...]
# compare two runs: what each refuted that the other left standing
python3 .claude/skills/fuzz-loop-report/summarize.py --compare fuzz-out/A fuzz-out/B
```

It prints the per-run results table, the per-round table, the refuted and
surviving invariants, and the cost breakdown, all from `history.json`. For
detail, read `summary.md` in the run directory.

Blackbox runs name functions `sub_0x...`. To translate them for the reader,
use `nm` on the **unstripped** copy, `fuzz-out/<run>/work/<name>.bb`. Say
that this was done only for the report, and that the loop itself never saw
the names.

## 4. Response format

Use exactly these four sections, in this order.

### Results

One table first, before any prose. Use one row per run, or per mode when
comparing. Columns, at minimum:

| target | front-end | seed | rounds | rules proposed (round 0) | refuted | survived | disagreements | time |

When comparing modes, add a "false rules left standing" column: rules the
*other* mode refuted on the same seed. Bold the cells that differ between
modes. If the user asked about specific bugs, add a second short table of
those bugs: function, rule, refuted yes/no, round, counterexample input.

### Description

Two to five plain sentences: what was run, on what, and with which settings.
Name the front-end explicitly, saying "source code (Kvasir)" or "blackbox
(stripped binary, your tracer)". The user has had to ask which one was used
before, so never leave it implicit.

### Round by round

The user wants the intermediate output of every iteration, not only the end
state. For each round, from the loop's log or the `per round:` block of
`summarize.py`:

- **Inputs:** executions run, and how many inputs were kept and why
  (coverage / violation / closer).
- **Refuted rules:** each rule refuted that round, with the input that broke
  it.
- **New rules:** each rule newly proposed, and whether it is a weaker
  restatement of one just refuted (for example `x >= 1` falls and `x >= -5`
  appears).
- **Near-misses:** rules the fuzzer got closer to breaking without breaking
  them (distance before -> after).
- **Anything unusual:** a rule coming back after being refuted, a crash, a
  round where nothing was kept, the dictionary growing, or a quiet round that
  counts toward the stopping point.

Put this in a compact table (round | executions | kept | refuted | new |
notable), then one or two lines per round under it for the notable events.
Do not pad rounds where nothing happened; say "quiet round" and move on.

### Reasoning and analysis

The interpretation. **Every claim carries the number that supports it.**

- Good: "Guided runs never missed a refutation; coverage-only left 3, 16 and
  5 false rules standing on seeds 0-2."
- Bad: "Guidance clearly helps."

Cover, as applicable:

1. **What broke and why it matters.** Name each real bug found, with the
   rule, the counterexample, and the round.
2. **What survived.** Separate the true rules (the control, such as `clamp`'s
   bounds) from artifacts that are identical on every input (harness
   artifacts, or tracer guesses like the 64-for-16 array size). Survival is
   not proof; give the closest approach.
3. **Comparison**, if more than one mode or seed: differences with counts,
   and whether they hold on every seed or only on some.
4. **Cost**: executions, seconds per input, and where the time went (tracer,
   Kvasir, Daikon).
5. **Caveats**: small corpus, few seeds, test programs written alongside the
   tool. State them plainly, without hedging every sentence.

Finish with at most one line suggesting a next step, if there is an obvious
one.

## Style

- Plain English. Explain a term the first time it is used ("refuted means
  Daikon stopped reporting the rule because an input broke it").
- Tables over paragraphs for anything with more than three numbers.
- Do not round in a way that changes meaning. Write "143 vs 137", not "about
  the same".
