# Phase 0 — Package refactor + test harness (as built)

Status: **complete**. Gate passed, 46 tests green, full corpus at 0 failures.

Companion to the master plan. This records what was actually built and, more
usefully, where reality diverged from the plan.

## What shipped

```
scripts/tracer/          1043 lines total (was one 944-line script)
  __init__.py     18     no re-exports, deliberately
  log.py          25     Logger                             pure
  schema.py       53     NUM_STACK_ARG_SLOTS, REG_VARS_*    pure
  writer.py       60     DaikonTraceWriter                  pure
  elfload.py     184     ELF parse + function discovery     pyelftools
  emulate.py     549     Tracer, main recovery              unicorn + capstone
  cli.py         138     build_parser, main, usage docstring
scripts/unicorn_dwarf.py  16   shim
pytest.ini                     testpaths / pythonpath / norecursedirs
tests_py/                 46 tests, 6 files
tests_py/golden/               tier-0 regression oracle
```

`emulate.py` and `cli.py` were extracted with `sed` line ranges rather than
retyped, so the copy is provably verbatim.

New flag `--tier 0..7`, parsed and stored but unused. Named `--tier` rather than
`--layer` because `--layers` (stack relocation) already exists.

## Deviations from plan

**1. pytest didn't error on collection — it hung.** The plan predicted
`scripts/daikon_test.py` would raise during collection (it runs
`pefile.PE("test.exe")` at module level against a nonexistent file). Measured
behavior was worse: bare `pytest` never terminated, because it walks `daikon/`
(full vendored java tree), `unicorn-2.0.1/`, and `venv/` first. A hang is
strictly harder to diagnose than a traceback. `pytest.ini` therefore needs
`norecursedirs` in addition to `testpaths`; the plan called for only the latter.
Collection now completes in 0.24s.

**2. The gate oracle had to be committed, not archived to /tmp.** The plan said
"archive every `.dtrace` outside the repo". That works for a one-shot gate but
evaporates, leaving the e2e test permanently skipped. Instead
`tests_py/golden/test08.tier0.dtrace` is committed. This is strictly better than
planned: since tiers 1+ are opt-in via `--tier`, tier-0 output must never move
again, so the golden is a permanent regression guard rather than a throwaway.

**3. `__init__.py` must stay empty of re-exports.** Not in the plan. Importing
`tracer.writer` executes `tracer/__init__.py` first, so the "version, public
re-exports" the plan called for would have dragged unicorn into every pure
import and silently voided the entire purity boundary. `test_purity.py` now
greps `__init__.py` for `from .emulate` / `from .elfload` to keep it that way.

**4. The purity probe needed a negative control.** A blocker that silently
stopped blocking would make all four purity tests pass for the wrong reason.
`test_blocker_actually_blocks` asserts `tracer.emulate` and `tracer.elfload`
*do* fail under the block.

## Issues from the plan: disposition

| # | Issue | Outcome |
|---|---|---|
| 1 | `sys.exit(1)` at import | Confined to `emulate.py` / `elfload.py`; enforced by `test_purity.py`. Converting to `raise` deferred — it is a behavior change. |
| 2 | pytest collects the scripts | Fixed, and worse than predicted (see deviation 1) |
| 3 | `zip()` silent truncation | `add_sample` now raises `ValueError`; 2 tests |
| 4 | `NUM_STACK_ARG_SLOTS` drift | Single definition in `schema.py`; arithmetic pinned by test |
| 5 | `--layer` / `--layers` collision | `--tier` chosen; test asserts `--layer` exits nonzero |
| 6 | `Samples:` log contract | e2e test applies test.sh's exact regex; confirmed live (`samp=42`) |
| 7 | `Tracer` bound to argparse Namespace | Deferred as planned |
| 8 | 147-line `run()` | Left intact as planned; split belongs in Phase 2 |
| 9 | package vs class name | Accepted `tracer`; no venv/stdlib conflict |
| 10 | sys.path for tests | `pythonpath = scripts` in pytest.ini |
| 11 | `__pycache__` | `.gitignore` updated |
| 12 | determinism | **Verified** — two runs byte-identical; also a standing e2e test |

## Acceptance evidence

- Determinism: two runs of `test08.exe`, byte-identical.
- Gate: all 8 corpus binaries byte-identical to pre-refactor baseline.
- `--tier 0` byte-identical to no flag; `--layer 3` exits 2.
- `--help` still renders the usage epilog (docstring moved with `build_parser`).
- `pytest tests_py/` → 46 passed (42 unit, 4 e2e).
- `./test.sh` full corpus → tracer 8/8, kvasir 4/4, **0 failures**.
- No new `.inv.gz` in the repo root (still 14 pre-existing).

## Carried into Phase 1

- `DaikonTraceWriter` still takes one global `var_names`. Tier 1 replaces this
  with per-ppt `VarSpec` schemas — the `ValueError` guard added here becomes
  load-bearing at that point.
- `test_writer.py` deliberately pins the *current* (Kvasir-mismatched)
  `ppt-type exit` and `EXIT1`. Tier 1 changes those; the test edits are the
  intended signal, not drift.
- Tier 0 must keep reproducing `tests_py/golden/test08.tier0.dtrace` forever.
