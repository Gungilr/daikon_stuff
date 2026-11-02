# Getting precise, scalable invariants out of Daikon from black-box traces and fuzzing workloads

Method note: plse.cs.washington.edu could not be reached from this session (DNS blocked). Primary source used instead: the Daikon manual sources in the codespecs/daikon GitHub repo, shallow clone at commit e96cd15 (2026-10-30), `doc/daikon.texinfo` (user manual, now says "Daikon version 5.9.1") and `doc/developer.texinfo`, plus the Java source under `java/daikon`. Treat these as the 5.8.x/5.9.x manual text. The project is 5.8.x-era. Option names quoted below were stable across those versions as far as I can tell, but I did not diff 5.8.x against 5.9.1. GitHub file links below point at `master`. `[unverified]` marks claims I could not check against a primary source.

## Q1. Which Daikon options and config parameters most affect precision, and what do the docs recommend?

### Takeaway
Daikon never reports an invariant that a sample falsified. Precision losses therefore come from three places: (a) invariants that were true by chance, controlled by `--conf_limit` and the per-invariant `computeConfidence`; (b) noise variables and nonsense comparisons, controlled by comparability, `--var-omit-pattern`, derived-variable switches and turning off invariant classes; (c) output filters that hide correct facts, so a filter's choice of leader can also *distort* what gets shown. For a refutation-driven fuzzing loop, the main levers are the following:
- Raise `--conf_limit`.
- Drop variables you cannot name correctly.
- Disable invariant classes that make no sense for raw machine words.
- Keep everything in the `.inv` file, filter at print or check time, and refute with InvariantChecker.

### Cited Findings
- **`--conf_limit`.** "If the confidence level for a given invariant is larger than the limit, then Daikon outputs the invariant. This mechanism filters out invariants that are satisfied purely by chance... Daikon never outputs invariants that were ever false." The default is .99, and "Larger values yield stronger filtering." Each invariant type has its own `computeConfidence`. For `a<b` it is `1 - 1/2^numsamples`, so 3 samples give 0.875 and 9 samples give 0.998. — [daikon.texinfo, "Options to control invariant detection"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- `--conf_limit 0` "causes all properties that have not been falsified to be printed". — [daikon.texinfo, "True invariants are not reported due to output filters"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- The config equivalent is `daikon.inv.Invariant.confidence_limit` (default `.99`): "Invariants are displayed only if the confidence that the invariant did not occur by chance is greater than this." — [Invariant.java](https://github.com/codespecs/daikon/blob/master/java/daikon/inv/Invariant.java)
- **Diagnosing confidence.** `java daikon.diff.Diff MyFile.inv.gz` or `daikon.PrintInvariants --dbg daikon.PrintInvariants.repr MyFile.inv.gz` prints each invariant's confidence. `--disc_reason all` prints why each discarded invariant was dropped, and `--track` follows one invariant through processing. — [daikon.texinfo, "Options to control invariant detection" / "Missing output invariants"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Invariant filters.** All are enabled by default, each with its own enable switch ("Options to enable/disable filters"):
  - DerivedParameterFilter: suppresses EXIT invariants over post-state pass-by-value parameters.
  - ObviousFilter: suppresses invariants implied by printed ones.
  - OnlyConstantVariablesFilter.
  - ParentFilter: suppresses invariants implied by a parent program point (ppt) in the dataflow hierarchy.
  - SimplifyFilter: only active with `--suppress_redundant`.
  - UnjustifiedFilter: "Currently the limit is .01", i.e. it shows only invariants whose estimated chance probability is below 1%.
  - UnmodifiedVariableEqualityFilter: ESC output only.

  — [daikon.texinfo, "Invariant filters"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Equality optimisation and leaders.** "Daikon chooses one variable (the leader) from the set of equal variables, and only prints invariants over the leader. Suppose that a = b = c. Then Daikon will print a = b and a = c, but not b = c... might print a > d, but would not print b > d." — [daikon.texinfo, "Equal variables"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **`daikon.Daikon.undo_opts`** (default false): "Controls whether the Daikon optimizations (equality sets, suppressions) are undone at the end to create a more complete set of invariants. Output does not include conditional program points, implications, reflexive and partially reflexive invariants." `DaikonSimple` is a reference implementation without these optimisations. — [Daikon.java](https://github.com/codespecs/daikon/blob/master/java/daikon/Daikon.java), [DaikonSimple.java](https://github.com/codespecs/daikon/blob/master/java/daikon/DaikonSimple.java)
- **Suppression (non-instantiating suppressions, NIS).** "processing of an invariant is postponed as long as certain other invariants that logically imply it hold." `--omit_from_output s` (omit suppressed invariants from the `.inv` file) "will cause subtle output changes", while `0` and `r` are safe. The algorithm is chosen by `daikon.suppress.NIS.suppression_processor`: HYBRID (default), ANTECEDENT or FALSIFIED. — [daikon.texinfo, "Options to control Daikon output"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo); [NIS.java](https://github.com/codespecs/daikon/blob/master/java/daikon/suppress/NIS.java)
- **`--suppress_redundant`** uses the Simplify prover to remove more logically implied output. It is slow, and is tunable via `daikon.simplify.Session.simplify_max_iterations` and `simplify_timeout`. — [daikon.texinfo](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Dynamic constants.** `daikon.DynamicConstants.use_dynamic_constant_optimization` (default true) "doesn't instantiate invariants over constant variables (i.e., those that have only seen one value). When the variable receives a second value, invariants are instantiated and are given the sample representing the previous constant value." — [DynamicConstants.java](https://github.com/codespecs/daikon/blob/master/java/daikon/DynamicConstants.java)
- **Splitters and conditional invariants.**
  - `daikon.split.PptSplitter.disable_splitting` (default false) disables the built-in rules, which "look for implications based on boolean return values and also when there are exactly two exit points from a method."
  - `daikon.split.SplitterList.all_splitters` (default true) enables "indiscriminate splitting".
  - Conditional output is governed by `output_conditionals` (default true).

  Splitters multiply the program points that get tested, so each extra conditional ppt is another chance for a fact to hold by luck `[inference]`. — [PptSplitter.java](https://github.com/codespecs/daikon/blob/master/java/daikon/split/PptSplitter.java), [SplitterList.java](https://github.com/codespecs/daikon/blob/master/java/daikon/split/SplitterList.java)
- **Ppt and variable selection.**
  - `--ppt-select-pattern`, `--ppt-omit-pattern`, `--var-select-pattern` and `--var-omit-pattern` take Java regexes, and omit takes precedence over select.
  - The var patterns apply to derived variables too ("whether in the trace file or derived").
  - Ppt patterns "can save time even if there are no samples for the excluded program points".
  - The same filters are best applied in the front end, so "the target program will run faster and the trace file will be smaller."

  — [daikon.texinfo, "Processing only part of the trace file"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **"Too much output" (the official advice).** "You should always use the DynComp tool... to avoid producing such properties" (unrelated-variable comparisons). Beyond that:
  - Disable whole invariant classes that are irrelevant to the domain, e.g. bitwise ones.
  - Exclude variables, procedures and derived variables.
  - Use the redundancy options.

  Also: "Some irrelevant output indicates a deficiency in your test suite... does not execute the code with a broad distribution of values... This problem disappears if you augment your test suite so that it exercises the code with more different values." — [daikon.texinfo, "Too much output"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Disabling derived variables** "significantly improves Daikon's performance at the cost of producing fewer invariants" (the manual's large-example advice). The config switch is `daikon.Daikon.disable_derived_variables` (default false), and finer per-derivation switches exist ("Options to enable/disable derived variables"). — [daikon.texinfo, "Dealing with large examples"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo); [Daikon.java](https://github.com/codespecs/daikon/blob/master/java/daikon/Daikon.java)
- `--disable-all-invariants`, then re-enabling a chosen set via `--config_option daikon.inv.<...>.enabled=true`, is supported. — [daikon.texinfo, "Options to control invariant detection"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- `--nohierarchy` treats each ppt independently. It is meant for "applications that do not have a concept of hierarchy" and for traces with unmatched ENTER samples. — [daikon.texinfo](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Hierarchy-free, partial traces.** `daikon.FileIO.ignore_missing_enter` makes Daikon "ignore exit ppts that don't have a matching enter ppt rather than exiting with an error. Unmatched exits can occur if only a portion of a dtrace file is processed." — [FileIO.java](https://github.com/codespecs/daikon/blob/master/java/daikon/FileIO.java)
- **The test-suite flags are not Daikon flags.** `--ignore-globals`, `--nesting-depth=N` and `--disambig` are Kvasir front-end options. `--nesting-depth`/`--struct-depth` limit how deeply struct fields are dumped, `--ignore-globals`/`--ignore-static-vars` drop globals and statics, and `--disambig` reads or writes a pointer-vs-array disambiguation file. The manual lists them under "Reducing variables" as ways to make big programs tractable. — [daikon.texinfo, "Kvasir options" / "Reducing variables"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)

### Inferences
- **Recommended Daikon invocation for a refuting fuzzer.** Run Daikon with a raised `--conf_limit` (e.g. 0.999 or more) for the facts you *hand to the fuzzer as claims*. Keep a low-conf `.inv` (or `--conf_limit 0`) as the candidate pool. Confidence grows with sample count, so with fuzzing-scale sample counts a high limit costs little recall but kills small-sample flukes.
- **Invariant classes to disable for raw machine words.** For black-box machine-word variables, disable invariant classes whose truth is almost always an artifact of a narrow value distribution. Candidates `[inference; measure on fixtures]`:
  - Modulus/NonModulus.
  - Bitwise subset (`BitwiseComplement`/`BitwiseSubset`-style), when the variables are not known to be flag words.
  - OneOf over pointer-ish ints. `daikon.inv.unary.scalar.OneOfScalar` has an `OneOf_only` setting (`dkconfig_OneOf_only` default false). Its exact semantics are `[unverified]`.
- **Leader choice can make a correct fact look like a wrong one.** Filters operate on the *leader* of an equality set. If the front end emits a variable that is always equal to `orig(x)` (modbits/unchanged args), then `x == orig(x)` is printed, and every other invariant is printed only over the leader. If the leader is a post-state `is_param` variable, DerivedParameterFilter can then hide it (see Q2). The effect is distortion as much as removal.
- For an *evaluation against the Kvasir oracle*, reproducing Kvasir's variable set (Kvasir-style names, `--nesting-depth=1`, no globals) matters more than Daikon tuning. Most of the measured unmatched facts (64%) are about undeclared variables (project EVALUATION-KVASIR-SUITE.md).

### Gaps
- The full generated list of config options (`config-options.texinfo`) is built at release time and is not in the repo. I read only selected options from source. I did not obtain the exact names of the per-filter enable switches (I expect `daikon.inv.filter.<FilterName>.enabled`, `[unverified]`).
- I did not read the `computeConfidence` of LinearBinary/LinearTernary, which are generated from `.jpp` templates not in my sparse checkout. How confidence scales with distinct values versus raw sample count is therefore `[unverified]` for linear invariants.

## Q2. How do modbits, comparability (DynComp), is_param, nonsensical values and hashcode rep-types affect output, and what should a front end without debug info emit?

### Takeaway
Modbits that are always 1 are explicitly "safe". Daikon can also *recompute* them itself: set `daikon.FileIO.add_changed=false` to get modbit=1 iff the value changed. The redundant `argN == orig(argN)` facts are mostly real equalities that the leader/filter machinery prints, and `is_param` is what normally suppresses post-state parameter noise; it does so by filtering any EXIT invariant whose leader is a post-state param. Comparability is the main documented precision lever ("always use DynComp"). Without DynComp, a black-box front end should still emit coarse, *sound-enough* comparability classes rather than `-1` (comparable to everything). It should also use `hashcode` for anything pointer-like and `nonsensical` with modbit 2 for unreadable or invalid memory.

### Cited Findings
- **Modbits format.** "modified? (0, 1, or 2). This value is 0 if the variable has not been assigned to since the last time this program point was executed, and 1 if [it] has been assigned... It is safe for an implementation to always set it to 1. It is also safe to always set it to 0, because Daikon corrects obviously incorrect modification bits... The special value 2 should be used only (and always) when the value field is nonsensical." — [developer.texinfo, data trace record format](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo)
- **`daikon.FileIO.add_changed`** (default true): "When false, set modbits to 1 iff the printed representation has changed. When true, set modbits to 1 if the printed representation has changed; leave other modbits as is." In code, an unchanged value representation is set to UNMODIFIED only when `add_changed` is false. — [FileIO.java ~L140–146, ~L2217–2222](https://github.com/codespecs/daikon/blob/master/java/daikon/FileIO.java)
- **Where modbits matter.** `--output_num_samples` prints a "Samples breakdown" of modified (m), unmodified (u) and nonsensical (x) samples, and "These types affect statistical tests that determine whether a particular invariant... is printed." In current source, though, the modbit-based confidence formulas in `Modulus`/`NonModulus` (`ppt.num_mod_samples()`) are commented out. The influence of modbits on confidence may therefore now be small `[partially verified]`. — [daikon.texinfo, `--output_num_samples`](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo); [Modulus.java L223, NonModulus.java L185](https://github.com/codespecs/daikon/tree/master/java/daikon/inv/unary/scalar)
- **`is_param` (documented semantics).** "Some procedures reassign parameters — essentially using them as local variables. Such uses are not relevant to the procedure's external specification. The is_param flag causes Daikon not to print certain invariants, if the variable has been reassigned":
  1. Invariants that use the post-state form of a parameter `p` are not printed.
  2. Invariants over fields `p.x` are printed only if `p` is unchanged.
  3. Some immutable characteristics, such as array sizes, are not printed.

  — [developer.texinfo, "Variable declarations" / flags](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo)
- **`is_param` (code).** `VarInfo.isDerivedParamAndUninteresting()` returns true ("not interesting, IS_PARAM == true") for any non-prestate variable with `isParam()`. DerivedParameterFilter uses this to drop EXIT invariants. `PrintInvariants` lists a param whose post value differs from orig as "reassigned_parameters" rather than "modified". — [VarInfo.java ~L1275–1285](https://github.com/codespecs/daikon/blob/master/java/daikon/VarInfo.java); [PrintInvariants.java ~L1018–1026](https://github.com/codespecs/daikon/blob/master/java/daikon/PrintInvariants.java)
- **Comparability keys.**
  - A non-array key is a signed integer. Two variables are comparable "if both integers are the same, or if either integer is negative (that is, a negative number means 'comparable to every other variable')."
  - Array keys look like `8[5]` (element class 8, index class 5).
  - "Variables at different program points are never compared."
  - The `implicit` comparability type is the default.

  — [developer.texinfo, "Variable declarations" / "Variable comparability"](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo)
- **`daikon.VarInfo.declared_type_comparability`** (default true): variables "are only considered comparable if they are declared with the same type... This may miss valid invariants, but significant time can be saved." So `dec-type` strings act as an extra comparability partition. — [VarInfo.java](https://github.com/codespecs/daikon/blob/master/java/daikon/VarInfo.java)
- **Equality sets follow comparability.** "You can control which variables are in an equality set; see Variable comparability." — [daikon.texinfo, "Equal variables"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **`hashcode` rep-type** "is intended for unique object identifiers like memory addresses (pointers)... treated like int, except that the hashcode values are considered uninteresting for the purposes of output", e.g. "var has only one value" instead of `var == 0x38E8A`. DtraceDiff compares hashcodes only as null versus non-null. `daikon.DynamicConstants.skip_hashcode_type` defaults to true. — [developer.texinfo](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo); [daikon.texinfo, "Has only one value variables" / "DtraceDiff utility"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo); [DynamicConstants.java](https://github.com/codespecs/daikon/blob/master/java/daikon/DynamicConstants.java)
- **Nonsensical values.** "It is the responsibility of the front end to perform a check at run time whenever a variable's value is about to be output... and to output the value nonsensical rather than crashing the program or outputting an uninitialized or meaningless value. (Determining when an expression's value is meaningless is the most challenging part of writing an instrumenter for a language like C, since it requires tracking memory allocation and initialization.)" The modbit must be 2, and `daikon.Daikon.guardNulls` controls how output is guarded. — [developer.texinfo, "Nonsensical values"](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo)
- **Other useful decl attributes for a black-box front end:**
  - `min-value`/`max-value`/`min-length`/`max-length`, which let Daikon suppress obvious bounds such as `var <= v`. Example: width-derived bounds like 0..255 for a byte load.
  - `flags synthetic` for front-end-invented variables.
  - `nomod` for never-modified variables.
  - `non_null`, which suppresses NonZero.
  - `constant <value>`: the variable is then omitted from records.

  — [developer.texinfo, "Variable declarations"](https://github.com/codespecs/daikon/blob/master/doc/developer.texinfo)

### Inferences
- **Modbits fix (cheap and worth testing first).** Keep emitting 1 but run Daikon with `--config_option daikon.FileIO.add_changed=false`, or have the front end emit 0 when the value equals the previous sample at that ppt. Neither removes the `argN == orig(argN)` *equality*, because that is a genuine value fact. It removes only modbit-related "modified" noise. The redundant facts themselves should be removed in post-processing: drop `x == orig(x)` at EXIT for register- or stack-passed scalar args, which is exactly what C pass-by-value makes uninteresting.
- **Likely mechanism of the `is_param` coefficient defect** `[inference, not verified by experiment]`. With `is_param` set, any EXIT invariant whose printed variables include a post-state param is filtered. Daikon also prints `2*a - b + 3 == 0` over the equality-set *leader*. If post-state `a` and `orig(a)` are in one equality set and the leader is the post-state variable, the linear invariant is filtered, while unit-coefficient forms may survive through other paths or ppts.
  - Remedies to test: (i) set `is_param` but disable only DerivedParameterFilter (`daikon.inv.filter.DerivedParameterFilter.enabled=false`, name `[unverified]`); (ii) emit `is_param` and rely on the `orig(...)` copies; (iii) skip `is_param` and post-filter `x == orig(x)` yourself.
  - Use `--disc_reason`/`--track` on `LinearBinary<a,b>@foo:::EXIT` to confirm which filter fires.
- **Comparability without debug info.** `-1` everywhere makes every scalar comparable to every other, which the manual says produces "irrelevant properties... over unrelated variables". Cheap partitions a binary front end can compute:
  - Separate pointer-valued (`hashcode`) from integer-valued words.
  - Separate by access width or signedness (byte, short, word, qword loads).
  - Separate return/arg registers from memory-derived fields.
  - Optionally run a value-flow ("DynComp-lite") union-find over registers and memory during emulation: values that flow into the same arithmetic or compare instruction share a class. This mirrors what Kvasir's DynComp does for C.
- **Use `dec-type` deliberately.** Because `declared_type_comparability` is on by default, a distinct `dec-type` string per inferred abstract type (e.g. `ptr`, `u8`, `i32`) gives a second free partition.
- **Pointer-root globals.** When adding globals as pointer roots, declaring them `hashcode` (not `int`) avoids ordering and linear facts between addresses. Restricting their fields to their own comparability class should contain the reported "output explosion" `[inference]`.

### Gaps
- No measured data found on how much DynComp improves precision for C/binary traces. The manual asserts it ("always use DynComp") but I found no numbers.
- I did not confirm whether `add_changed=false` changes printed invariants in 5.8.x (versus only sample-breakdown statistics).

## Q3. How to make Daikon handle many traces: online mode, sampling, merging, DtraceDiff, InvariantChecker, memory

### Takeaway
Daikon has no true incremental mode that updates an existing `.inv` file from a new trace. What it offers:
- **MergeInvariants**, which combines per-chunk `.inv` files. The manual says "should be the same as running Daikon on the N original .dtrace files".
- **InvariantChecker**, which takes an `.inv` file plus new dtraces and reports violated invariants. This is exactly the refutation primitive a fuzzing loop needs.
- **Online execution** through pipes, and **`--server` mode**, which reads files from a directory as they appear.

Cost is driven by ppts × variables per ppt (including derived variables), so pruning variables is the dominant scaling knob. Sampling executions is possible, but its results cannot be merged back into an equivalent result.

### Cited Findings
- **MergeInvariants** "merges multiple serialized invariant files to create a single serialized invariant file that contains the invariants that are true across each of the input files. The results of merging N serialized invariant files should be the same as running Daikon on the N original .dtrace files." Usage: `java daikon.MergeInvariants [-o out.inv] file1 file2...`. — [daikon.texinfo, "MergeInvariants"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Split and merge for large inputs.** "First... split your .dtrace file into parts. Next, run Daikon on each resulting .dtrace file. Finally, use the MergeInvariants tool... to combine the resulting .inv files into one." — [daikon.texinfo, "Multiple smaller files"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **InvariantChecker.** "takes a set of invariants found by Daikon and a set of data trace files. It checks each sample in the data trace files against each of the invariants. Any sample that violates an invariant is noted." Options:
  - `--output file`.
  - `--conf`: only invariants above the default confidence.
  - `--filter`: only invariants not removed by the default filters.
  - `--verbose`: print every violating sample.
  - `--dir dir`: process all `.inv` files in a directory and count invariants failed by any dtrace there.

  Invocation: `java daikon.tools.InvariantChecker [options] invs.inv.gz trace1.dtrace ...`. — [daikon.texinfo, "InvariantChecker"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Online execution.** "running Daikon at the same time as the target program. The front end supplies information to Daikon directly over a socket or pipe... Kvasir... supports online execution via... Linux pipes." Also: "In the future, Daikon may be able to output partial results as the target program is executing" (i.e. it currently does not). — [daikon.texinfo, "Run Daikon online"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **`--server dirname`**: "reads files from dirname as they appear (sorted lexicographically) until it finds a file ending in .end, at which point it calculates and outputs the invariants." `--files_from` reads the list of file names from a file. — [daikon.texinfo, "Options to control Daikon output"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Reducing executions.** "Here are ways to run Daikon over fewer executions of each program point. (You cannot combine the resulting invariants in order to obtain the same result as running Daikon over all the executions.)" Options include running on a subset of dtrace files, truncating (`trace-untruncate` repairs a partial last record) and front-end sampling of procedure executions. `daikon.FileIO.max_line_number` caps the lines read, and `daikon.Daikon.ppt_perc` processes the first N% of ppts sorted by name. — [daikon.texinfo, "Reducing executions" / "Reducing program points"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo); [FileIO.java](https://github.com/codespecs/daikon/blob/master/java/daikon/FileIO.java), [Daikon.java](https://github.com/codespecs/daikon/blob/master/java/daikon/Daikon.java)
- **Memory.** Out-of-memory "is likely that it has created more invariants than will fit in memory. The number of invariants created depends on the number of program points and the number of variables at each program point."
  - Use `-Xmx` (manual example `-Xmx7g`).
  - Check derived variables with `--output_num_samples` and disable the ones you don't need.
  - "Any output generated before the out-of-memory error is perfectly valid."

  "Daikon's running time depends on both the length of the test run and the size of the program data (such as its use of global variables and nested data structures)." — [daikon.texinfo, "Out of memory" / "Dealing with large examples"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **Compression and disk.** `.dtrace.gz` is read transparently, and "Compression is the default" for Chicory/Kvasir. The manual also suggests prune "as early in the process as possible... better to have the front end output less information, rather than have Daikon ignore some of the information." — [daikon.texinfo, "Large dtrace files" / "Less information per file"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **`--omit_from_output 0r`** shrinks `.inv` files by about 10% typically. It helps more with many unused ppts or many variables, and is "safe". — [daikon.texinfo](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **DtraceDiff** compares two dtraces content-wise (same ppts in the same order, same variables and values). It stops at the first difference, compares hashcodes only as null versus non-null, and compares floats fuzzily. It supports the ppt/var select and omit patterns. — [daikon.texinfo, "DtraceDiff utility"](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **`--no-dtrace-pretty`.** No such Daikon option appears in the manual source I searched `[not found]`. Relevant real knobs: `daikon.FileIO.dtrace_line_count`, which skips line counting for the progress display, and `daikon.FileIO.read_samples_only`, which only reads samples, for timing. — [FileIO.java](https://github.com/codespecs/daikon/blob/master/java/daikon/FileIO.java)

### Inferences
- **Recommended fuzzing loop architecture:**
  1. Seed corpus → Daikon → `seed.inv.gz`.
  2. Each fuzz batch → dtrace → `InvariantChecker --conf --filter seed.inv.gz batch*.dtrace.gz`, whose output lists violated invariants.
  3. Refuted invariants are dropped. Inputs that refute are kept as "diversity" seeds.
  4. Periodically re-infer from the union. Either rerun Daikon or run Daikon per batch and use MergeInvariants, whose result equals inference over all traces.

  Merging is associative in principle, so batches can be inferred in parallel.
- **Re-inference is needed, not only checking.** InvariantChecker checks only invariants that *exist* in the `.inv`. Weaker invariants that should replace refuted ones (e.g. `i <= j` after `i < j` dies) appear only after re-inference. Keeping the `.inv` built with `--conf_limit 0` is unproven but plausibly gives the checker a larger candidate pool `[inference]`.
- **Keep the dtrace small for fuzzing scale.** Prune at the front end (fewer ppts, fewer variables, no derived variables for checker runs). Skip writing pretty traces: a minimal one-value-per-line format is already what Daikon reads, and `.gz` saves disk. For extremely many executions, sample per-ppt (e.g. cap N samples per ppt per batch) *only for inference*, never for refutation.

### Gaps
- InvariantChecker's runtime and memory at fuzzing scale: no published benchmarks found.
- Whether MergeInvariants preserves exact confidence (sample counts) across merged files, and so exactly reproduces a single-run `--conf_limit` decision, is asserted by the manual but not verified here.

## Q4. Measured reports of Daikon precision issues and remedies in the literature

### Takeaway
Empirical studies consistently show that Daikon's output mixes real specifications with facts about the test suite. Value diversity (more and varied executions) is the documented remedy. Humans are poor judges of which inferred invariants are correct, which supports automatic refutation (fuzzing, symbolic checking) over manual triage.

### Cited Findings
- **Polikarpova, Ciupa and Meyer (ISSTA 2009)** applied Daikon to 25 classes and compared more than 19,500 inferred clauses with programmer-written contracts. Daikon found about 60% of the programmer-written clauses and generated "around five times as many relevant assertion clauses". They concluded inference strengthens contracts but does not replace them. — [Daikon pubs abstract](https://plse.cs.washington.edu/daikon/pubs/PolikarpovaCM2009-abstract.html); [Meyer blog summary](https://bertrandmeyer.com/2009/08/03/contracts-human-machines/) (secondary; the abstract page could not be fetched directly, so this summary comes from search snippets)
- **Staats, Hong, Kim and Rothermel (ISSTA 2012, "Understanding User Understanding: Determining Correctness of Generated Program Invariants")**: users misclassified 9–32% of correct invariants and 26–59% of incorrect ones. The figures are reported second-hand by a later paper. — [ISSTA 2012 program](https://crisys.cs.umn.edu/issta2012/program.shtml); figures via [arXiv 1903.06089 "Are My Invariants Valid? A Learning Approach"](https://arxiv.org/pdf/1903.06089) `[secondary]`
- **Hong, Kim and Staats (KCSE 2012)** propose validating Daikon-inferred invariants with symbolic execution. — [KAIST pdf](https://swtv.kaist.ac.kr/publications/2012/kcse2012_S.Hong.pdf/)
- **The Daikon manual's own position:** spurious output "indicates a deficiency in your test suite... does not execute the code with a broad distribution of values". In its `i < j` example, the reported `i < j` is "an example of a false positive or overfitting" that a longer run with `i=j=22` would correct. — [daikon.texinfo](https://github.com/codespecs/daikon/blob/master/doc/daikon.texinfo)
- **"Invariant inference for static checking: An empirical evaluation"** (Nimmer and Ernst, FSE 2002) is a primary study of how many Daikon invariants a static checker could verify. I did not retrieve its numbers. — [abstract](https://homes.cs.washington.edu/~mernst/pubs/annotation-study-fse2002-abstract.html)
- **DySy (Csallner, Tillmann, Smaragdakis, ICSE 2008)**, on Daikon's own benchmark, "infers the majority of the interesting Daikon invariants, while eliminating invariants that a human user is likely to consider irrelevant." — [DySy abstract](https://plse.cs.washington.edu/daikon/pubs/CsallnerTS2008-abstract.html)
- **SpecFuzzer (Molina, d'Amorim, Aguirre; ICSE 2022; tool paper ASE 2023)** generates candidate assertions with grammar-based fuzzing, uses Daikon to discard candidates falsified by a test suite, then ranks and clusters the survivors with mutation analysis. On 43 Java methods it was more effective than GAssert and EvoSpex by precision/recall. It is a direct precedent for "Daikon as a falsification filter plus extra refutation". — [arXiv 2201.10874](https://arxiv.org/abs/2201.10874v1); [ASE 2023 tool demo](https://conf.researchr.org/details/ase-2023/ase-2023-tool-demonstrations/2/SpecFuzzer-A-Tool-for-Inferring-Class-Specifications-via-Grammar-based-Fuzzing)

### Inferences
- The project's design choice of a fuzzer refuting invariants is well aligned with the literature. The manual explicitly frames false positives as test-suite artifacts that more diverse values remove, and SpecFuzzer/GAssert/EvoSpex all use generated inputs to falsify candidates.
- Because humans misclassify a large fraction of generated invariants (Staats et al.), the project's precision metric against the Kvasir oracle is a better guide than manual inspection. "False" should mean *refuted by some execution*, not "not in the oracle".

### Gaps
- I found no primary-source figure for the fraction of Daikon output that is *false* (as opposed to irrelevant) on C programs.
- I did not retrieve SpecFuzzer's Daikon-alone baseline precision numbers.
- No study found that measures Daikon precision as a function of fuzzing-generated (vs. test-suite) executions.

## Q5. Alternatives and complements to Daikon for black-box traces

### Takeaway
DIG/SymInfer/NumInv (ThanhVu Nguyen et al.) infer nonlinear numerical equalities and inequalities and, with symbolic states, verify them via counterexample-guided refinement (CEGIR). That makes them more sound than template checking, but they need source or symbolic access. For pure trace input, DIG-style polynomial equality solving over traces is a direct complement for the linear and nonlinear arithmetic facts Daikon misses or misfilters. Texada (LTL over event logs), InvGen and neural approaches were not researched in depth here.

### Cited Findings
- **SymInfer** (Nguyen, Dwyer, Visser; arXiv 1903.11768) uses Symbolic PathFinder states to infer and verify numerical invariants, including nonlinear ones. It seeds candidates with DIG from concrete states, then checks them via verification conditions and an SMT/SAT solver with counterexample refinement (CEGIR). It reports quality comparable to NumInv but faster. It notes that Daikon-based iDiscovery does not support nonlinear properties, and that for non-numerical variables Daikon/iDiscovery may infer more. — [arXiv 1903.11768](https://arxiv.org/pdf/1903.11768)
- **DySy** uses dynamic symbolic execution (path conditions) rather than value templates, and reduces "irrelevant" invariants compared with Daikon. — [DySy ICSE 2008 pdf](https://people.cs.umass.edu/%7Eyannis/dysy-icse08.pdf)
- **SpecFuzzer** combines a grammar-based candidate generator, a Daikon falsification filter and mutation-based ranking. — [arXiv 2201.10874](https://arxiv.org/abs/2201.10874v1)

### Inferences
- For black-box traces, running DIG's equation solver over the same per-ppt value tables would independently recover facts like `2*a - b + 3 == 0`, which the project currently loses to the `is_param` filter interaction. Cross-checking agreement between DIG and Daikon is a cheap precision signal `[inference]`.
- A symbolic-execution complement is plausible for binaries because the project already emulates them (Unicorn). One option is to validate a Daikon invariant per function by checking it over symbolic paths (à la Hong/Kim/Staats, SymInfer). That approach would be more sound than fuzzing alone `[inference, cost unknown]`.

### Gaps
- Not researched within the tool-call budget: Texada (Lemieux et al., LTL property mining), InvGen, ICE/PIE learners (mentioned only via SymInfer), and neural or LLM invariant inference (e.g. Pei et al. 2023). Their fit for black-box traces is unassessed.
- No sourced comparison of DIG versus Daikon precision on trace-only (no symbolic) input was found.
