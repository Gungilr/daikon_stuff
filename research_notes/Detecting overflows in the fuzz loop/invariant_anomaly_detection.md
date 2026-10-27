# Invariant- and anomaly-based runtime bug detection (fit for a Daikon + fuzzer loop)

Scope note: primary PDFs were read in full text for DIDUCE (ICSE 2002), ClearView (SOSP 2009), InvsCov (USENIX Sec 2021), CBI (PLDI 2005), Eclat (ECOOP 2005), and the Halo (S&P 2024) and Binvariants (FSE 2026) slide decks. Other items come from abstracts or search summaries and are marked as such.

## DIDUCE (Hangal & Lam, ICSE 2002): online learning, relaxation, reporting, results

### Takeaway
DIDUCE is the closest published match to "flag the first deviation even when nobody designed an invariant for it". It keeps a per-expression bitmask of which bits have always been constant. The first value that flips a previously constant bit is reported and the hypothesis is relaxed, ranked by the drop in confidence. A negative return at a program point that only ever returned non-negative values flips the sign bit, so it is reported on first occurrence with no `return >= 0` template needed.

### Cited Findings
- DIDUCE "hypothesizes the strictest invariants at the beginning, and gradually relaxes the hypothesis as violations are detected to allow for new behavior"; violations are reported as they happen. — [Hangal & Lam, ICSE 2002 (PDF)](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Representation: each tracked expression has an initial value V and a mask M. M starts as all ones and V as the first value W. A new value W' is a violation iff `(W' xor V) & M != 0`, and the relaxation is `M := M & ~(W' xor V)`. — [same PDF, §3.3](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- For numbers, the mask captures (1) "whether the values were only positive or only negative, only odd or only even", (2) an approximate upper bound, and (3) which bits are constant. For references it captures null vs non-null and run-time type. — [same PDF](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Each expression can be violated at most once per bit (at most word-size times), and for a counter increasing by a constant step "the frequency of violations decreases exponentially". Storage is about 3 words per tracked expression, and the cost is a few memory and logic ops per point. — [same PDF](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Confidence = (number of evaluations) / 2^n, where n is the number of 0s in the mask. Each violation is reported with the change in confidence, and "a large drop in confidence signals a noteworthy invariant violation". The first execution of code, and run-time-type violations, get a fixed user-set confidence. — [same PDF, §3.4](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Tracked values: at instrumented points (field reads/writes, static reads/writes, procedure interfaces) it tracks the value and, for writes, the old value. Stack (local) accesses are left out. — [same PDF, §3.1-3.2](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Training mode vs checking mode: the only difference is that checking mode emits relaxation messages. Learning continues in checking mode. Learned invariants can be saved to a file and reloaded to start a later run, so a baseline carries across runs. — [same PDF](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Slowdowns on 4 Java programs: simulator 8-12x (10 machines), Mailmanage 6x, JSSE 8x, Joeq 20x. — [same PDF, Table 1](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- Results and false positives on the simulator: after training on the start of each run, "almost all the violations detected after an hour ... were interesting", except one set caused by a steadily increasing counter. Those false alarms had low confidence. DIDUCE found 2 otherwise-undetected bugs and the root causes of 3 more, and it flagged about 10 rare corner cases that the programmer found informative. It also isolated a timing-dependent bug in released JSSE. — [same PDF, §5](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- A later patent claims DIDUCE and Daikon-style tools produce many false positives. This is a secondary, non-peer-reviewed criticism. — [USPTO 8234525](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/8234525)

### Inferences
- For abs_diff: if every normal execution returned a value ≥ 0, bit 31 of the return is constant 0 in M. The first overflow input that returns a negative value violates the mask, and since many evaluations narrowed the mask, the confidence drop is large, so it ranks high. This needs no template and no Daikon re-proposal. The problem the user hit (Daikon never proposing `return >= 0` once negatives were in the corpus) goes away if the bitmask is updated online and alarms on the first flip. It does not help if a legitimate negative return was seen earlier.
- Caveat: as the fuzzer pushes arguments to extreme values, argument bitmasks relax a lot early (many low-value alarms). Ranking by confidence drop, or restricting alarms to return/exit values (see Eclat below), is the relevant filter.
- "Never forget": DIDUCE's saved-invariant file plus monotone relaxation is exactly a persistent baseline. A relaxation event is a durable record ("bit 31 of abs_diff.return was constant for N calls, then flipped on input X"), unlike Daikon's per-round re-learning, where an invariant silently disappears.

### Gaps
- No numeric false-positive rate (FP / total reports) is given in the paper; only the qualitative statements above.

## Daikon-based anomaly/bug detection: ClearView, Carrot, Eclat, Sahoo et al., IDS

### Takeaway
Daikon-style likely invariants are rarely used as the primary alarm in published systems. ClearView uses separate zero-FP monitors to detect failures and uses invariants only to locate and repair them. Eclat uses entry vs exit violations to triage generated inputs: about 30% precision versus 2.3% for unfiltered inputs. Early pure-invariant fault localization (Carrot) failed.

### Cited Findings
- ClearView (Perkins et al., SOSP 2009) works on stripped Windows x86 binaries. It learns invariants with "an enhanced version of Daikon" from normal executions. Detection comes from monitors (Memory Firewall, Heap Guard, Shadow Stack), and "current monitors have no false positives". When a monitor fires, ClearView finds *correlated* invariants (satisfied in normal runs, violated before the failure) among those at predominators of the failure PC on the call stack. — [ClearView PDF](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- ClearView's correlation levels: "Highly correlated" means violated the last time it was checked before every detected failure and satisfied all other times. Moderately and slightly correlated are weaker. — [same PDF §2.4.3](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- ClearView invariant types and repairs: one-of (e.g. call targets), lower-bound `c <= v`, and less-than `v1 <= v2`. Its rationale for lower bounds is that defects "cause an array or buffer index to be negative" or pass "a negative number as a length ... to memcpy", which "typically result in errors that violate a lower-bound invariant such as 0 <= v". — [same PDF §2.5](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- ClearView added a pointer heuristic: a variable that ever holds a negative value or a value in 1..100,000 is not a pointer, and ClearView skips lower-bound and less-than inference on pointers. Removing duplicate invariants roughly halved the invariant count. — [same PDF §2.2.4](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- ClearView results: in a Red Team exercise it blocked all 10 exploits and patched 7 of 10. The Red Team "was unable to elicit any false positives". The mean time from first attack to a successful patch was 4.9 minutes (5.4 executions on average). Learning was costly: 12 pages loaded in 5.2 s normally versus 1600 s with learning (>300x), dominated by the Daikon x86 front end. The execution environment itself added 47%. — [same PDF §1.1, §4.4](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf); [abstract](https://homes.cs.washington.edu/~mernst/pubs/automatic-patching-sosp2009-abstract.html)
- ClearView limitations: Daikon's preconfigured invariant set may lack the needed invariant, and "the learning phase may not provide enough coverage ... to learn this invariant". — [same PDF §5](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- Carrot (Pytlik, Renieris, Krishnamurthi, Reiss, AADEBUG 2003) applied Daikon-style potential invariants (equality, sum, less-than, constant) at function entry/exit to fault localization. It "could not locate any bugs" in Siemens-suite variants, and the authors call the results unsatisfactory. — [arXiv cs/0310040](https://arxiv.org/pdf/cs/0310040); [Daikon pubs page](https://plse.cs.washington.edu/daikon/pubs/pytlik-aadebug-2003-abstract.html)
- Eclat (Pacheco & Ernst, ECOOP 2005) infers an operational model (Daikon) from a correct test suite, then classifies each generated input with this decision table:

  | Entry violated | Exit violated | Label |
  |---|---|---|
  | no | no | normal |
  | no | yes | fault-revealing |
  | yes | no | (new) normal |
  | yes | yes | illegal |

  It keeps one input per violation pattern. — [Eclat PDF, Fig. 6](https://homes.cs.washington.edu/~mernst/pubs/classify-tests-ecoop2005.pdf)
- Eclat precision (Fig. 11): about 1338 inputs generated per run on average, at 2.3% fault-revealing. About 5.0 were selected, at 30% precision on average (range 0%-100% per subject). JCrasher averaged 0.92%. The paper also notes false reports caused by "a deficiency in the" test suite: behavior that differs from the suite but is correct. — [Eclat PDF](https://homes.cs.washington.edu/~mernst/pubs/classify-tests-ecoop2005.pdf)
- Sahoo, Criswell, Geigle, Adve (ASPLOS 2013) build likely *range* invariants from automatically generated correct inputs close to the failing input. They filter candidates with dynamic backward slicing, dependence filtering, and multiple failing inputs, which cuts the candidates to 5-17 program expressions on large servers. This is from the abstract and summaries; the full text was not read. — [Illinois experts page](https://experts.illinois.edu/en/publications/using-likely-invariants-for-automated-software-fault-localization/); [MSR talk abstract](https://www.microsoft.com/en-us/research/?p=189462)

### Inferences
- Eclat's table maps directly onto the loop. For an abs_diff call with in-range-looking arguments (no entry violation) and a negative return (exit violation), the label is fault-revealing. Large or negative arguments that newly violate entry invariants would still be labeled *illegal* if the exit is also violated, so entry invariants learned from a 1-seed corpus (`x == 5`) would wrongly suppress the alarm. This argues for using only weak or type-derived entry conditions, or only exit-value anomalies, as the alarm.
- ClearView's lesson: pair the invariant anomaly with a precise oracle (a sanitizer or trap) when one exists. Use invariants for triage and explanation, not as the sole alarm.

### Gaps
- Invariant-based intrusion detection (Sekar et al. FSA models; Gao et al. gray-box execution graphs; "learning program behavior" profiles) was not researched in this pass. No sourced FP numbers here.
- Ernst et al., "Dynamically discovering likely program invariants to support program evolution" (TSE 2001), was not fetched. It is the foundational Daikon paper and is not specifically an alarm technique.
- No primary source was found for "mutation-based checking of invariants" in an alarm role.

## Value-profile / novelty approaches and statistical predicates (CBI, IJON, InvsCov-style)

### Takeaway
CBI's `returns` scheme is exactly "is the return value <0, <=0, >0, >=0, ==0, !=0" at every scalar-returning call site. Tracking such sign predicates per function and alarming the first time a previously never-true predicate (e.g. `ret < 0`) becomes true is a cheap, template-free novelty signal. IJON shows that such value signals can drive fuzzing, and InvsCov and Binvariants use violations as coverage-like feedback, not as bug reports.

### Cited Findings
- CBI (Liblit, Naik, Zheng, Aiken, Jordan, PLDI 2005) uses three instrumentation schemes:
  - **branches**: two predicates per conditional;
  - **returns**: "the sign of a function's return value is often used to signal success or failure. At each scalar-returning function call site, we track six predicates: whether the returned value is ever < 0, <= 0, > 0, >= 0, = 0, or != 0";
  - **scalar-pairs**: six relations between an assigned value and other same-typed in-scope variables and constants.

  — [CBI PLDI 2005 PDF](https://pages.cs.wisc.edu/~liblit/pldi-2005/pldi-2005.pdf)
- CBI samples sparsely (1/100 keeps overhead acceptable in most applications) and ranks predicates by `Increase(P) = Failure(P) - Context(P)`, which needs labeled failing and passing runs. Pruning by Increase > 0 cuts predicates "from hundreds of thousands to thousands". — [same PDF](https://pages.cs.wisc.edu/~liblit/pldi-2005/pldi-2005.pdf)
- IJON (Aschermann, Schumilo, Abbasi, Holz, 2020) adds human annotations that expose state values to the fuzzer. A later paper describes the macros: `IJON_SET` (numeric state), `IJON_MAX`/`IJON_MIN` (reward monotone progress), and `IJON_STATE`. A main limitation is the manual annotation; follow-ups (SandPuppy, AIJon arXiv 2609.18457) try to automate it. The macro descriptions are second-hand; the IJON PDF was not read. — [CASA page](https://www.casa.rub.de/forschung/publikationen/detail/ijon-exploring-deep-state-spaces-via-fuzzing); [AIJon arXiv](https://arxiv.org/pdf/2609.18457)
- InvsCov (Fioraldi, D'Elia, Balzarotti, USENIX Sec 2021) mines Daikon invariants once over a corpus: the queue of a 24h AFL++ run, also used as the seeds. It compiles them into checks and XORs each basic block's set of violated invariants into the edge ID, so each new combination of violations looks like new coverage. Bug oracles were ASan and UBSan; invariant violations are feedback only. — [InvsCov PDF](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- InvsCov's rationale: invariants capturing "only local properties of the corpus are interesting because their violation would tip fuzzers about what value combinations ... are unusual, and ideally the home of bugs". Pruning: (1) drop invariants implied by static value-range analysis (e.g. "unsigned integer variables are always greater than or equal to zero"), (2) drop invariants across non-comparable variables, (3) drop overlapping conditions. — [same PDF §3.2-3.3](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- InvsCov results (median, 5 trials of 48h, 8 targets, totals in Table 4): the DEFAULT config found 147 bugs with InvsCov vs 94 with CodeCov (156%); MOPT 151 vs 113; RARE 152 vs 107. 43 of the 65 InvsCov-only bugs were at locations CodeCov reached but did not trigger. — [same PDF Tables 4-5](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- Binvariants (Yang & Nagy, FSE 2026) learns register-level value-range and relationship invariants on binaries (x86-64 GPRs) via AFL++ and QEMU and treats violations like a new-coverage signal. On 25 binaries, "18 bugs are traceable back to distinct likely invariant violations". Bugs were deduplicated with ASan or QEMU-ASan. Figures are from the slides only. — [Binvariants FSE'26 slides](https://futures.cs.utah.edu/papers/26FSE-c_slides.pdf)

### Inferences
- A cheap addition that would have caught the abs_diff overflow: for every function exit value (and Kvasir-visible pointees), keep a persistent cumulative profile across all rounds: min, max, the six CBI sign predicates, and optionally a DIDUCE V/M mask. Emit an alarm the first time a sign predicate goes from never-true to true after K ≥ some threshold observations (e.g. `ret < 0` first seen after 10,000 non-negative returns). This is O(1) per call and never "forgets", because it is monotone.
- To keep alarms tractable, report CBI-style novelty only for exit values (Eclat logic). Rank by DIDUCE confidence drop (observations / 2^free-bits), as DIDUCE did.
- For the source mode, add the ground-truth oracle that InvsCov used: compile with `-fsanitize=signed-integer-overflow` (UBSan). This directly catches the abs_diff overflow regardless of invariants. For the Unicorn blackbox mode, an analogous check is the x86 OF flag after add/sub/imul, though that raises many FPs for intentional wraparound. This is an inference and was not found in a source.

### Gaps
- No source quantified the FP rate of "first sign change" alarms in fuzzing; this is a design inference.
- The "value spectra" (Xie & Notkin) and "state novelty search" literature was not covered.

## Learning before fuzzing vs online; baselines; type-derived and LLM-proposed invariants

### Takeaway
InvsCov and Binvariants learn once from a mature corpus, then check. Halo learns online but uses invariants to *steer* toward a target, not to detect bugs. DIDUCE is the online, monotone-baseline detector. LLM-generated invariants and oracles (LISA, PROMFUZZ) are emerging for non-crashing bugs, but they report candidates that a human confirms.

### Cited Findings
- InvsCov learns once, from the queue of a coverage-guided fuzzer taken "as soon as that fuzzer shows signs of slowing down". The authors argue that learning from a corpus of valid files alone would overfit. — [InvsCov PDF §3.4](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- Halo (Huang, Zhou, Payer, Zhang, "Everything is Good for Something: Counterexample-Guided Directed Fuzzing", IEEE S&P 2024) uses Daikon/DIG-style likely-invariant inference over reachable vs unreachable inputs to approximate the path condition to a target. It reduces dimensionality via taint inference over input bytes and generates new inputs inside the approximated region. It reports 6.2x more test cases reaching targets, a 15.3x speedup to the same bug, and 10 incomplete fixes of earlier CVEs/bugs. Under AFLGo, about 88% of time went to inputs that never reach the target. — [Halo S&P'24 slides](https://nebelwelt.net/files/24Oakland2-presentation.pdf)
- DIDUCE supports saving and reloading the learned invariant set, so a trusted run's baseline can be used in a later checking run. — [DIDUCE PDF](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- LISA (Yang, He, Xu, Wei, Chen; arXiv 2607.18711, 2026) is LLM-based invariant testing for library functional bugs. It iteratively generates API sequences plus LLM-written invariants (not exact I/O oracles), guided by API n-gram feedback, and reports "high-confidence bug candidates" for developer confirmation. The abstract gives no precision numbers. — [arXiv abs](https://arxiv.org/abs/2607.18711)
- PROMFUZZ (arXiv 2503.23718) has an LLM insert invariant checkers into smart contracts, then fuzzes toward them, motivated by functional bugs that do not crash. Search summary only. — [arXiv](https://arxiv.org/pdf/2503.23718)
- "LLMs and Fuzzing in Tandem" (arXiv 2507.05272) uses an LLM to propose weakest preconditions, refined by fuzzing. Search summary only. — [arXiv](https://arxiv.org/pdf/2507.05272)
- An evaluation of LLM-generated oracles from requirements on real bugs found "non-trivial generalization but with substantial bug- and model-level variance". Search summary only. — [arXiv 2607.10277](https://arxiv.org/html/2607.10277v1)

### Inferences
- Learning from 1 seed (the user's case) is the worst case for both learn-once (overfit `x == 5`) and Daikon re-learning (the invariant vanishes before a useful one appears). A monotone online profile (DIDUCE/CBI) sidesteps this: `ret >= 0` never needs to be proposed, because the sign bit has simply never flipped.
- Type and semantics templates: for a function named or typed like |a-b| with a signed return, an LLM or a rule could propose `return >= 0` up front and pin it into a baseline that is never re-learned. LISA and PROMFUZZ indicate that LLM invariants are usable as candidates but need human or secondary confirmation. Pinned invariants should be kept separate from Daikon's re-learned set, and a violation should be reported once per invariant, de-duplicated like Eclat.

### Gaps
- No primary source was found for KernelGPT or Fuzz4All acting as *invariant/oracle* generators. Both are input and spec generators; they were not verified here.
- No published work was found that explicitly implements "never forget a refuted invariant" across Daikon re-learning rounds, other than DIDUCE's saved monotone state.

## False-positive rates and how they are handled

### Takeaway
Reported FP handling falls into four strategies:
- rank by confidence (DIDUCE);
- require a separate precise failure detector (ClearView: zero FPs in the Red Team test);
- classify by entry vs exit violation and dedupe by pattern (Eclat: 30% precision vs 2.3% baseline);
- use violations only as feedback, with sanitizers as the oracle (InvsCov, Binvariants).

Pure invariant-violation reporting without these steps has poor or negative results (Carrot).

### Cited Findings
- DIDUCE: early-run messages are numerous. After training, the remaining FPs (a monotone counter) had low confidence. No numeric rate is given. — [DIDUCE PDF](https://cs.fit.edu/~pkc/id/related/hangal-icse02.pdf)
- ClearView: zero FPs, because detection is by monitors and invariants are only correlated after a failure. — [ClearView PDF](https://rcs.uwaterloo.ca/~ali/cs842-s23/papers/autopatch.pdf)
- Eclat: average precision of selected inputs is 30%, so about 70% of reported candidates were not fault-revealing. — [Eclat PDF Fig. 11](https://homes.cs.washington.edu/~mernst/pubs/classify-tests-ecoop2005.pdf)
- Carrot: no bugs localized. — [arXiv cs/0310040](https://arxiv.org/pdf/cs/0310040)
- InvsCov: static range analysis prunes impossible-to-violate invariants (e.g. unsigned >= 0); comparability sets prune spurious relations. — [InvsCov PDF](https://www.usenix.org/system/files/sec21-fioraldi.pdf)
- CBI: statistical ranking with confidence intervals on Increase(P), using pass/fail labels. — [CBI PDF](https://pages.cs.wisc.edu/~liblit/pldi-2005/pldi-2005.pdf)

### Inferences
- In a fuzz loop, the fuzzer's own corpus has no pass/fail labels, so CBI-style ranking is unavailable unless a sanitizer or crash supplies labels. DIDUCE-style confidence plus Eclat's exit-only rule is the most practical FP filter for unlabeled anomalies. UBSan should be the precise oracle where source exists.

### Gaps
- No study was found that gives FP rates specifically for sign-change or range-novelty alarms during greybox fuzzing.
