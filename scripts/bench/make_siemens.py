#!/usr/bin/env python3
"""Generate fuzz targets from the Siemens suite, with seeded logic faults.

    python3 scripts/bench/make_siemens.py DAIKON_SRC/tests/kvasir-tests

The Siemens programs (Hutchins et al., ICSE 1994) are the classic benchmark
for dynamic invariant detection. Daikon ships the CORRECT versions in its
Kvasir test suite. The faulty versions live in SIR, which needs registration,
so faults are seeded here instead, by single-expression mutation. That is the
same kind of change as SIR's hand-seeded faults (relational operators,
boundaries, missing conditions, constants), and Andrews et al. (ICSE 2005)
found mutants a reasonable stand-in for real faults in testing experiments.

Every fault is written FAULT(id, k, original, mutant) (fuzz/runtime/fuzz.h).
The programs compute the mutant, and the scoring build marks every input that
makes the two differ. All faults in a program are live at once, as in Magma.

Output: fuzz/targets/siemens/<prog>/<prog>.c, any headers it needs, and
<prog>.seeds.
"""
import os
import shutil
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(REPO, "fuzz", "targets", "siemens")
SHIM = '#include "../../../runtime/prog_shim.h"\n'

# (program, extra files, [(original text, replacement)], adapter, kinds)
PROGRAMS = {
    "tcas": {
        "files": [],
        "edits": [
            ("    upward_preferred = Inhibit_Biased_Climb() > Down_Separation;\n"
             "    if (upward_preferred)\n    {\n\tresult = !(Own_Below_Threat())",
             "    upward_preferred = FAULT(\"tcas_climb_ge\", 1, Inhibit_Biased_Climb() > Down_Separation,"
             " Inhibit_Biased_Climb() >= Down_Separation);\n"
             "    if (upward_preferred)\n    {\n\tresult = !(Own_Below_Threat())"),
            ("(Own_Tracked_Alt_Rate <= OLEV) && (Cur_Vertical_Sep > MAXALTDIFF)",
             "(Own_Tracked_Alt_Rate <= OLEV) && FAULT(\"tcas_enabled_ge\", 2,"
             " Cur_Vertical_Sep > MAXALTDIFF, Cur_Vertical_Sep >= MAXALTDIFF)"),
            ("return (Climb_Inhibit ? Up_Separation + NOZCROSS : Up_Separation);",
             "return (Climb_Inhibit ? FAULT(\"tcas_nozcross_const\", 3, Up_Separation + NOZCROSS,"
             " Up_Separation + MINSEP) : Up_Separation);"),
            ("return (Other_Tracked_Alt < Own_Tracked_Alt);",
             "return FAULT(\"tcas_above_le\", 4, Other_Tracked_Alt < Own_Tracked_Alt,"
             " Other_Tracked_Alt <= Own_Tracked_Alt);"),
        ],
        "adapter": r'''
void fuzz_target(const uint8_t *data, size_t size) {
    /* 12 little-endian i32 arguments, exactly what main() would atoi(). */
    static char bufs[12][16];
    char *argv[14] = {"tcas"};
    fuzz_cursor c = fuzz_cursor_make(data, size);
    for (int i = 0; i < 12; i++) {
        snprintf(bufs[i], sizeof bufs[i], "%d", (int)fuzz_take_i32(&c));
        argv[i + 1] = bufs[i];
    }
    argv[13] = NULL;
    run_prog((int (*)())prog_main, 13, argv, NULL, 0);
}
''',
    },
    "tot_info": {
        "files": ["std.h", "chisq.h", "gamma.h"],
        "edits": [
            ("\tfor ( j = 0; j < 6; ++j )",
             "\tfor ( j = 0; FAULT(\"tot_lgamma_terms\", 1, j < 6, j < 5); ++j )"),
            ("\treturn x < a + 1.0 ? 1.0 - gser( a, x ) : gcf( a, x );",
             "\treturn FAULT(\"tot_qgamma_le\", 2, x < a + 1.0, x <= a + 1.0)"
             " ? 1.0 - gser( a, x ) : gcf( a, x );"),
            ("\t\tif ( info >= 0.0 )",
             "\t\tif ( FAULT(\"tot_info_gt\", 3, info >= 0.0, info > 0.0) )"),
            ("\t\tif ( pi > 0.0 )",
             "\t\tif ( FAULT(\"tot_pi_ge\", 4, pi > 0.0, pi >= 0.0) )"),
        ],
        "adapter": r'''
void fuzz_target(const uint8_t *data, size_t size) {
    char *argv[] = {"tot_info", NULL};
    run_prog((int (*)())prog_main, 1, argv, data, size);
}
''',
    },
    "replace": {
        "files": [],
        "edits": [
            ("main(argc, argv)", "int main(argc, argv)"),
            ("\t    else if (*j <= 1 || src[*i + 1] == ENDSTR)",
             "\t    else if (FAULT(\"rep_dash_lt\", 1, *j <= 1, *j < 1) || src[*i + 1] == ENDSTR)"),
            ("\telse if ((arg[i] == CLOSURE) && (i > start)) ",
             "\telse if ((arg[i] == CLOSURE) && FAULT(\"rep_closure_ge\", 2, i > start, i >= start)) "),
            ("\t    for (j = s1; j < s2; j++) ",
             "\t    for (j = s1; FAULT(\"rep_ditto_le\", 3, j < s2, j <= s2); j++) "),
            ("\t    if ((m >= 0) && (lastm != m)) {",
             "\t    if (FAULT(\"rep_subline_gt\", 4, m >= 0, m > 0) && (lastm != m)) {"),
        ],
        "adapter": r'''
void fuzz_target(const uint8_t *data, size_t size) {
    /* pattern NUL substitution NUL text: the two arguments, then stdin. */
    static char pat[256], sub[256];
    size_t i = 0, k = 0;
    while (i < size && data[i] && k < sizeof pat - 1) pat[k++] = data[i++];
    pat[k] = 0; if (i < size) i++;
    k = 0;
    while (i < size && data[i] && k < sizeof sub - 1) sub[k++] = data[i++];
    sub[k] = 0; if (i < size) i++;
    char *argv[] = {"replace", pat, sub, NULL};
    run_prog((int (*)())prog_main, 3, argv, data + i, size - i);
}
''',
    },
    "print_tokens": {
        "files": ["stream.h", "tokens.h"],
        "edits": [
            ("main(argc,argv)", "int main(argc,argv)"),
            ("      if(stream_ptr->stream_ind == 0)",
             "      if(FAULT(\"pt_unget_le\", 1, stream_ptr->stream_ind == 0,"
             " stream_ptr->stream_ind <= 1))"),
            ("      if(!isalpha(ch) && !isdigit(ch)) /* Check for digit and alpha */",
             "      if(FAULT(\"pt_delim_or\", 2, !isalpha(ch) && !isdigit(ch),"
             " !isalpha(ch) || !isdigit(ch))) /* Check for digit and alpha */"),
            ("\t  if(token_ind < 80) /* ADDED ERROR CHECK - hf */",
             "\t  if(FAULT(\"pt_token_len\", 3, token_ind < 80, token_ind < 79)) /* ADDED ERROR CHECK - hf */"),
        ],
        "adapter": r'''
void fuzz_target(const uint8_t *data, size_t size) {
    char *argv[] = {"print_tokens", NULL};
    run_prog((int (*)())prog_main, 1, argv, data, size);
}
''',
    },
    "print_tokens2": {
        "files": ["stream.h", "tokens.h"],
        "edits": [
            ("main(argc,argv)", "int main(argc,argv)"),
            ("       if(isdigit(*(str+i)))",
             "       if(FAULT(\"pt2_num_dot\", 1, isdigit(*(str+i)) != 0,"
             " isdigit(*(str+i)) || *(str+i)=='.'))"),
            ("    { if(ch=='\"' | ch=='\\n')",
             "    { if(FAULT(\"pt2_string_nl\", 2, ch=='\"' | ch=='\\n', ch=='\"'))"),
            (" if(ch ==' ' || ch=='\\n' || ch==59) return(TRUE); ",
             " if(FAULT(\"pt2_tokend_semi\", 3, ch ==' ' || ch=='\\n' || ch==59,"
             " ch ==' ' || ch=='\\n')) return(TRUE); "),
            ("  if ((*str)=='#' && isalpha(*(str+1)))",
             "  if (FAULT(\"pt2_charconst_alpha\", 4, (*str)=='#' && isalpha(*(str+1)),"
             " (*str)=='#'))"),
        ],
        "adapter": r'''
void fuzz_target(const uint8_t *data, size_t size) {
    char *argv[] = {"print_tokens2", NULL};
    run_prog((int (*)())prog_main, 1, argv, data, size);
}
''',
    },
}


def seeds_for(prog, src):
    """Seed lines in the .seeds format (hex for anything with newlines)."""
    out = []
    if prog == "tcas":
        for line in open(os.path.join(src, "tcas", "tests.sh")):
            nums = line.split("./tcas")[-1].split()
            if len(nums) == 12:
                out.append("i32: " + " ".join(nums))
            if len(out) == 12:
                break
        return out
    if prog == "replace":
        text = open(os.path.join(src, "replace", "ruin.8"), "rb").read()
        cases = [(b"X", b"NEW", text), (b"a", b"b", b"banana\n"),
                 (b"[a-c]*", b"X", b"abcabc xyz\n"), (b"%th", b"TH", b"the thing\nthat\n"),
                 (b"e$", b"E", b"one\ntwo three\n"), (b"?", b"@", b"hi\n")]
        return [(p + b"\0" + s + b"\0" + t).hex() for p, s, t in cases]
    name = {"tot_info": "tst45", "print_tokens": "tst180",
            "print_tokens2": "tst183"}[prog]
    data = open(os.path.join(src, prog, name), "rb").read()
    out = [data[:256].hex()]
    if prog == "tot_info":
        out += [b"2 2\n10 20\n30 40\n".hex(), b"3 2\n1 2 3 4 5 6\n".hex(),
                b"# comment\n1 3\n5 5 5\n".hex()]
    else:
        out += [b"and or if xor\n".hex(), b'(a "str" 12 #c)\n'.hex(),
                b"lambda x ; comment\n".hex(), b"[ ] , ` ' =>\n".hex()]
    return out


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print(__doc__)
        return 2
    src = argv[0]
    for prog, spec in PROGRAMS.items():
        d = os.path.join(OUT, prog)
        os.makedirs(d, exist_ok=True)
        for f in spec["files"]:
            shutil.copy(os.path.join(src, prog, f), os.path.join(d, f))
        text = open(os.path.join(src, prog, prog + ".c"), errors="replace").read()
        for old, new in spec["edits"]:
            if text.count(old) != 1:
                raise SystemExit("%s: edit site found %d times: %r" % (prog, text.count(old), old))
            text = text.replace(old, new)
        header = ("/* Generated by scripts/bench/make_siemens.py from the Siemens suite\n"
                  " * (Daikon tests/kvasir-tests/%s). Seeded faults are marked FAULT(...).\n"
                  " * Planted bugs (benchmark ground truth, see scripts/bench):\n" % prog)
        for old, new in spec["edits"]:
            if "FAULT(" in new:
                fid = new.split('FAULT("')[1].split('"')[0]
                header += " *   %-22s (logic)\n" % fid
        header += " */\n"
        with open(os.path.join(d, prog + ".c"), "w") as f:
            f.write(header + SHIM + text + spec["adapter"])
        with open(os.path.join(d, prog + ".seeds"), "w") as f:
            f.write("# generated by scripts/bench/make_siemens.py from the suite's own tests\n")
            f.write("\n".join(seeds_for(prog, src)) + "\n")
        print("wrote", os.path.join(d, prog + ".c"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
