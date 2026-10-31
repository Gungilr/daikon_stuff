/*
 * prog_shim.h - run a whole `main()` program as a fuzz target.
 *
 * Include it AFTER the program's own system headers and BEFORE its code:
 *
 *   - `main` becomes `prog_main`, and fuzz_target() calls it with an argv
 *     built from the input and stdin reading the rest (fmemopen).
 *   - `exit(n)` jumps back to fuzz_target() instead of ending the process,
 *     so one process still runs a whole batch.
 *   - stdout goes to /dev/null. In the scoring build (-DFUZZ_ORACLE) it is
 *     captured instead and its hash printed as `@@OUT <hash>`, so the scorer
 *     can tell whether a seeded fault changed the program's output.
 *
 * Seeded faults use FAULT(id, k, original, mutant): the program computes
 * `mutant`. A build with -DFUZZ_REVERT=k computes `original` for fault k
 * only, which gives the scorer one reference build per fault.
 */
#ifndef PROG_SHIM_H
#define PROG_SHIM_H

/* The Siemens programs are 1993 K&R C: implicit int and undeclared library
 * calls. clang 16+ and gcc 14+ make those errors by default, so relax them
 * for files that use this shim rather than rewrite the programs. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wimplicit-int"
#pragma clang diagnostic ignored "-Wimplicit-function-declaration"
#pragma clang diagnostic ignored "-Wint-conversion"
#pragma clang diagnostic ignored "-Wdeprecated-non-prototype"
#pragma clang diagnostic ignored "-Wreturn-type"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wimplicit-int"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"
#endif

#include <ctype.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"

/* The jump buffer lives inside a function, not at file scope: Kvasir dumps
 * every file-scope variable at every program point, and a jmp_buf is 23
 * variables of saved registers and signal masks. On tcas those alone made
 * Daikon run for more than 5 minutes on 116 samples, against 3 s without. */
static jmp_buf *prog_exit_jmp(void) {
    static jmp_buf buf;
    return &buf;
}

static void prog_exit(int code) {
    (void)code;
    longjmp(*prog_exit_jmp(), 1);
}

#define exit prog_exit
#define main prog_main

/* Runs prog_main(argc, argv) with `in[0..n)` as stdin. */
static void run_prog(int (*m)(), int argc, char **argv, const uint8_t *in, size_t n) {
    static FILE *devnull_in, *devnull_out;
    if (!devnull_in) {
        devnull_in = fopen("/dev/null", "r");
        devnull_out = fopen("/dev/null", "w");
    }
    FILE *saved_in = stdin, *saved_out = stdout;
    FILE *f = n ? fmemopen((void *)in, n, "r") : NULL;
    stdin = f ? f : devnull_in;
    clearerr(stdin);
#ifdef FUZZ_ORACLE
    char *out = NULL;
    size_t out_len = 0;
    stdout = open_memstream(&out, &out_len);
#else
    stdout = devnull_out;
#endif
    if (!setjmp(*prog_exit_jmp()))
        m(argc, argv);
    fflush(stdout);
#ifdef FUZZ_ORACLE
    fclose(stdout);
    uint32_t h = 2166136261u;                       /* FNV-1a */
    for (size_t i = 0; i < out_len; i++)
        h = (h ^ (unsigned char)out[i]) * 16777619u;
    fprintf(stderr, "@@OUT %08x\n", h);
    free(out);
#endif
    if (f)
        fclose(f);
    stdin = saved_in;
    stdout = saved_out;
}

#endif
