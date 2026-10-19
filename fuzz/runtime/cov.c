/*
 * cov.c - a minimal SanitizerCoverage runtime, so the loop needs neither
 * libFuzzer nor AFL.
 *
 * The target is compiled with -fsanitize-coverage=trace-pc,trace-cmp, which
 * both gcc and clang support and which only emits calls to the callbacks
 * defined here. THIS file must be compiled WITHOUT that flag, or every
 * callback would instrument itself.
 *
 * Features reported per input, all hashed into one 64K map:
 *
 *   edges       AFL-style (prev_pc ^ cur_pc), with AFL hit-count buckets so a
 *               loop running 4 times is distinguishable from one running 40.
 *   cmp values  libFuzzer-style "value profile": (cmp site, popcount(a ^ b)).
 *               Every extra matching bit of a comparison against a magic
 *               constant is a new feature, so the fuzzer can climb toward
 *               `x == 0x1337` one bit at a time instead of guessing it.
 *
 * Constant operands of comparisons are also reported, and the fuzzer adds
 * them to its dictionary.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define MAP_BITS 16
#define MAP_SIZE (1u << MAP_BITS)
#define MAX_CONSTS 64

static uint8_t hits[MAP_SIZE];
static uintptr_t prev_loc;
static uint64_t consts[MAX_CONSTS];
static unsigned n_consts;

static inline uint32_t mix(uintptr_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return (uint32_t)x;
}

void fuzz_cov_reset(void) {
    memset(hits, 0, sizeof hits);
    prev_loc = 0;
    n_consts = 0;
}

static inline unsigned bucket(uint8_t n) {
    if (n <= 3)
        return n;          /* 1, 2, 3 */
    if (n <= 7)
        return 4;
    if (n <= 15)
        return 5;
    if (n <= 31)
        return 6;
    if (n <= 127)
        return 7;
    return 8;
}

void fuzz_cov_dump(FILE *out, unsigned id) {
    fprintf(out, "F %u", id);
    for (unsigned i = 0; i < MAP_SIZE; i++) {
        if (hits[i])
            fprintf(out, " %u", i * 16 + bucket(hits[i]));
    }
    fputc('\n', out);
    if (n_consts) {
        fprintf(out, "C %u", id);
        for (unsigned i = 0; i < n_consts; i++)
            fprintf(out, " %llu", (unsigned long long)consts[i]);
        fputc('\n', out);
    }
    fflush(out);
}

/* Return addresses are taken relative to a function in this binary, so a
 * PIE build under ASLR yields the same features in every process. Without
 * this, each batch "discovers" hundreds of features that are only the load
 * address moving, and the loop never reaches a fixed point. */
#define REL(pc) ((uintptr_t)(pc) - (uintptr_t)&fuzz_cov_reset)

void __sanitizer_cov_trace_pc(void) {
    uintptr_t loc = mix(REL(__builtin_return_address(0)));
    uint32_t idx = (uint32_t)(loc ^ prev_loc) & (MAP_SIZE - 1);
    if (hits[idx] < 255)
        hits[idx]++;
    prev_loc = loc >> 1;
}

static inline void cmp_feature(uintptr_t site, uint64_t a, uint64_t b) {
    /* Value-profile features live in their own region of the hash so they
     * do not alias edges as often; collisions only ever cost a feature. */
    uint32_t idx = (mix(site) + (uint32_t)__builtin_popcountll(a ^ b)) &
                   (MAP_SIZE - 1);
    hits[idx] = 1;
}

static inline void record_const(uint64_t c) {
    if (c == 0 || c == 1 || n_consts >= MAX_CONSTS)
        return;
    for (unsigned i = 0; i < n_consts; i++)
        if (consts[i] == c)
            return;
    consts[n_consts++] = c;
}

#define SITE REL(__builtin_return_address(0))

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { cmp_feature(SITE, a, b); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { cmp_feature(SITE, a, b); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { cmp_feature(SITE, a, b); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { cmp_feature(SITE, a, b); }

void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) {
    cmp_feature(SITE, a, b);
    record_const(a);
}
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) {
    cmp_feature(SITE, a, b);
    record_const(a);
}
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) {
    cmp_feature(SITE, a, b);
    record_const(a);
}
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) {
    cmp_feature(SITE, a, b);
    record_const(a);
}

/* cases[0] = number of cases, cases[1] = operand width in bits. */
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    for (uint64_t i = 0; i < cases[0]; i++) {
        cmp_feature(SITE + i, val, cases[2 + i]);
        record_const(cases[2 + i]);
    }
}

/* gcc emits these for floating-point compares; nothing useful to learn. */
void __sanitizer_cov_trace_cmpf(float a, float b) { (void)a; (void)b; }
void __sanitizer_cov_trace_cmpd(double a, double b) { (void)a; (void)b; }
