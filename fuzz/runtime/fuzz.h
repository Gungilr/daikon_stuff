/*
 * fuzz.h - the interface between a fuzz target and the batch harness.
 *
 * A target defines exactly one entry point:
 *
 *     void fuzz_target(const uint8_t *data, size_t size);
 *
 * and decodes its arguments from the raw bytes with the fuzz_take_* helpers
 * below. The harness calls it once per input record, many records per
 * process, so a target MUST NOT keep state between calls (reset any globals
 * at the top of fuzz_target). That is what lets one Valgrind start-up serve a
 * whole batch instead of one input.
 *
 * Everything the target calls is traced by Kvasir and becomes a Daikon
 * program point. fuzz_target itself and the harness functions are dropped by
 * the Python side before Daikon sees the trace, so keep the interesting logic
 * in ordinary functions with ordinary scalar parameters - those are what the
 * invariants are about.
 */
#ifndef FUZZ_H
#define FUZZ_H

#include <stddef.h>
#include <stdint.h>

/* Forced inline even at -O0, so the helpers never become program points of
 * their own. That matters most for stripped binaries, where they could not be
 * filtered out by name. */
#define FUZZ_INLINE static inline __attribute__((always_inline))

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} fuzz_cursor;

FUZZ_INLINE fuzz_cursor fuzz_cursor_make(const uint8_t *data, size_t size) {
    fuzz_cursor c = {data, size, 0};
    return c;
}

/* Little-endian reads. Past the end of the input every read yields zero, so
 * a short input is always valid - the fuzzer never wastes executions on
 * inputs the target rejects for length. */
FUZZ_INLINE uint32_t fuzz_take_u32(fuzz_cursor *c) {
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (c->pos < c->size)
            v |= (uint32_t)c->data[c->pos++] << (8 * i);
    }
    return v;
}

FUZZ_INLINE int32_t fuzz_take_i32(fuzz_cursor *c) {
    return (int32_t)fuzz_take_u32(c);
}

FUZZ_INLINE uint8_t fuzz_take_u8(fuzz_cursor *c) {
    return c->pos < c->size ? c->data[c->pos++] : 0;
}

/* Copies up to `cap` bytes; returns how many were copied. A plain loop, not
 * memcpy: under the emulation tracer, calls into libc are skipped. */
FUZZ_INLINE size_t fuzz_take_bytes(fuzz_cursor *c, uint8_t *out, size_t cap) {
    size_t n = c->size - c->pos;
    if (n > cap)
        n = cap;
    for (size_t i = 0; i < n; i++)
        out[i] = c->data[c->pos + i];
    c->pos += n;
    return n;
}

/* Ground truth for benchmarking (scripts/bench). FUZZ_BUG marks a planted
 * bug: in the scoring build (-DFUZZ_ORACLE) it prints `@@BUG <id>` when the
 * condition holds, i.e. when the input triggers that bug. In every build a
 * fuzzer runs, it compiles to nothing, so no tool can see it. */
/* FUZZ_BUG_FATAL marks a memory bug. The oracle build has no memory
 * protection, so it abandons the input as soon as the bug is recorded rather
 * than let the overrun corrupt its own stack (packet.c's 255-byte copy into
 * a 16-byte buffer otherwise overwrites the loop counter and never ends). */
#ifdef FUZZ_ORACLE
#include <stdio.h>
void fuzz_oracle_abandon(void);
#define FUZZ_BUG(id, cond) \
    do { if (cond) fprintf(stderr, "@@BUG %s %s\n", id, __func__); } while (0)
#define FUZZ_BUG_FATAL(id, cond) \
    do { if (cond) { fprintf(stderr, "@@BUG %s %s\n", id, __func__); \
                     fuzz_oracle_abandon(); } } while (0)
int fuzz_mark(const char *id, const char *fn);
#define FUZZ_MARK(id, cond) ((cond) ? fuzz_mark(id, __func__) : 0)
#else
#define FUZZ_BUG(id, cond) ((void)0)
#define FUZZ_BUG_FATAL(id, cond) ((void)0)
#define FUZZ_MARK(id, cond) 0
#endif

/* A seeded fault (logic bug): the program computes `mut` where the correct
 * program computes `orig`. The oracle build marks the fault whenever the two
 * differ, i.e. whenever the input INFECTS the program state. A build with
 * -DFUZZ_REVERT=k computes `orig` for fault number k, so the scorer can check
 * whether that infection changed the output. Both expressions must be free of
 * side effects: the oracle evaluates both. */
#ifndef FUZZ_REVERT
#define FUZZ_REVERT 0
#endif
#define FAULT(id, k, orig, mut) \
    ((k) == FUZZ_REVERT ? (orig) : (FUZZ_MARK(id, (orig) != (mut)), (mut)))

void fuzz_target(const uint8_t *data, size_t size);

#endif
