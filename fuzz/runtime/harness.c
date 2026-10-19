/*
 * harness.c - batch driver shared by every fuzz target.
 *
 *     harness BATCH_FILE [COV_OUT]
 *
 * BATCH_FILE is a sequence of records, each a little-endian u32 length
 * followed by that many bytes. Each record is handed to fuzz_target() in
 * turn, preceded by a call to fuzz_input_begin(id).
 *
 * fuzz_input_begin exists to be traced. Kvasir records its ENTER with the
 * `fuzz_id` parameter, and that sample is how the Python side attributes the
 * samples that follow it to the input that produced them. It must therefore
 * stay a real, non-inlined, externally visible function.
 *
 * In the coverage build (compiled with -DFUZZ_COV and linked with cov.c),
 * COV_OUT receives one text line per record, written and flushed BEFORE the
 * next record starts:
 *
 *     S <id>                      record <id> is about to run
 *     F <id> <feature>...         coverage features it reached
 *     C <id> <constant>...        constants it was compared against
 *
 * The `S` line is flushed first, so when an input crashes the process the
 * last `S` without a matching `F` names the input that did it.
 */
#include <stdio.h>
#include <stdlib.h>

#include "fuzz.h"

#ifdef FUZZ_COV
void fuzz_cov_reset(void);
void fuzz_cov_dump(FILE *out, unsigned id);
#endif

__attribute__((noinline)) void fuzz_input_begin(int fuzz_id) {
    /* Keeps the call from being discarded; the parameter is what matters. */
    __asm__ volatile("" : : "r"(fuzz_id) : "memory");
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    size_t cap = 1 << 16, n = 0;
    uint8_t *buf = malloc(cap);
    size_t got;
    while (buf && (got = fread(buf + n, 1, cap - n, f)) > 0) {
        n += got;
        if (n == cap)
            buf = realloc(buf, cap *= 2);
    }
    fclose(f);
    *len = n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s BATCH_FILE [COV_OUT]\n", argv[0]);
        return 2;
    }
    size_t len = 0;
    uint8_t *batch = read_file(argv[1], &len);
    if (!batch) {
        perror(argv[1]);
        return 2;
    }
#ifdef FUZZ_COV
    FILE *cov = argc > 2 ? fopen(argv[2], "w") : NULL;
#endif

    size_t pos = 0;
    unsigned id = 0;
    while (pos + 4 <= len) {
        uint32_t n = (uint32_t)batch[pos] | (uint32_t)batch[pos + 1] << 8 |
                     (uint32_t)batch[pos + 2] << 16 |
                     (uint32_t)batch[pos + 3] << 24;
        pos += 4;
        if (n > len - pos)
            n = (uint32_t)(len - pos);
#ifdef FUZZ_COV
        if (cov) {
            fprintf(cov, "S %u\n", id);
            fflush(cov);
        }
        fuzz_cov_reset();
#endif
        /* Each record gets an allocation of exactly its own size. Kvasir
         * sizes a pointee by its heap block, so handing out a pointer into
         * the batch buffer would make every traced pointer to the input
         * dump the REST OF THE BATCH - quadratic trace size, measured at
         * 110 MB for 1000 inputs. */
        uint8_t *rec = malloc(n ? n : 1);
        memcpy(rec, batch + pos, n);
        fuzz_input_begin((int)id);
        fuzz_target(rec, n);
        free(rec);
#ifdef FUZZ_COV
        if (cov)
            fuzz_cov_dump(cov, id);
#endif
        pos += n;
        id++;
    }
#ifdef FUZZ_COV
    if (cov)
        fclose(cov);
#endif
    free(batch);
    return 0;
}
