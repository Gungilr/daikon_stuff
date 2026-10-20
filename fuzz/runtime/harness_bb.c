/*
 * harness_bb.c - driver for fuzzing a binary under the emulation tracer
 * (scripts/tracer, --fuzz-batch), where no source or symbols are available
 * at trace time.
 *
 * The emulator cannot easily feed a program through files or stdin: that
 * would mean emulating libc. Instead this harness owns one initialized
 * global, so it lands in .data, and .data survives `strip --strip-all`:
 *
 *     magic[16]  "DAIKON-FUZZ-BLOB", found by scanning the loaded image
 *     len        u32, written by the tracer per input
 *     data[]     the input bytes, written by the tracer per input
 *
 * main hands it to fuzz_target exactly as harness.c does for one record.
 * The tracer starts a fresh emulator per input, so nothing carries over.
 * Keep FUZZ_MAX in step with scripts/tracer/fuzzinput.py.
 */
#include "fuzz.h"

#define FUZZ_MAX 4096

struct fuzz_blob {
    char magic[16];
    uint32_t len;
    uint8_t data[FUZZ_MAX];
};

/* volatile: at -O1+ the compiler could otherwise fold len to its initial 0. */
volatile struct fuzz_blob fuzz_blob = {"DAIKON-FUZZ-BLOB", 0, {0}};

int main(void) {
    uint32_t n = fuzz_blob.len;
    if (n > FUZZ_MAX)
        n = FUZZ_MAX;
    fuzz_target((const uint8_t *)fuzz_blob.data, n);
    return 0;
}
