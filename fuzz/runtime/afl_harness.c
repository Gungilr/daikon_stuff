/*
 * afl_harness.c - AFL++ persistent-mode driver for the same fuzz_target()
 * every other front-end uses. Built only for the benchmark baseline
 * (scripts/bench), with afl-clang-fast, ASan and UBSan, and no -fwrapv.
 *
 * Each input is copied into its own exact-size allocation, as in harness.c,
 * so ASan sees reads past its end.
 */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>   /* read(), used by __AFL_FUZZ_INIT */

#include "fuzz.h"

__AFL_FUZZ_INIT();

int main(void) {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        uint8_t *rec = malloc(len ? len : 1);
        memcpy(rec, buf, len);
        fuzz_target(rec, len);
        free(rec);
    }
    return 0;
}
