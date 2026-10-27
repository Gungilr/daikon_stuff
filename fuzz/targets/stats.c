/*
 * stats.c - small statistics over a list of signed bytes. First byte is the
 * count n (0..15), then n values.
 *
 * Planted bugs:
 *   mean_div_zero  (UB)    mean() divides by n without checking it, so n == 0
 *                          is a division by zero.
 *   max3_wrong     (logic) max3() returns b when a < b, without comparing b
 *                          to c, so it can return less than the largest value.
 */
#include "../runtime/fuzz.h"

int mean(const signed char *v, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += v[i];
    FUZZ_BUG("mean_div_zero", n == 0);
    return s / n;                              /* bug: n may be 0 */
}

int max3(int a, int b, int c) {
    int r;
    if (a >= b)
        r = a >= c ? a : c;
    else
        r = b;                                 /* bug: forgot to compare c */
    FUZZ_BUG("max3_wrong", r < a || r < b || r < c);
    return r;
}

void fuzz_target(const uint8_t *data, size_t size) {
    signed char v[16];
    for (int i = 0; i < 16; i++)
        v[i] = 0;
    fuzz_cursor c = fuzz_cursor_make(data, size);
    int n = fuzz_take_u8(&c) % 16;
    for (int i = 0; i < n; i++)
        v[i] = (signed char)fuzz_take_u8(&c);
    mean(v, n);
    if (n >= 3)
        max3(v[0], v[1], v[2]);
}
