/*
 * arith.c - scalar fuzz target. Each function has an invariant that a small
 * seed corpus "proves" and that is false, and each falls to a different part
 * of the loop:
 *
 *   classify   seeds are all small positives, so Daikon reports `x >= 1` and
 *              `return == 1`. Plain mutation refutes both within a round.
 *   abs_diff   `return >= 0` looks like a true property of the code and holds
 *              for every input except the overflowing ones (a - b wraps when
 *              the operands straddle INT_MIN/INT_MAX). Distance guidance on
 *              `return >= 0` pushes the operands apart until it wraps. A real
 *              bug, found by attacking a plausible invariant.
 *   lookup     `return >= 0` is false only for one 32-bit key. No amount of
 *              random mutation finds it; the comparison constant does, via
 *              the trace-cmp dictionary in fuzz/runtime/cov.c.
 *   clamp      `lo <= return` and `return <= hi` are true (fuzz_target only
 *              calls it with lo <= hi), so they must survive. It is the
 *              control: a loop that refutes everything is broken.
 *
 * Planted bugs (benchmark ground truth, see scripts/bench):
 *   abs_diff_a_minus_b  (UB)    a - b overflows when a > b and they are far apart
 *   abs_diff_b_minus_a  (UB)    b - a overflows the same way when a <= b
 *   lookup_magic        (logic) returns -1 for one key; documented as 0..255
 */
#include <limits.h>

#include "../runtime/fuzz.h"

int classify(int x) {
    if (x < 0)
        return -1;
    if (x == 0)
        return 0;
    if (x > 1000)
        return 2;
    return 1;
}

int abs_diff(int a, int b) {
    /* Deliberately written the naive way. -fwrapv in the build makes the
     * overflow wrap deterministically instead of being undefined. */
    FUZZ_BUG("abs_diff_a_minus_b", a > b && (long long)a - b > INT_MAX);
    FUZZ_BUG("abs_diff_b_minus_a", a <= b && (long long)b - a > INT_MAX);
    return a > b ? a - b : b - a;
}

int lookup(int key) {
    FUZZ_BUG("lookup_magic", key == 0x5eed1337);   /* logic: documented 0..255 */
    if (key == 0x5eed1337)
        return -1;
    return key & 0xff;
}

int clamp(int x, int lo, int hi) {
    if (x < lo)
        return lo;
    if (x > hi)
        return hi;
    return x;
}

void fuzz_target(const uint8_t *data, size_t size) {
    fuzz_cursor c = fuzz_cursor_make(data, size);
    int x = fuzz_take_i32(&c);
    int y = fuzz_take_i32(&c);
    int z = fuzz_take_i32(&c);

    classify(x);
    abs_diff(x, y);
    lookup(y);
    if (y <= z)
        clamp(x, y, z);
}
