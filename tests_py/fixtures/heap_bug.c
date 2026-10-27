/* Test fixture for the bug checker: a heap overflow when the first byte is
 * 7, a signed overflow when it is 9, and nothing otherwise. */
#include <stdlib.h>
#include "../../fuzz/runtime/fuzz.h"

int write_at(int idx) {
    char *p = malloc(4);
    p[idx] = 1;                 /* out of bounds when idx >= 4 */
    int v = p[0];
    free(p);
    return v;
}

int grow(int x) {
    return x + 2147483647;      /* overflows when x > 0 */
}

void fuzz_target(const uint8_t *data, size_t size) {
    int b = size ? data[0] : 0;
    if (b == 7)
        write_at(b);
    if (b == 9)
        grow(b);
}
