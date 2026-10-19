/*
 * buffer.c - pointer/array fuzz target, so the loop is exercised on the
 * sequence variables Kvasir derives from arrays (`arr[..]`) and not only on
 * scalars.
 *
 *   sum_bytes     the seeds are ASCII, so Daikon reports `buf[..] elements
 *                 <= 127`-style facts and a bound on `return`; arbitrary
 *                 bytes refute both.
 *   count_upper   `return <= n` is true and survives; `return == 0` from
 *                 lowercase seeds does not.
 *   parse_digits  `return >= 0` is false once the digits overflow an int,
 *                 which needs ten or more digit bytes in a row.
 *
 * The buffer is copied into a fixed, zeroed array so Kvasir sees a bounded,
 * fully initialized pointee rather than the harness's raw input pointer.
 * Without the memset the tail is uninitialized, Kvasir writes it as
 * `nonsensical`, and Daikon reports nothing about the array at all.
 */
#include "../runtime/fuzz.h"

#define CAP 16

int sum_bytes(const unsigned char *buf, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s += buf[i];
    return s;
}

int count_upper(const unsigned char *buf, int n) {
    int k = 0;
    for (int i = 0; i < n; i++)
        if (buf[i] >= 'A' && buf[i] <= 'Z')
            k++;
    return k;
}

int parse_digits(const unsigned char *buf, int n) {
    int v = 0;
    for (int i = 0; i < n && buf[i] >= '0' && buf[i] <= '9'; i++)
        v = v * 10 + (buf[i] - '0');
    return v;
}

void fuzz_target(const uint8_t *data, size_t size) {
    unsigned char buf[CAP];
    memset(buf, 0, sizeof buf);
    fuzz_cursor c = fuzz_cursor_make(data, size);
    int n = (int)fuzz_take_bytes(&c, buf, CAP);

    sum_bytes(buf, n);
    count_upper(buf, n);
    parse_digits(buf, n);
}
