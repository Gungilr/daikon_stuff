#include <stdio.h>

/*
 * test14.c - pointee edge cases found in the 2026-09-17 review.
 *
 * Both bugs below were invisible to the rest of the corpus because every other
 * fixture passes a valid pointer and reads through it.
 *
 * `maybe` is called with a valid pointer AND with NULL. A null used to be
 * classified as a scalar, and one scalar sighting demoted the slot
 * permanently - so the function emitted no pointee for ANY call, including the
 * valid one. Null is now neutral: it neither promotes nor demotes, and the
 * null call alone reports `nonsensical`.
 *
 * `fill` is an out-parameter: it writes through the pointer and never reads.
 * Only memory READS were hooked, so its fields left no footprint and were
 * recovered not at all. Writes now count as field evidence too.
 */

typedef struct { int a, b; } pair_t;

int maybe(pair_t *p) {
    return p ? p->a : -1;
}

void fill(pair_t *p, int v) {
    p->a = v;
    p->b = v * 2;
}

int main(void) {
    pair_t q = {3, 4};
    long acc = maybe(&q) + maybe(0);

    pair_t out;
    for (int i = 1; i <= 3; i++) {
        fill(&out, i);
        acc += out.a + out.b;
    }

    printf("acc = %ld\n", acc);
    return 0;
}
