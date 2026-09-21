#include <stdio.h>

/*
 * test11.c - recursion, for ENTER/EXIT pairing.
 *
 * This is the only corpus member where the same program point has several
 * frames live at once, so it is the one that can distinguish correct pairing
 * from incorrect pairing.
 *
 * fact(5) produces the observation sequence
 *     ENTER n = 5, 4, 3, 2, 1
 *     EXIT  return = 1, 2, 6, 24, 120
 * Correct (LIFO) pairing gives (orig(n), return) = (1,1) (2,2) (3,6) (4,24)
 * (5,120), for which `return % orig(n) == 0` holds. Arrival-order pairing would
 * give (5,1) first, where 1 % 5 = 1, and the invariant would vanish. That
 * invariant is therefore a direct read-out of which pairing Daikon used.
 *
 * Measured at tier 0 (no nonce emitted): Daikon pairs correctly anyway, via the
 * stack discipline it falls back on for traces without nonces. Tier 1 emits an
 * explicit nonce and must not regress that.
 *
 * Note fact() has two `return` statements but compiles at -O0 to a single `ret`
 * - gcc routes both through one epilogue. That is why one exit site per
 * function, named EXIT0, is the right model.
 */
int fact(int n) {
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int main(void) {
    printf("fact(5) = %d\n", fact(5));
    return 0;
}
