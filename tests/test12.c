#include <stdio.h>

/*
 * test12.c - value fidelity: signedness, width, void, and pointer returns.
 *
 * The corpus could not previously see the tracer's biggest value bug: every
 * fixture used non-negative loop counters, so a scan of all baseline traces
 * found ZERO negative values. An `int` occupies the low 32 bits of its
 * register and writes to eax zero-extend, so -1 sat in rax as
 * 0x00000000FFFFFFFF and was reported as 4294967295 - and Daikon then inferred
 * `> 0` where the truth was `< 0`. Not a phrasing difference: a wrong answer.
 *
 * `negate` and `takes_negative` pin both directions (negative out, negative
 * in). Kvasir reports -1..-5; anything else here is the bug returning.
 *
 * `big_unsigned` is the deliberate counter-case. Signedness is NOT observable
 * dynamically - nothing distinguishes `int` from `unsigned int` holding a
 * high-bit value - so the tracer sign-extends, which is right for `int` (the
 * common case) and WRONG here. Kvasir reads DWARF and gets it right. This
 * function exists to keep that trade visible and measurable rather than
 * quietly wrong.
 *
 * `discard_me` is void: its caller never reads rax. `identity_ptr` returns a
 * pointer, which must stay 64-bit - sign-extending a stack address would
 * corrupt it.
 */

int negate(int x) { return -x; }

int takes_negative(int x) { return x - 1; }

unsigned int big_unsigned(unsigned int x) { return x | 0x80000000u; }

void discard_me(int x) { (void)x; }

int *identity_ptr(int *p) { return p; }

int main(void) {
    long acc = 0;
    int local = 7;

    for (int i = 1; i <= 5; i++) {
        acc += negate(i);              /* returns -1 .. -5          */
        acc += takes_negative(-i);     /* receives -1 .. -5         */
        acc += (int)(big_unsigned(i) >> 28);
        discard_me(i);                 /* result never consumed     */
        acc += *identity_ptr(&local);  /* pointer in, pointer out   */
    }

    printf("acc = %ld\n", acc);
    return 0;
}
