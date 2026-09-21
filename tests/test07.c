#include <stdio.h>

/*
 * test07.c - exercises register and stack argument passing.
 *
 * Under the SysV x86-64 ABI, the first six integer/pointer arguments go in
 * registers (rdi, rsi, rdx, rcx, r8, r9) and the seventh onward go on the
 * stack (arg7 at [rsp], arg8 at [rsp+8] at the moment of the call).
 *
 * All meaningful computation lives in the called functions below, never in
 * main(), because the tracer deliberately does not track main's arguments
 * (nothing calls main, so it has no observed argument list).
 */

/*
 * reg6: six arguments, all register-passed. This is the control case - it
 * uses every argument register up to r9, with no stack arguments. The return
 * value relates to arg6 (f, in r9), so the expected invariant is
 *     return == orig(f) + 10
 * The current register-based detection should already recover this.
 */
int reg6(int a, int b, int c, int d, int e, int f) {
    return f + 10;
}

/*
 * stack8: eight arguments. a-f are register-passed; g and h are stack-passed
 * (arg7 and arg8). g is held constant across calls and h varies with a clean
 * relation to the return value, so the expected invariants are
 *     g == 100
 *     return == orig(h) + 1
 * Both of these are properties of STACK arguments. Register-only tracing
 * cannot see g or h, so until stack-argument capture is added these two facts
 * will be ABSENT from the tracer output while Kvasir (which reads DWARF)
 * reports them. That gap is the point of this test.
 */
int stack8(int a, int b, int c, int d, int e, int f, int g, int h) {
    return h + 1;
}

int main(void) {
    long acc = 0;

    for (int i = 0; i < 12; i++) {
        /*
         * Filler arguments are fixed, distinct constants; only the carrier
         * arguments (f in reg6, h in stack8) vary with i. This keeps the
         * observed invariants focused: constants on the fillers, a single
         * linear relation on each carrier, and nothing incidental.
         */
        acc += reg6(1, 2, 3, 4, 5, i);             /* f = i  -> return = i + 10 */
        acc += stack8(1, 2, 3, 4, 5, 6, 100, i);   /* h = i  -> return = i + 1; g = 100 */
    }

    printf("acc = %ld\n", acc);
    return 0;
}