#include <stdio.h>

/*
 * test10.c - argument-count extremes.
 *
 * `twelve` takes 12 arguments: six in registers (rdi, rsi, rdx, rcx, r8, r9)
 * and six on the stack at [rbp+0x10] through [rbp+0x38]. This exceeds the old
 * fixed 4-slot stack window, so it exercises the tier-2 requirement that the
 * captured slot count follow the inferred arity rather than a constant.
 *
 * Only the LAST stack argument is used. Under the contiguity rule (arity =
 * highest index observed + 1) that single read has to imply all eleven
 * preceding arguments, because stack arguments are already in memory and are
 * never spilled by the -O0 prologue the way register arguments are.
 *
 * `nullary` takes nothing, so it must yield arity 0 and declare no argument
 * variables - a case that is easy to accidentally turn into a crash or a
 * dropped ppt. At tier 2 its program point still carries `rax`, which is
 * retained under its own name until tier 3 promotes it to a proper `return`;
 * only then does the ENTER point become genuinely empty, as Kvasir's
 * main(void) is.
 */

int twelve(int a, int b, int c, int d, int e, int f,
           int g, int h, int i, int j, int k, int l) {
    return l + 1;          /* only the 12th argument is read */
}

int nullary(void) {
    return 42;
}

int main(void) {
    long acc = 0;
    for (int n = 0; n < 5; n++) {
        acc += twelve(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, n);
        acc += nullary();
    }
    printf("acc = %ld\n", acc);
    return 0;
}
