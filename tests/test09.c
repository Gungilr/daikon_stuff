#include <stdio.h>

/*
 * test09.c - dead parameters, for argument detection.
 *
 * `b` is never read. The question is whether use-before-def can still see it.
 *
 * Measured, the answer depends entirely on the optimization level:
 *
 *   -O0:  mov %edi,-0x4(%rbp)     both parameters spilled to the frame in the
 *         mov %esi,-0x8(%rbp)     prologue, whether used or not
 *         mov -0x4(%rbp),%eax  => both read before write => arity 2, matching
 *                                 Kvasir exactly
 *
 *   -O1:  mov %edi,%eax        => esi never touched => arity 1, Kvasir says 2
 *         ret
 *
 * So the dead-parameter blind spot belongs to the optimization level, not to
 * dynamic detection. The corpus is built at -O0 (the Makefile passes no -O
 * flag), which flatters the heuristic - any claim about argument recovery made
 * from this corpus is an -O0 claim.
 *
 * `trailing_dead` puts the dead parameter LAST, which is the case the
 * contiguity rule (arity = highest index used + 1) cannot rescue on its own: at
 * -O0 the prologue spill is what recovers it, not contiguity.
 */

int pick_first(int a, int b) {
    return a;
}

/* Dead parameter in the middle: contiguity recovers `b` from the use of `c`
 * even without the prologue spill. */
int skip_middle(int a, int b, int c) {
    return a + c;
}

/* Dead parameter last: only the -O0 spill makes this visible. */
int trailing_dead(int a, int b) {
    return a * 2;
}

int main(void) {
    long acc = 0;
    for (int i = 0; i < 6; i++) {
        acc += pick_first(i, 100);
        acc += skip_middle(i, 200, i + 1);
        acc += trailing_dead(i, 300);
    }
    printf("acc = %ld\n", acc);
    return 0;
}
