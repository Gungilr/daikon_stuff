#include <stdio.h>
#include <stdlib.h>

/*
 * test13.c - array pointees, for the array-versus-struct decision.
 *
 * `sum_array` takes the dominant C idiom: a pointer travelling with its
 * length. That correlation is the ONLY observable signal separating an array
 * from a struct, because the two are otherwise identical at the machine level:
 *
 *   - Access patterns match exactly. An `int p[2]` and a `struct {int a, b;}`
 *     are both read as two 4-byte fields at offsets 0 and 4.
 *   - The addressing mode does not help either. gcc -O0 computes arr[i]
 *     arithmetically (`lea 0x0(,%rax,4),%rdx ; add %rdx,%rax ; mov (%rax)`)
 *     rather than emitting a scaled-index dereference, so the instruction form
 *     is indistinguishable from `p->a`.
 *
 * So the tracer claims an array only when some integer argument equals the
 * element count on every observed call. `n` does here; nothing does for
 * `two_fields`, which must therefore stay struct-modelled.
 *
 * `varying_len` is called with different lengths so the correlation has to
 * hold across calls rather than coinciding once.
 *
 * `two_fields` is the trap: a two-element pointee whose function also takes an
 * unrelated int. If that int ever equalled 2 the pointee would be misread as
 * an array, so it is deliberately passed a value that never does.
 */

int sum_array(int *arr, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += arr[i];
    return s;
}

int varying_len(int *arr, int n) {
    return n > 0 ? arr[n - 1] : 0;
}

typedef struct { int a, b; } pair_t;

/* Struct pointee plus an unrelated int that must not be mistaken for a length. */
int two_fields(pair_t *p, int tag) {
    return p->a + p->b + (tag - tag);
}

int main(void) {
    int *heap = malloc(5 * sizeof(int));
    for (int i = 0; i < 5; i++) heap[i] = i + 1;

    int *small = malloc(3 * sizeof(int));
    for (int i = 0; i < 3; i++) small[i] = (i + 1) * 10;

    pair_t q = {7, 8};
    long acc = sum_array(heap, 5);
    acc += varying_len(heap, 5);
    acc += varying_len(small, 3);
    acc += two_fields(&q, 99);

    printf("acc = %ld\n", acc);
    free(small);
    free(heap);
    return 0;
}
