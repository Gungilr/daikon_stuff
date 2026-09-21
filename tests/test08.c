#include <stdio.h>
#include <stdlib.h>

/*
 * test08.c - exercises reads THROUGH a pointer, for both storage classes a
 * pointer can target: the caller's stack frame and the heap.
 *
 * The register tracer (scripts/unicorn_dwarf.py) captures the raw pointer
 * VALUE held in an argument register at ENTER/EXIT, but never dereferences
 * it - with no type information it cannot know a register holds a pointer,
 * let alone what it points at. Kvasir, with full DWARF types, follows the
 * pointer and reports facts about the pointee.
 *
 * Both functions below have the same shape and differ only in where their
 * argument's target lives, which isolates two distinct gaps:
 *
 *   stack_read -> pure dereference gap. The tracer does receive a valid
 *                 pointer; it just can't read through it.
 *   heap_read  -> dereference gap PLUS the missing allocator model. The
 *                 tracer skips calls to unresolved imports (malloc among
 *                 them) and forces the return register to 0, so the heap
 *                 pointer is observed as the constant 0 and the struct
 *                 actually lives on the zero page that the unmapped-memory
 *                 hook lazily maps. The program still computes the right
 *                 answer under emulation, but `rdi == 0` for every sample
 *                 is an artifact of that stub, not a property of the
 *                 program. Kvasir runs the binary natively and sees the
 *                 real allocation.
 */

typedef struct {
    int a;
    int b;
} pair_t;

/*
 * stack_read: argument points at a pair_t in the caller's frame, built so
 * that b == a + 1 and the result is a + b.
 *
 * Kvasir recovers the pointee relation (it models a pointer as a
 * one-element array, so facts appear over p[].a / p[].b):
 *     p[].a - p[].b + 1 == 0
 *     p[].a elements < return
 *     p[].b elements <= return
 * Note Daikon gives elementwise COMPARISONS against return rather than the
 * exact `return == p->a + p->b`: the pointee is a sequence, and linear
 * equations are not inferred between a sequence and a scalar. That is the
 * honest ground-truth ceiling for this shape, not a Kvasir failure.
 *
 * The tracer reports nothing about the pointee - only register facts, and
 * (at --layouts 1) a spurious constant for the pointer itself, since one
 * deterministic run pins the stack at a fixed address. Running with
 * --layouts >1 relocates the stack and removes that constant.
 */
int stack_read(pair_t *p) {
    return p->a + p->b;
}

/*
 * heap_read: same shape, argument points at a malloc'd pair_t, built so
 * that b == 3a and the result is 2a.
 *
 * Kvasir recovers:
 *     3 * p[].a - p[].b == 0
 *     p[].a elements <= return
 *     p[].b elements >= return
 * The tracer again reports no pointee facts, and additionally reports the
 * pointer as constant zero for the allocator reason described above.
 */
int heap_read(pair_t *p) {
    return p->a * 2;
}

int main(void) {
    long acc = 0;

    for (int i = 0; i < 10; i++) {
        pair_t local = { i, i + 1 };           /* caller's stack frame */
        acc += stack_read(&local);

        pair_t *heap = malloc(sizeof(pair_t)); /* heap */
        heap->a = i;
        heap->b = i * 3;
        acc += heap_read(heap);
        free(heap);
    }

    printf("acc = %ld\n", acc);   /* 190 */
    return 0;
}
