/*
 * stack.c - a fixed-size stack driven by an operation stream: 'u' pushes the
 * next byte, 'o' pops, 'p' peeks, anything else is skipped.
 *
 * Planted bugs:
 *   stack_push_overflow  (memory) push checks `count > CAP` instead of
 *                        `count >= CAP`, so a 9th push writes data[8], one
 *                        past the heap array. Needs 9 pushes in one input.
 *   stack_pop_underflow  (memory) pop checks `count >= 0` instead of
 *                        `count > 0`, so popping an empty stack reads data[-1].
 */
#include <stdlib.h>

#include "../runtime/fuzz.h"

#define CAP 8

typedef struct {
    int count;
    unsigned char *data;
} stack_t8;

int push(stack_t8 *s, int v) {
    if (s->count > CAP)                        /* bug: should be >= */
        return -1;
    FUZZ_BUG_FATAL("stack_push_overflow", s->count == CAP);
    s->data[s->count++] = (unsigned char)v;
    return s->count;
}

int pop(stack_t8 *s) {
    if (s->count >= 0) {                       /* bug: should be > 0 */
        FUZZ_BUG_FATAL("stack_pop_underflow", s->count == 0);
        s->count--;
        return s->data[s->count];
    }
    return -1;
}

int peek(stack_t8 *s) {
    return s->count > 0 ? s->data[s->count - 1] : -1;
}

void fuzz_target(const uint8_t *data, size_t size) {
    stack_t8 s;
    s.count = 0;
    s.data = malloc(CAP);
    for (size_t i = 0; i < size && s.count >= 0; i++) {
        if (data[i] == 'u' && i + 1 < size)
            push(&s, data[++i]);
        else if (data[i] == 'o')
            pop(&s);
        else if (data[i] == 'p')
            peek(&s);
    }
    free(s.data);
}
