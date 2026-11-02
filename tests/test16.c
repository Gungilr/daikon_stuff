#include <stdlib.h>

/*
 * test16.c - phase 11 (object model) fixture.
 *
 * copy_item  two pointers into two different objects. Before the object
 *            model, every access was credited to whichever argument was
 *            checked first; now src's reads and dst's writes land on their
 *            own objects.
 * sum_list / second
 *            a heap linked list: pointer fields, a recursive type, and a
 *            depth-2 read (head->next->val) - the 2+-levels-deep facts that
 *            are 54% of what the tracer used to miss on Kvasir's suite.
 * as_int / as_float
 *            a union read both ways at one offset: the classifier must
 *            ABSTAIN rather than pick int or float.
 * scale      a double global read with SSE: typed double, not long.
 * tag        a struct global holding a string pointer and a count.
 * half       a heap struct whose second field is never written: with
 *            --shadow it is nonsensical, as Kvasir reports it.
 * motto      a char* global the program never dereferences: only its value,
 *            the address of a .rodata string, says it is a string
 *            (--rodata-strings).
 */

typedef struct { int id; double weight; } item_t;
typedef struct node { int val; struct node *next; } node_t;
typedef union { int i; float f; } num_t;
typedef struct { const char *label; long count; } tag_t;
typedef struct { int set; int unset; } half_t;

double scale = 2.5;
tag_t tag = { "fixture", 3 };
const char *motto = "never read";

void copy_item(item_t *dst, const item_t *src) {
    dst->id = src->id;
    dst->weight = src->weight;
}

int sum_list(node_t *head) {
    int s = 0;
    while (head) {
        s += head->val;
        head = head->next;
    }
    return s;
}

int second(node_t *head) {
    return head->next->val;
}

int as_int(num_t *n) { return n->i; }
float as_float(num_t *n) { return n->f; }

long tagged(tag_t *t) {
    return t->count + t->label[0];
}

int peek(half_t *h) {
    return h->set ^ h->unset;   /* reads a field nobody wrote */
}

int main(void) {
    item_t a = {7, 1.5}, b;
    copy_item(&b, &a);

    node_t *n3 = malloc(sizeof *n3);
    node_t *n2 = malloc(sizeof *n2);
    node_t *n1 = malloc(sizeof *n1);
    n3->val = 3; n3->next = 0;
    n2->val = 2; n2->next = n3;
    n1->val = 1; n1->next = n2;
    int s = sum_list(n1) + second(n1);

    num_t u;
    u.i = 5;
    s += as_int(&u);
    u.f = 1.0f;
    s += (int)as_float(&u);

    s += (int)(tagged(&tag) * scale);

    half_t *h = malloc(sizeof *h);
    h->set = 9;
    s += peek(h) & 0;
    return s & 0x7f;
}
