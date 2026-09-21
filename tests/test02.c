// tests/test02.c
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int multiply(int a, int b) {
    return a * b;
}

int main() {
    for (int i = 0; i < 10; i++) {
        int sum = add(i, 5);
        int product = multiply(i, 3);
        printf("sum=%d, product=%d\n", sum, product);
    }
    return 0;
}