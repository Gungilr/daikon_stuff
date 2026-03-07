#include <stdio.h>

int main() {
    int i;
    int even_count = 0;
    int odd_count = 0;
    
    for (i = 0; i < 10; i++) {
        if (i % 2 == 0) {
            even_count++;
        } else {
            odd_count++;
        }
    }
    
    printf("Even: %d, Odd: %d\n", even_count, odd_count);
    return 0;
}