#include <stdio.h>

int sum(int num) {
    
    return num + 1;
}

int main() {
    int total = 0;
    
    for (int i = 0; i < 5; i++) {
        total = sum(total);
    }

    printf("Sum: %d\n", total);
    return 0;
}