#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>

uint64_t func(uint64_t a, uint64_t b) {
    return a * b;
}

int main() {
    uint64_t res3 = func(434234323, 434234323342);
    printf("%lu\n", res3);
    return 0;
}