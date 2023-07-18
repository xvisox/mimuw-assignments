#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>

uint64_t func(char c) {
    switch (c) {
        case 'n':
            return 0;
        case 'P':
            return 1;
        case 'E':
            return 2;
        case 'D':
            return 3;
        case 'G':
            return 4;
        case 'S':
            return 5;
        case 'B':
            return 6;
        case 'C':
            return 7;
        default:
            return 0;
    }
}

int main() {
    return 0;
}