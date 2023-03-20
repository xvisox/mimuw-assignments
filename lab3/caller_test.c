#include <assert.h>
#include <stdio.h>

// To jest deklaracja testowanej funkcji.
int caller(int (*callback)(int), int x);

// To jest deklaracja funkcji wołanej przez testowaną funkcję.
int called(int x);

#define XD 10

int main() {
    for (int i = 1; i < XD; ++i) {
//        int result = caller(called, i);
//        printf("%d\n", result);
        assert(i + 1 == caller(called, i));
    }
}
