#include <assert.h>
#include <stdio.h>

// To jest deklaracja testowanej funkcji.
unsigned counter(void);

int main() {
    for (unsigned i = 1; i < 100; ++i) {
        unsigned int xd = counter();
//        printf("%d\n", xd);
        assert(xd == i);
    }
}
