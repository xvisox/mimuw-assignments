#include <iostream>
#include <unistd.h>

#define NAP_MICROSECS 1000000

int main() {
    for (int i = 1; i <= 20; i++) {
        if (i % 2 == 0) {
            std::cerr << i << std::endl;
        } else {
            std::cout << i << std::endl;
        }
        usleep(NAP_MICROSECS);  // Sleep for 1 second
    }
    return 0;
}