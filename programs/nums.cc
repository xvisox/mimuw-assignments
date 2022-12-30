#include <iostream>
#include <unistd.h>

#define NAP_MICROSECS 1000000

int main() {
    for (int i = 1; i <= 10; i++) {
        if (i % 2 == 0) {
            std::cerr << i;
        } else {
            std::cout << i;
        }
        usleep(NAP_MICROSECS);  // Sleep for 1 second
    }
    std::cout << std::endl;
    return 0;
}