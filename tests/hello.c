#include "stdio.h"
#include <unistd.h>

int main() {
    int xd = sched_deadline(10, 11, 0);
    return 0;
}
