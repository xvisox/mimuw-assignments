// gcc -z execstack -fno-stack-protector -fno-pie -no-pie -o zad2 zad2.c
// setarch x86_64 --addr-no-randomize ./zad2

#include <stdio.h>

void funkcja(void) {
    char buf[16];
    scanf("%s", buf);
}

int main(void) {
    funkcja();
    return 0;
}
