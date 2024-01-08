// gcc -z execstack -fno-stack-protector -fno-pie -no-pie -o zad1 zad1.c

#include <stdio.h>
#include <stdlib.h>

void win(void) {
    puts("WIN");
    system("sh");
}

void funkcja(void) {
    char buf[16];
    scanf("%s", buf);
}

int main(void) {
    funkcja();
    return 0;
}
