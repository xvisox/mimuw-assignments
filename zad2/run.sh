#!/bin/bash

nasm -DN=2 -f elf64 -w+all -w+error -o core.o core.asm
gcc -c -Wall -Wextra -std=c17 -O2 -o test.o test.c
gcc -z noexecstack -lpthread -o test core.o test.o

./test

rm -f core.o test.o test