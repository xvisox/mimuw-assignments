#!/bin/bash

nasm -DN=2 -f elf64 -w+all -w+error -o core.o core.asm
gcc -c -Wall -Wextra -std=c17 -O2 -o example.o example.c
gcc -z noexecstack -lpthread -o example core.o example.o

./example

rm -f core.o example.o example