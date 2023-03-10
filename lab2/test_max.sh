#!/bin/bash

nasm -f elf64 -w+all -w+error -o max.o max.asm
gcc -c -Wall -std=c17 -O2 -o max_test.o max_test.c
gcc -o max_test max_test.o max.o
./max_test
rm -rf max.o max_test.o max_test