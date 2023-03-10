#!/bin/bash

nasm -f elf64 -w+all -w+error -o delay.o delay.asm
gcc -c -Wall -std=c17 -O2 -o delay_test.o delay_test.c
gcc -o delay_test delay_test.o delay.o
./delay_test
rm -rf delay.o delay_test.o delay_test