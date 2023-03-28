#!/bin/bash

nasm -f elf64 -w+all -w+error -o hello.o hello.asm
ld --fatal-warnings -o hello hello.o

./hello

rm hello.o hello