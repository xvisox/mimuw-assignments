#!/bin/bash

nasm -f elf64 -w+all -w+error -o execve.o execve.asm
ld --fatal-warnings -o execve execve.o

./execve ./hello
rm execve.o execve
