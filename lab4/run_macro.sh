#!/bin/bash

nasm -f elf64 -w+all -w+error -o macro_print.o macro_print.asm
ld --fatal-warnings -o macro_print macro_print.o

./macro_print
rm macro_print.o macro_print
