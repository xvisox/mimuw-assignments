#!/bin/bash

nasm -f elf64 -w+all -w+error -o params.o params.asm
ld --fatal-warnings -o params params.o

./params slowo
rm params.o params
