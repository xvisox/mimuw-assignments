#!/bin/bash

gcc -c -Wall -Werror -std=c17 -O2 check.c
gcc -o check check.o

objdump -d -M intel-mnemonic check.o

rm -f check.o check
