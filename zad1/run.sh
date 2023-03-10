#!/bin/bash

nasm -felf64 inverse_permutation.asm && ld inverse_permutation.o && ./a.out
