global _start

SYS_WRITE equ 1
SYS_EXIT  equ 60
STDOUT    equ 1

section .rodata

hello: db `Hello World!\n`
HELLO_LEN equ $ - hello

section .text

_start:
    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov esi, hello
    mov edx, HELLO_LEN
    syscall
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
