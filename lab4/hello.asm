global _start
%include "macro_print.asm"
%include "call_consts.asm"

section .rodata

hello: db `Hello World!\n`
HELLO_LEN equ $ - hello

section .text

_start:
    mov rax, 0x2115
    print "rax = ", rax
    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov esi, hello
    mov edx, HELLO_LEN
    syscall
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
