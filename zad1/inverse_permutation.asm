global _start
section .text
_start:
    mov rdx, output
    mov rax, 0x000042343253500
    mov r8, rax
    mov r9b, 0x40

.loop:
    test r8b, 1
    mov al, 0x30
    jz .skip
    mov al, 0x31
.skip:
    mov byte [rdx], al
    shr r8, 1
    inc rdx
    dec r9
    jnz .loop

    ; calling write
    mov byte [rdx], 0x0a ; newline
    mov rax, 1 ; system call for write
    mov rdi, 1 ; file descriptor (stdout)
    mov rsi, output
    mov rdx, dataSize
    syscall

    ; calling exit
    mov rax, 60  ; system call for exit
    xor rdi, rdi ; exit code 0
    syscall      ; invoke operating system to exit

section .bss
dataSize equ 65 ; 64 characters + 1 for null terminator
output: resb dataSize
