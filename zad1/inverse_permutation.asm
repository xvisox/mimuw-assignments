global inverse_permutation

section .text
; prints the value of rax in binary
print_rax:
    mov rdx, output ; register to store output address
    mov r8, rax ; register to store rax value
    mov r9b, 0x40 ; 64 bits
.loop:
    test r8b, 1
    mov al, 0x30
    jz .skip
    mov al, 0x31
.skip:
    mov byte [rdx], al
    shr r8, 1
    inc rdx
    dec r9b
    jnz .loop

    mov byte [rdx], 0x0a ; newline
    ; now reverse the string
    dec rdx
    mov r10, rdx ; r10 will be used to store the end of the string
    mov rdx, output ; rdx will be used to store the start of the string
    mov r9b, 0x20 ; 32 bits
.loop2:
    xor ax, ax
    mov al, byte [rdx]
    push ax
    mov al, byte [r10]
    mov byte [rdx], al
    pop ax
    mov byte [r10], al
    inc rdx
    dec r10
    dec r9b
    jnz .loop2

    ; calling write
    mov rax, 1 ; system call for write
    mov rdi, 1 ; file descriptor (stdout)
    mov rsi, output
    mov rdx, data_size
    syscall
    ret

; rdi - n (number of elements)
; esi - pointer to array of elements
inverse_permutation:
    test rdi, rdi ; check if n is 0
    jz .false
    mov rax, 1
    shl rax, 31 ; rax now contains 2^31
    cmp rdi, rax
    ja .false ; check if n is greater than 2^31

.true:
    mov al, 0x1 ; return true
    jmp .end
.false:
    mov al, 0x0 ; return false
.end:
    ret

; TODO: remove this section, only for debugging.
section .bss
data_size equ 65 ; 64 characters + 1 for null terminator
output: resb data_size
