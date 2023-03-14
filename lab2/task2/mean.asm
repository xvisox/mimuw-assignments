global mean

section .text

; a - rdi
; b - rsi
mean:
    xor r8, r8
    xor rax, rax

    test rdi, 0x1
    jz .skip1
    add r8b, 0x1
.skip1:
    test rsi, 0x1
    jz .skip2
    add r8b, 0x1
.skip2:
    shr rdi, 0x1
    shr rsi, 0x1
    shr r8b, 0x1

    add rdi, rsi
    add rdi, r8

    mov rax, rdi
    ret
