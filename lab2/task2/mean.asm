global mean

section .text

; a - rdi
; b - rsi
mean:
    add rdi, rsi
    rcr rdi, 1
    mov rax, rdi
    ret
