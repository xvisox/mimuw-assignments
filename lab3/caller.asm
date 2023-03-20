global caller

section .text

; rdi - func
; rsi - arg
caller:
    sub rsp, 8
    mov rax, rdi
    mov rdi, rsi
    call rax
    add rsp, 8
    ret