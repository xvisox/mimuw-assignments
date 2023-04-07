global core

section .text

; rdi - core identifier
; rsi - pointer to string of operations to perform
core:
    push r12 ; r12 will store core identifier
    push r13 ; r13 will store pointer to string of operations to perform
    mov r12, rdi
    mov r13, rsi

    ; loop through the string
.loop:
    xor rax, rax
    mov al, [r13]
.add:
    cmp al, '+'
    jnz .multiply
    ; add the top two numbers on stack
    pop r8
    add [rsp], r8
.multiply:
    cmp al, '*'
    jnz .negate
    ; multiply the top two numbers on stack
    pop rax
    imul qword [rsp]
    mov [rsp], rax
.negate:
    cmp al, '-'
    jnz .number
    ; negate the top number on stack
    neg qword [rsp]
.number:
    cmp al, '0'
    jb .core_identifier
    cmp al, '9'
    ja .core_identifier
    ; push number
    sub al, '0'
    push rax
.core_identifier:
    cmp al, 'n'
    jnz .move
    ; core identifier
    push r12
.move:
    cmp al, 'B'
    jnz .abandon
    ; move
    ; TODO: implement
.abandon:
    cmp al, 'C'
    jnz .duplicate
    ; abandon
    ; TODO: implement
.duplicate:
    cmp al, 'D'
    jnz .swap
    ; duplicate
    ; TODO: implement
.swap:
    cmp al, 'E'
    jnz .call_get
    ; swap
    ; TODO: implement
.call_get:
    cmp al, 'G'
    jnz .call_put
    ; call get
    ; TODO: implement
.call_put:
    cmp al, 'P'
    jnz .synchronize
    ; call put
    ; TODO: implement
.synchronize:
    ; there's no need to check the condition for 'S'
    ; synchronize two cores and swap their top values
    ; TODO: implement

    ; increment pointer
    inc r13
    ; check if we reached the end of the string
    cmp byte [r13], 0
    jnz .loop

.end:
    ; return the top value on stack
    pop rax
    pop r13
    pop r12
    ret