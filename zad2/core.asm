global core

%macro call_func_with_stack_alignment 1
    mov rdi, r12
    mov r15, rsp
    and r15, 0b1111
    sub rsp, r15
    call %1
    add rsp, r15
%endmacro

extern get_value
extern put_value

section .data
spin_lock: times N dq -1
value: times N dq 0

section .text

; rdi - core identifier
; rsi - pointer to string of operations to perform
core:
    push r12 ; r12 will store core identifier
    push r13 ; r13 will store pointer to string of operations to perform
    push r14 ; r14 will store pointer to stack
    push r15 ; r15 will store the mask to align the stack
    mov r12, rdi
    mov r13, rsi
    mov r14, rsp

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
    ; push core identifier
    push r12
.move:
    cmp al, 'B'
    jnz .abandon
    ; move the pointer by a value from the top of the stack
    pop r8
    cmp r8, 0
    jge .positive
    sub r13, r8
    jmp .switch_end
.positive:
    add r13, r8
.abandon:
    cmp al, 'C'
    jnz .duplicate
    ; abandon the top value from the stack
    pop r8
.duplicate:
    cmp al, 'D'
    jnz .swap
    ; duplicate the top value of the stack
    push qword [rsp]
.swap:
    cmp al, 'E'
    jnz .call_get
    ; swap the top two values on stack
    pop r8
    xchg [rsp], r8
    push r8
.call_get:
    cmp al, 'G'
    jnz .call_put
    ; call get_value
    call_func_with_stack_alignment get_value
    push rax
.call_put:
    cmp al, 'P'
    jnz .synchronize
    ; call put_value
    pop rsi
    call_func_with_stack_alignment put_value
.synchronize:
    cmp al, 'S'
    jnz .switch_end
    ; synchronize two cores and swap their top values
    pop r8                      ; get m from the stack
    mov rax, [rsp]              ; get the value to offer
    lea rsi, [rel value]        ; get the address of value
    lea rdi, [rel spin_lock]    ; get the address of spin_lock
    mov [rsi + 8 * r12], rax    ; set the value to offer
    mov [rdi + 8 * r12], r8     ; set the lock to acquire
    lea rdx, [rdi + 8 * r8]     ; get the address of spin_lock[m]
    mov rcx, -1                 ; closed lock
.busy_wait:
    mov rax, r12                ; open lock we want to acquire
    lock cmpxchg [rdx], rcx
    jnz .busy_wait
    ; we acquired the lock
    mov rax, [rsi + 8 * r8]     ; get the value to swap
    mov [rsp], rax              ; swap the values

.busier_wait:
    cmp qword [rdi + 8 * r12], -1
    jnz .busier_wait

.switch_end:
    ; increment pointer
    inc r13
    ; check if we reached the end of the string
    cmp byte [r13], 0
    jnz .loop

.end:
    ; return the top value on stack
    pop rax
    mov rsp, r14
    ; restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    ret
