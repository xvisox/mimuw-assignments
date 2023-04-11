; Hubert Michalski hm438596
global core

extern get_value
extern put_value

%macro CALL_WITH_STACK_ALIGN 1          ; calls a function with aligned stack
                                        ; [%1] - function to call
        mov     rdi, r12                ; pass core identifier
        mov     r15, rsp                ; get the current stack pointer
        and     spl, 0xf0               ; align the stack pointer
        call    %1
        mov     rsp, r15                ; restore the stack pointer
%endmacro

section .data

spin_lock:      times N dq -1           ; the identifier of the core that certain core is waiting for
                                        ; i.e. core i wants to exchange values with core spin_lock[i]
value:          times N dq 0            ; the value that certain core is offering to exchange

section .text

core:                                   ; simulates one core of a distributed stack machine
                                        ; rdi - core identifier
                                        ; rsi - pointer to string of operations to perform
                                        ; [return] - the value from the top of the stack
                                        ; [modified] - rax, rdi, rsi, rdx, r8

                                        ; function calls can change rdi and rsi registers so we need to
                                        ; save their values in the registers that can't be changed
        push    r12                     ; r12 will store core identifier
        push    r13                     ; r13 will store pointer to string of operations to perform
        push    r14                     ; r14 will store pointer to stack
        push    r15                     ; r15 will store the mask to align the stack
        mov     r12, rdi
        mov     r13, rsi
        mov     r14, rsp

                                        ; loop through the string of operations
.loop:
        mov     al, [r13]
.add:
        cmp     al, '+'
        jnz     .multiply
                                        ; add the two values from the top of the stack
        pop     r8
        add     [rsp], r8
        jmp     .loop_end
.multiply:
        cmp     al, '*'
        jnz     .negate
                                        ; multiply the two values from the top of the stack
        pop     rax
        imul    qword [rsp]
        mov     [rsp], rax
        jmp     .loop_end
.negate:
        cmp     al, '-'
        jnz     .core_identifier
                                        ; negate the value at the top of the stack
        neg     qword [rsp]
        jmp     .loop_end
.core_identifier:
        cmp     al, 'n'
        jnz     .move
                                        ; push core identifier
        push    r12
        jmp     .loop_end
.move:
        cmp     al, 'B'
        jnz     .abandon
                                        ; move the pointer by a value from the top of the stack
        pop     r8
        cmp     qword [rsp], 0
        jz      .loop_end
        add     r13, r8
        jmp     .loop_end
.abandon:
        cmp     al, 'C'
        jnz     .duplicate
                                        ; abandon the value from the top of the stack
        pop     r8
        jmp     .loop_end
.duplicate:
        cmp     al, 'D'
        jnz     .swap
                                        ; duplicate the value from the top of the stack
        push    qword [rsp]
        jmp     .loop_end
.swap:
        cmp     al, 'E'
        jnz     .call_get
                                        ; swap two values from the top of the stack
        pop     r8
        xchg    [rsp], r8
        push    r8
        jmp     .loop_end
.call_get:
        cmp     al, 'G'
        jnz     .call_put
                                        ; call get_value function
        CALL_WITH_STACK_ALIGN get_value ; call function with aligned stack
        push    rax                     ; push the value returned by get_value
        jmp     .loop_end
.call_put:
        cmp     al, 'P'
        jnz     .synchronize
                                        ; call put_value function
        pop     rsi                     ; get the value to put
        CALL_WITH_STACK_ALIGN put_value ; call function with aligned stack
        jmp     .loop_end
.synchronize:
        cmp     al, 'S'
        jnz     .number
                                        ; synchronize two cores and then swap
                                        ; their values from the top
        pop     r8                      ; get value 'm' from the stack
        mov     rax, [rsp]              ; get the value to swap with core 'm'

        lea     rsi, [rel value]        ; get the address of values to exchange
        mov     [rsi + 8 * r12], rax    ; set the value[n] to the value to exchange with core 'm',
                                        ; no need to atomically set the value

        mov     rax, r8                 ; copy the value 'm'
        lea     rdi, [rel spin_lock]    ; get the address of spin locks
        xchg    [rdi + 8 * r12], rax    ; set the value of spin_lock[n] to 'm' meaning that core 'n'
                                        ; is waiting for core 'm' to exchange values
                                        ; we used xchg to atomically set the value
                                        ; additionally, we get the value of spin_lock[n] in rax (that is -1)

        lea     rdx, [rdi + 8 * r8]     ; get the address of spin_lock[m]
.busy_wait:
        cmp     qword [rdx], r12        ; check if core 'm' is waiting for core 'n'
        jnz     .busy_wait
                                        ; we acquired the lock
        mov     rcx, [rsi + 8 * r8]     ; get the value to swap
        mov     [rsp], rcx              ; swap the values
        xchg    [rdx], rax              ; release the lock, set the value of spin_lock[m] to -1

        lea     rdx, [rdi + 8 * r12]    ; get the address of spin_lock[n]
.wait:
        cmp     qword [rdx], -1         ; check if the core 'm' has already taken our value
        jnz     .wait
        jmp     .loop_end

.number:
                                        ; push number from the string
        sub     al, '0'
        movzx   r8, al
        push    r8

.loop_end:
        inc     r13                     ; move to the next operation
        cmp     byte [r13], 0           ; check if we reached the end of the string
        jnz     .loop

.return:
        pop     rax                     ; return the value from the top of the stack
        mov     rsp, r14
                                        ; restore registers
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        ret
