; Hubert Michalski hm438596
global core

extern get_value
extern put_value

%macro CALL_WITH_STACK_ALIGN 1              ; calls a function with aligned stack
                                            ; [%1] - function to call
        mov     rdi, rbx                    ; pass core identifier
        mov     r13, rsp                    ; get the current stack pointer
        and     spl, 0xf0                   ; align the stack pointer
        call    %1
        mov     rsp, r13                    ; restore the stack pointer
%endmacro

section .data

spin_lock:      times N dq -1               ; the identifier of the core that certain core is waiting for
                                            ; i.e. core i wants to exchange values with core spin_lock[i]
value:          times N dq 0                ; the value that certain core is offering to exchange

section .text

core:                                       ; simulates one core of a distributed stack machine
                                            ; rdi - core identifier
                                            ; rsi - pointer to string of operations to perform
                                            ; [return] - the value from the top of the stack
                                            ; [modified] - rax, rdi, rsi, rdx, rcx

                                            ; function calls can change rdi and rsi registers so we need to
                                            ; save their values in the registers that can't be changed
        push    rbx                         ; rbx will store core identifier
        push    rbp                         ; rbp will store pointer to string of operations to perform
        push    r12                         ; r12 will store pointer to stack
        push    r13                         ; r13 will store the mask to align the stack
        mov     rbx, rdi
        mov     rbp, rsi
        mov     r12, rsp

                                            ; loop through the string of operations
.loop:
        xor     eax, eax
        mov     al, [rbp]
.add:
        cmp     al, '+'
        jnz     .multiply
                                            ; add the two values from the top of the stack
        pop     rcx
        add     [rsp], rcx
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
        push    rbx
        jmp     .loop_end
.move:
        cmp     al, 'B'
        jnz     .abandon
                                            ; move the pointer by a value from the top of the stack
        pop     rcx
        cmp     qword [rsp], 0
        jz      .loop_end
        add     rbp, rcx
        jmp     .loop_end
.abandon:
        cmp     al, 'C'
        jnz     .duplicate
                                            ; abandon the value from the top of the stack
        pop     rcx
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
        pop     rcx
        pop     rax
        push    rcx
        push    rax
        jmp     .loop_end
.call_get:
        cmp     al, 'G'
        jnz     .call_put
                                            ; call get_value function
        CALL_WITH_STACK_ALIGN get_value     ; call function with aligned stack
        push    rax                         ; push the value returned by get_value
        jmp     .loop_end
.call_put:
        cmp     al, 'P'
        jnz     .synchronize
                                            ; call put_value function
        pop     rsi                         ; get the value to put
        CALL_WITH_STACK_ALIGN put_value     ; call function with aligned stack
        jmp     .loop_end
.synchronize:
        cmp     al, 'S'
        jnz     .number
                                            ; synchronize two cores and then swap
                                            ; their values from the top
        pop     rcx                         ; get value 'm' from the stack
        mov     rax, [rsp]                  ; get the value to swap with core 'm'

        lea     r9, [rel value]             ; get the address of values to exchange
        mov     [r9 + 8 * rbx], rax         ; set the value[n] to the value to exchange with core 'm',
                                            ; no need to atomically set the value

        mov     rax, rcx                    ; copy the value 'm'
        lea     r8, [rel spin_lock]         ; get the address of spin locks
        xchg    [r8 + 8 * rbx], rax         ; set the value of spin_lock[n] to 'm' meaning that core 'n'
                                            ; is waiting for core 'm' to exchange values
                                            ; we used xchg to atomically set the value
                                            ; additionally, we get the value of spin_lock[n] in rax (that is -1)

.busy_wait:
        cmp     qword [r8 + 8 * rcx], rbx   ; check if core 'm' is waiting for core 'n'
        jnz     .busy_wait
                                            ; we acquired the lock
        mov     rdx, [r9 + 8 * rcx]         ; get the value to swap
        mov     [rsp], rdx                  ; swap the values
        xchg    [r8 + 8 * rcx], rax         ; release the lock, set the value of spin_lock[m] to -1

.wait:
        cmp     qword [r8 + 8 * rbx],  -1   ; check if the core 'm' has already taken our value
        jnz     .wait
        jmp     .loop_end

.number:
                                            ; push number from the string
        sub     al, '0'
        push    rax

.loop_end:
        inc     rbp                         ; move to the next operation
        cmp     byte [rbp], 0               ; check if we reached the end of the string
        jnz     .loop

.return:
        pop     rax                         ; return the value from the top of the stack
        mov     rsp, r12
                                            ; restore registers
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret
