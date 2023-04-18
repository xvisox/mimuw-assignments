; Hubert Michalski hm438596
global core

extern get_value
extern put_value

ALIGN_SPL       equ 0xf0

%macro CALL_WITH_STACK_ALIGN 1              ; calls a function with aligned stack
                                            ; [%1] - function to call
        push    rdi                         ; save rdi register (core identifier)
        push    rbp                         ; save rbp register (stack pointer)
        mov     rbp, rsp                    ; get the current stack pointer
        and     spl, ALIGN_SPL              ; align the stack pointer
        call    %1
        mov     rsp, rbp                    ; restore the stack pointer before alignment
        pop     rbp                         ; restore rbp register
        pop     rdi                         ; restore rdi register
%endmacro

section .data
spin_lock:      times N dq -1               ; the identifier of the core that certain core is waiting for,
                                            ; that is core i wants to exchange values with core spin_lock[i]
                                            ; -1 means that the core is not waiting for any other core

section .bss
value:          resq N                      ; the value that certain core is offering to exchange

section .text

core:                                       ; simulates one core of a distributed stack machine
                                            ; rdi - core identifier
                                            ; rsi - pointer to string of operations to perform
                                            ; [return] - the value from the top of the stack
                                            ; [modified] - rax, rsi, rdx, rcx, r8, r9

                                            ; function call can change rsi register so we need to
                                            ; save its value to the 'safe' register rbx
        push    rbx                         ; rbx will store pointer to string of operations to perform
        push    rbp                         ; rbp will store pointer to the stack from the beginning of the simulation
        mov     rbx, rsi
        mov     rbp, rsp

.loop:                                      ; loop through the string of operations
        xor     eax, eax
        mov     al, [rbx]                   ; get the next operation
        cmp     al, '+'
        jz      .add
        cmp     al, '*'
        jz      .multiply
        cmp     al, '-'
        jz      .negate
        cmp     al, 'n'
        jz      .core_identifier
        cmp     al, 'B'
        jz      .move
        cmp     al, 'C'
        jz      .abandon
        cmp     al, 'D'
        jz      .duplicate
        cmp     al, 'E'
        jz      .swap
        cmp     al, 'G'
        jz      .call_get
        cmp     al, 'P'
        jz      .call_put
        cmp     al, 'S'
        jz      .synchronize
        jmp     .number

.add:                                       ; add the two values from the top of the stack
        pop     rcx
        add     [rsp], rcx
        jmp     .loop_end
.multiply:                                  ; multiply the two values from the top of the stack
        pop     rax
        imul    qword [rsp]
        mov     [rsp], rax
        jmp     .loop_end
.negate:                                    ; negate the value at the top of the stack
        neg     qword [rsp]
        jmp     .loop_end
.core_identifier:                           ; push core identifier
        push    rdi
        jmp     .loop_end
.move:                                      ; move the pointer by a value from the top of the stack
        pop     rcx
        cmp     qword [rsp], 0
        jz      .loop_end
        add     rbx, rcx
        jmp     .loop_end
.abandon:                                   ; abandon the value from the top of the stack
        pop     rcx
        jmp     .loop_end
.duplicate:                                 ; duplicate the value from the top of the stack
        push    qword [rsp]
        jmp     .loop_end
.swap:                                      ; swap two values from the top of the stack
        pop     rcx
        pop     rax
        push    rcx
        push    rax
        jmp     .loop_end
.call_get:                                  ; call get_value function
        CALL_WITH_STACK_ALIGN get_value     ; call function with aligned stack
        push    rax                         ; push the value returned by get_value
        jmp     .loop_end
.call_put:                                  ; call put_value function
        pop     rsi                         ; get the value to put
        CALL_WITH_STACK_ALIGN put_value     ; call function with aligned stack
        jmp     .loop_end
.synchronize:                               ; synchronize two cores and then swap
                                            ; their values from the top
        pop     rcx                         ; get value 'm' from the stack
        mov     rax, [rsp]                  ; get the value to swap with core 'm'

        lea     r9, [rel value]             ; get the address of values to exchange
        mov     [r9 + 8 * rdi], rax         ; set the value[n] to the value to exchange with core 'm',
                                            ; no need to atomically set the value

        mov     rax, rcx                    ; copy the value 'm'
        lea     r8, [rel spin_lock]         ; get the address of spin locks
        xchg    [r8 + 8 * rdi], rax         ; set the value of spin_lock[n] to 'm' meaning that core 'n'
                                            ; is waiting for core 'm' to exchange values
                                            ; we used xchg to atomically set the value
                                            ; additionally, we get the value of spin_lock[n] in rax (that is -1)

.busy_wait:
        cmp     qword [r8 + 8 * rcx], rdi   ; check if core 'm' is waiting for core 'n'
        jnz     .busy_wait
                                            ; we acquired the lock
        mov     rdx, [r9 + 8 * rcx]         ; get the value to swap
        mov     [rsp], rdx                  ; swap the values
        xchg    [r8 + 8 * rcx], rax         ; release the lock, set the value of spin_lock[m] to -1

.wait:
        cmp     qword [r8 + 8 * rdi],  -1   ; check if the core 'm' has already taken our value
        jnz     .wait
        jmp     .loop_end

.number:                                    ; push number from the string
        sub     al, '0'
        push    rax

.loop_end:
        inc     rbx                         ; move to the next operation
        cmp     byte [rbx], 0               ; check if we reached the end of the string
        jnz     .loop

.return:
        pop     rax                         ; return the value from the top of the stack
        mov     rsp, rbp                    ; restore the stack pointer
                                            ; restore registers
        pop     rbp
        pop     rbx
        ret
