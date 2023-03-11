global inverse_permutation

section .text

; rdi - n (number of elements)
; rsi - pointer to array of elements (ints)
inverse_permutation:
    push rbp                    ; save rbp
    mov rbp, rsp                ; set up the stack frame
    push r9                     ; save r9
    push r10                    ; save r10
    push r11                    ; save r11
    push r12                    ; save r12
    xor r10b, r10b              ; clear r10b, will store the return code
    xor rax, rax                ; clear rax

    ; validate n
    test rdi, rdi               ; check if n is 0
    jz .end
    mov rax, 1
    shl rax, 31                 ; rax now contains 2^31
    cmp rdi, rax
    jae .end                    ; check if n is greater than 2^31

    ; validate permutation in two steps
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
.loop_bounds:
    mov eax, dword [rdx]        ; get element
    cmp eax, edi                ; check if element is greater than n
    jge .end
    cmp eax, 0                  ; check if element is less than 0
    jl .end
    add rdx, 4                  ; go to next element
    loop .loop_bounds

    ; all elements are valid, now check if they are unique
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
    mov r11d, 0x80000000        ; r11d will store the most significant bit
    mov r12d, 0x7fffffff        ; r12d will store the mask to clear the most significant bit
.loop_visited:
    mov eax, dword [rdx]        ; get current element
    and eax, r12d               ; clear the most significant bit
    lea r9, [rsi + 4 * rax]     ; r9 will store the address of the element
    test dword [r9], r11d       ; check if the most significant bit is set
    jnz .clean                  ; if set, the permutation is not valid
    mov eax, dword [r9]         ; get the element p[i]
    or eax, r11d                ; set the most significant bit
    mov dword [r9], eax         ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_visited

    ; exited the loop, permutation is valid
    mov r10b, 0x1 ; set the return to true

.clean:
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
.loop_clean:
    mov eax, dword [rdx]        ; get element
    and eax, r12d               ; clear the most significant bit
    mov dword [rdx], eax        ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_clean

    test r10b, r10b             ; check if the return code is true
    jz .end                     ; if not, return

.inverse:


.end:
    mov al, r10b                ; return the error code
    pop r12                     ; restore r12
    pop r11                     ; restore r11
    pop r10                     ; restore r10
    pop r9                      ; restore r9
    mov rsp, rbp                ; restore stack pointer
    pop rbp                     ; restore rbp
    ret
