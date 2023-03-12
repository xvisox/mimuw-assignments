global inverse_permutation

section .text

; clear the most significant bit of each element
clean:
    mov r12d, 0x7fffffff        ; r12d will store the mask to clear the most significant bit
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
.loop_clean:
    mov eax, dword [rdx]        ; get element
    and eax, r12d               ; clear the most significant bit
    mov dword [rdx], eax        ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_clean
    ret

; rdi - n (number of elements)
; rsi - pointer to array of elements (ints)
inverse_permutation:
    push rbp                    ; save rbp
    mov rbp, rsp                ; set up the stack frame
    push r12                    ; save r12
    push r13                    ; save r13
    xor r10b, r10b              ; clear r10b, will store the return code

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
    jnz .clear                  ; if set, the permutation is not valid
    mov eax, dword [r9]         ; get the element p[i]
    or eax, r11d                ; set the most significant bit
    mov dword [r9], eax         ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_visited

    ; exited the loop, permutation is valid
    mov r10b, 0x1               ; set the return to true
    call clean                  ; clear the most significant bits

    ; permutation is valid, now compute the inverse
    ; ecx - i
    ; r12d - j
    ; rdx - pointer to p[i]
    ; r11d - mask to check if the most significant bit is set
    ; eax - next
.inverse:
    xor ecx, ecx                ; ecx will store i
    mov rdx, rsi                ; save pointer in rdx
    xor r12d, r12d              ; r12d will store j
.loop_inverse:
    test dword [rdx], r11d      ; check if the most significant bit is set
    jnz .skip                   ; if set, skip the element
    mov r13d, ecx               ; prev = i
    mov r12d, dword [rdx]       ; j = p[i]
.cycle:
    cmp r12d, ecx               ; check if j == i
    jz .end_loop                ; if so, break the loop
    lea r9, [rsi + 4 * r12]     ; r9 will store the address of the element
    mov eax, dword [r9]         ; next = p[j]
    xor r13d, r11d              ; prev ^= mask
    mov dword [r9], r13d        ; p[j] = prev
    mov r13d, r12d              ; prev = j
    mov r12d, eax               ; j = next
    jmp .cycle                  ; continue the loop
.end_loop:
    xor r13d, r11d              ; prev ^= mask
    mov dword [rdx], r13d       ; p[i] = prev
.skip:
    add rdx, 4                  ; go to next element
    inc ecx                     ; i++
    cmp ecx, edi                ; check if i == n
    jne .loop_inverse           ; if not, continue the loop

.clear:
    call clean                  ; clear the most significant bits
.end:
    mov al, r10b                ; return the error code
    pop r13                     ; restore r13
    pop r12                     ; restore r12
    mov rsp, rbp                ; restore stack pointer
    pop rbp                     ; restore rbp
    ret
