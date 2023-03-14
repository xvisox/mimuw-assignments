global inverse_permutation

section .text

; clear the most significant bit of each element
clean:
    mov r8, 0x7fffffff          ; r8d will store the mask to clear the most significant bit
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
.loop_clean:
    mov r10d, dword [rdx]       ; get element
    and r10d, r8d               ; clear the most significant bit
    mov dword [rdx], r10d       ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_clean
    ret

; rdi - n (number of elements)
; rsi - pointer to array of elements (ints)
inverse_permutation:
    xor rax, rax                ; set the return to false
    test rdi, rdi               ; check if n is 0
    jz .end
    mov r8, 1
    shl r8, 31                  ; r8 now contains 2^31
    cmp rdi, r8
    jae .end                    ; check if n is greater than 2^31

    ; validate permutation in two steps
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
.loop_bounds:
    mov r8d, dword [rdx]        ; get element
    cmp r8d, edi                ; check if element is greater than n
    jge .end
    cmp r8d, 0                  ; check if element is less than 0
    jl .end
    add rdx, 4                  ; go to next element
    loop .loop_bounds

    ; all elements are valid, now check if they are unique
    mov ecx, edi                ; save n in ecx
    mov rdx, rsi                ; save pointer in rdx
    mov r11d, 0x80000000        ; r11d will store the most significant bit
    mov r8d, 0x7fffffff         ; r8d will store the mask to clear the most significant bit
.loop_visited:
    mov r10d, dword [rdx]       ; get current element
    and r10d, r8d               ; clear the most significant bit
    lea r9, [rsi + 4 * r10]     ; r9 will store the address of the element
    test dword [r9], r11d       ; check if the most significant bit is set
    jnz .clear                  ; if set, the permutation is not valid
    mov r10d, dword [r9]        ; get the element p[i]
    or r10d, r11d               ; set the most significant bit
    mov dword [r9], r10d        ; store the element in the address
    add rdx, 4                  ; go to next element
    loop .loop_visited

    call clean                  ; clear the most significant bits

    ; permutation is valid, now compute the inverse
    ; ecx - i
    ; r8d - j
    ; rdx - pointer to p[i]
    ; r11d - mask to check if the most significant bit is set
    ; eax - next
.inverse:
    xor ecx, ecx                ; ecx will store i
    mov rdx, rsi                ; save pointer in rdx
    xor r8d, r8d                ; r8d will store j
.loop_inverse:
    test dword [rdx], r11d      ; check if the most significant bit is set
    jnz .skip                   ; if set, skip the element
    mov r10d, ecx               ; prev = i
    mov r8d, dword [rdx]        ; j = p[i]
.cycle:
    cmp r8d, ecx                ; check if j == i
    jz .end_loop                ; if so, break the loop
    lea r9, [rsi + 4 * r8]      ; r9 will store the address of the element
    mov eax, dword [r9]         ; next = p[j]
    xor r10d, r11d              ; prev ^= mask
    mov dword [r9], r10d        ; p[j] = prev
    mov r10d, r8d               ; prev = j
    mov r8d, eax                ; j = next
    jmp .cycle                  ; continue the loop
.end_loop:
    xor r10d, r11d              ; prev ^= mask
    mov dword [rdx], r10d       ; p[i] = prev
.skip:
    add rdx, 4                  ; go to next element
    inc ecx                     ; i++
    cmp ecx, edi                ; check if i == n
    jne .loop_inverse           ; if not, continue the loop
    mov al, 0x1                 ; set the return to true

.clear:
    call clean                  ; clear the most significant bits
.end:
    ret

; rsp + 0x8 - n (number of elements)
; zmienic na stale w kodzie
; zmienic komenatrze do znaczacych bitow