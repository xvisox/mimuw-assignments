global inverse_permutation

SET_MASK        equ 0x80000000
CLEAR_MASK      equ 0x7fffffff

section .text

clean:                                  ; clears the most significant bit of each element
                                        ; rdi - n (number of elements)
                                        ; rsi - pointer to array of integers
                                        ; [return] - void
                                        ; [modified] - r8, r10d, rdx, ecx

        mov     r8, CLEAR_MASK          ; r8d will store the mask to clear the most significant bit
        mov     ecx, edi                ; save n in ecx
        mov     rdx, rsi                ; save pointer in rdx
.loop_clean:
        mov     r10d, dword [rdx]       ; get element
        and     r10d, r8d               ; clear the most significant bit of it
        mov     dword [rdx], r10d       ; store the element back in the address
        add     rdx, 4                  ; go to next element
        loop    .loop_clean
        ret

                                        ; rdi - n (number of elements)
                                        ; rsi - pointer to array of integers
                                        ; [return] - 0 if the permutation is not valid,
                                        ;            1 otherwise and in that case the inverse permutation
                                        ;            is stored in the array initially given in rsi
                                        ; [modified] - r8, r9, r10, r11, rdx, rcx, rax
inverse_permutation:
        sub     rsp, 0x8                ; reserve space on the stack for calling clean
        xor     rax, rax                ; set the return to false
        test    rdi, rdi                ; check if n is 0
        jz      .end
        mov     r8, 1
        shl     r8, 31
        cmp     rdi, r8
        jae     .end                    ; check if n is greater than 2^31

                                        ; validate permutation in two steps
        mov     ecx, edi                ; save n in ecx
        mov     rdx, rsi                ; save pointer in rdx
.loop_bounds:
        mov     r8d, dword [rdx]        ; get element
        cmp     r8d, edi                ; check if element is greater than or equal to n
        jge     .end
        cmp     r8d, 0                  ; check if element is less than 0
        jl      .end
        add     rdx, 4                  ; go to next element
        loop    .loop_bounds

                                        ; all elements are valid, now check if they are unique
                                        ; the most significant bit will be used to check if the element was visited
        mov     ecx, edi                ; save n in ecx
        mov     rdx, rsi                ; save pointer in rdx
        mov     r11d, SET_MASK          ; r11d will store the most significant bit
        mov     r8d, CLEAR_MASK         ; r8d will store the mask to clear the most significant bit
.loop_visited:
        mov     r10d, dword [rdx]       ; get current element, lets call it p[i]
        and     r10d, r8d               ; clear the most significant bit
        lea     r9, [rsi + 4 * r10]     ; r9 will store the address of the element under the index p[i] i.e. p[p[i]]
        test    dword [r9], r11d        ; check if the element was visited
        jnz     .clear                  ; if set, the permutation is not valid
        mov     r10d, dword [r9]        ; get the element p[p[i]]
        or      r10d, r11d              ; mark the element as visited (by setting the most significant bit)
        mov     dword [r9], r10d        ; store the element in the address
        add     rdx, 4                  ; go to next element
        loop    .loop_visited
                                        ; all elements are unique, the permutation is valid
        call    clean                   ; clear the most significant bits

                                        ; compute the inverse permutation
                                        ; r11d - mask to check if the element was visited
                                        ; eax  - auxiliary variable to store the next element
.inverse:
        xor     ecx, ecx                ; ecx will store i - main loop index
        xor     r8d, r8d                ; r8d will store j - inner loop index
        mov     rdx, rsi                ; rdx  - address of the current element i.e. p[i]
.loop_inverse:
        test    dword [rdx], r11d       ; check if the element was already visited
        jnz     .skip                   ; if set, skip the element
                                        ; otherwise, we start the inner loop to compute the inverse
        mov     r10d, ecx               ; store the previous element i.e. prev = i
        mov     r8d, dword [rdx]        ; store the index that will be changed i.e. j = p[i]
.cycle:
        cmp     r8d, ecx                ; check if i == j
        jz      .end_loop               ; if so, break the loop (because the cycle was found)
        lea     r9, [rsi + 4 * r8]      ; r9 will store the address of the element p[j]
        mov     eax, dword [r9]         ; save next element for later i.e. next = p[j]
        xor     r10d, r11d              ; set the previous element as visited
        mov     dword [r9], r10d        ; store the previous element in the address i.e. p[j] = prev
        mov     r10d, r8d               ; prepare variables for the next iteration i.e. prev = j
        mov     r8d, eax                ; and j = next
        jmp     .cycle                  ; continue the inner loop
.end_loop:
                                        ; end of the cycle
        xor     r10d, r11d              ; set the previous element as visited
        mov     dword [rdx], r10d       ; p[i] = prev
.skip:
        add     rdx, 4                  ; go to next element
        inc     ecx                     ; i++
        cmp     ecx, edi                ; check if i == n
        jne     .loop_inverse           ; if not, continue the loop
        mov     al, 0x1                 ; set the return to true

.clear:
        call    clean                   ; clear the most significant bits
.end:
        add     rsp, 0x8                ; restore the stack
        ret
