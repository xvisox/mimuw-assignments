global inverse_permutation

MAX_N           equ 0x80000000
CLEAR_MASK      equ 0x7fffffff

section .text

inverse_permutation:                    ; inverses the permutation given in the array
                                        ; rdi - n (number of elements)
                                        ; rsi - pointer to array of integers
                                        ; [return] - 0 if the permutation is not valid,
                                        ;            1 otherwise and in that case the inverse permutation
                                        ;            is stored in the array initially given in rsi
                                        ; [modified] - r8, r9, r10, r11, rdx, rcx, rax
        xor     al, al                  ; set the return to false
        test    rdi, rdi                ; check if n is 0
        jz      .end
        mov     r11, MAX_N              ; r11 will store the maximum n value
        cmp     rdi, r11
        ja      .end                    ; check if n is greater than 2^31

                                        ; validate permutation in two steps
        mov     ecx, edi                ; save n in ecx
.loop_bounds:
        lea     rdx, [rsi + 4 * rcx - 4]; r8 will store the address of the (n-i)-th element
        cmp     dword [rdx], edi        ; check if element is greater than or equal to n
        jae     .end                    ; use unsigned comparison to check both bounds at once (>= 0 and < n)
        loop    .loop_bounds

                                        ; all elements are valid, now check if they are unique
                                        ; the most significant bit will be used to check if the element was visited
                                        ; r11d stores the mask to check if the element was visited
        mov     ecx, edi                ; save n in ecx
.loop_visited:
        lea     rdx, [rsi + 4 * rcx - 4]; rdx will store the address of the (n-i)-th element
        mov     r10d, dword [rdx]       ; get current element, lets call it p[i]
        and     r10d, CLEAR_MASK        ; clear the most significant bit, so we can use it as an index
        lea     r9, [rsi + 4 * r10]     ; r9 will store the address of the element under the index p[i] i.e. p[p[i]]
        test    dword [r9], r11d        ; check if the element was visited
        jnz     .clear                  ; if set, the permutation is not valid
        or      dword [r9], r11d        ; mark the element as visited (by setting the most significant bit)
        loop    .loop_visited

                                        ; all elements are unique, the permutation is valid
                                        ; additionally, all elements are now marked as visited
                                        ; now we will mark visited elements by clearing the most significant bits
                                        ; compute the inverse permutation
                                        ; r11d - mask to check if the element was visited
                                        ; eax  - auxiliary variable to store the next element
                                        ; r8d  - index j, the inner loop index
.inverse:
        xor     ecx, ecx                ; ecx will store i - main loop index
.loop_inverse:
        lea     rdx, [rsi + 4 * rcx]    ; rdx will store the address of the i-th element
        test    dword [rdx], r11d       ; check if the element was already visited
        jz     .skip                    ; if not set, skip the element
                                        ; otherwise, we start the inner loop to compute the inverse
        mov     r10d, ecx               ; store the previous element i.e. prev = i
        mov     r8d, dword [rdx]        ; store the index that will be changed i.e. j = p[i]
        xor     r8d, r11d               ; clear the most significant bit of j
.cycle:
        cmp     r8d, ecx                ; check if i == j
        jz      .end_loop               ; if so, break the loop (because the cycle was found)
        lea     r9, [rsi + 4 * r8]      ; r9 will store the address of the element p[j]
        mov     eax, dword [r9]         ; save next element for later i.e. next = p[j]
        xor     eax, r11d               ; clear the most significant bit of next
        mov     dword [r9], r10d        ; store the previous element in the address i.e. p[j] = prev
        mov     r10d, r8d               ; prepare variables for the next iteration i.e. prev = j
        mov     r8d, eax                ; and j = next
        jmp     .cycle                  ; continue the inner loop
.end_loop:
                                        ; end of the cycle
        mov     dword [rdx], r10d       ; p[i] = prev
.skip:
        inc     ecx                     ; i++
        cmp     ecx, edi                ; check if i == n
        jne     .loop_inverse           ; if not, continue the loop

                                        ; the permutation is now inverted
        mov     al, 0x1                 ; set the return to true
        jmp     .end

.clear:
        mov     ecx, edi                ; save n in ecx
.loop_clear:
        lea     rdx, [rsi + 4 * rcx - 4]; rdx will store the address of the (n-i)-th element
        and     dword [rdx], CLEAR_MASK ; clear the most significant bit of it
        loop    .loop_clear
.end:
        ret
