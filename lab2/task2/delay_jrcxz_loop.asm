global delay

section .text

; n - rdi bo uint64_t
delay:
    rdtsc           ; liczba cykli zegara w parze rejestrów edx, eax
    shl   rdx, 0x20
    or    rax, rdx  ; liczba cykli zegara w rejestrze rax
    mov   r8, rax

    mov rcx, rdi
    jrcxz .end
.loop:
    loop .loop
.end:
    rdtsc           ; liczba cykli zegara w parze rejestrów edx, eax
    shl   rdx, 0x20
    or    rax, rdx  ; liczba cykli zegara w rejestrze rax
    sub   rax, r8
    ret
