global delay

section .text

; n - rdi
delay:
    rdtsc           ; liczba cykli zegara w parze rejestrów edx, eax
    shl   rdx, 0x20
    or    rax, rdx  ; liczba cykli zegara w rejestrze rax
    mov   r8, rax

    mov rcx, rdi
    test rcx, rcx
    jz .end
.loop:
    sub rcx, 1
    jnz .loop
.end:
    rdtsc           ; liczba cykli zegara w parze rejestrów edx, eax
    shl   rdx, 0x20
    or    rax, rdx  ; liczba cykli zegara w rejestrze rax

    sub rax, r8
    ret
