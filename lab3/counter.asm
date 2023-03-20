global counter

section .bss
count: resd 1

section .text

counter:
    lea r8, [rel count]
    mov eax, dword [r8]
    inc eax
    mov dword [r8], eax
    ret

