global smax
global umax

section .text

;(int a, int b)
; a - edi
; b - esi
smax:
    mov eax, edi
    cmp eax, esi
    cmovl eax, esi
    ret

umax:
    mov eax, edi
    cmp eax, esi
    cmovb eax, esi
    ret