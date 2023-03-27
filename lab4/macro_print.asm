%ifndef MACRO_PRINT_ASM
%define MACRO_PRINT_ASM

%macro print 2
    jmp     %%begin
%%hexa:  db "0123456789ABCDEF"
%%descr: db %1
%%begin:
    push    %2      ; Wartość do wypisania będzie na stosie. To działa również dla %2 = rsp.
    sub     rsp, 16 ; Zrób miejsce na stosie na bufor.
    pushf
    push    rax
    push    rcx
    push    rdx
    push    rsi
    push    rdi
    push    r11

    mov eax, 0x1
    mov edi, 0x1
    mov esi, %%descr
    mov edx, %%begin - %%descr
    syscall

    mov rax, [rsp + 72] ; register to print
    lea rsi, [rsp + 64] ; pointer to buffer
    mov rcx, 0x10       ; number of bytes to print
.loop:
    mov rdx, rax
    shr rdx, 60
    mov r8b, byte [%%hexa + rdx]
    mov byte [rsi], r8b
    inc rsi
    shl rax, 4
    loop .loop

    mov eax, 0x1
    mov edi, 0x1
    mov rsi, rsp
    add rsi, 64
    mov edx, 0x10
    syscall

    add rsp, 0x8
    pop     r11
    pop     rdi
    pop     rsi
    pop     rdx
    pop     rcx
    pop     rax
    popf
    add     rsp, 24
%endmacro

%endif

global _start

section .text

_start:
    mov rax, 0xC123456789abcdef
    print "rax = ", rax
    mov eax, 60
    xor edi, edi
    syscall