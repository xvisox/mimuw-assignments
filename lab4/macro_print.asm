%include "call_consts.asm"

%ifndef MACRO_PRINT_ASM
%define MACRO_PRINT_ASM

%macro print 2
    jmp     %%begin
%%hexa:  db "0123456789ABCDEF"
%%descr: db %1
%%begin:
    push %2               ; Wartość do wypisania będzie na stosie. To działa również dla %2 = rsp.
    sub rsp, HEX_REG_LEN  ; Zrób miejsce na stosie na bufor.
    pushf
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov esi, %%descr
    mov edx, %%begin - %%descr
    syscall

    mov rax, [rsp + 72]   ; Rejestr do wypisania.
    lea rsi, [rsp + 64]   ; Bufor na wypisywanie.
    mov rcx, HEX_REG_LEN  ; Liczba znakow do wypisania;
.loop:
    mov rdx, rax
    shr rdx, 60           ; Wez 4 najbardziej znaczace bity.
    mov r8b, byte [%%hexa + rdx]
    mov byte [rsi], r8b
    inc rsi
    shl rax, 4
    loop .loop

    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov rsi, rsp
    add rsi, 64         ; Bufor na wypisywanie.
    mov edx, HEX_REG_LEN; Liczba znakow do wypisania;
    syscall

    mov eax, SYS_WRITE
    mov edi, STDOUT
    push 0x0A
    mov rsi, rsp
    mov edx, 1
    syscall
    add rsp, 8

    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popf
    add rsp, 24
%endmacro

%endif
