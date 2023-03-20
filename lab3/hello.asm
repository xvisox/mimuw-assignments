global hello
extern putchar

section .rodata

hello_text: db `Hello World!\n\0`
length: dd 14

section .text

hello:
    sub rsp, 0x8
    mov ecx, dword [rel length]
    lea rdx, qword [rel hello_text]
.loop:
    mov dil, byte [rdx]
    push rcx
    push rdx
    call putchar wrt ..plt
    pop rdx
    pop rcx
    inc rdx
    loop .loop
.end:
    add rsp, 0x8
    ret