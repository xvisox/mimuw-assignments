global transform
extern putchar

section .text

; rdi - pointer to the array of bytes
transform:
    mov rax, rdi
    mov r8b, [rdi]
    cmp r8b, 0
    je .return
    push rbx
.check_if_letter:
    cmp   r8b, 'a'
    jb    .not_letter
    cmp   r8b, 'z'
    ja    .not_letter

.letter:
    mov rbx, rdi
    mov dil, r8b
    call putchar wrt ..plt
    inc rbx
    mov rax, rbx
    jmp .end

.not_letter:
    mov rbx, rdi

    mov dil, '('
    call putchar wrt ..plt

    inc rbx
    mov rdi, rbx
    call transform
    mov rbx, rax

    mov dil, '+'
    call putchar wrt ..plt

    mov rdi, rbx
    call transform
    mov rbx, rax

    mov dil, ')'
    call putchar wrt ..plt

    mov rax, rbx
.end:
    pop rbx
.return:
    ret