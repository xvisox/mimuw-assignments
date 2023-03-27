global _start

_start:
    mov rcx, [rsp]                  ; Ładuje do rcx liczbę parametrów.
    mov rdi, [rsp + 8 * rcx]        ; Ładuje do rbx adres ostatniego parametru.

    xor   rax, rax                  ; Szukamy '\0' w rdi
    mov   ecx, 20                   ; Maksymalna długość nazwy czegos.
    repne scasb

    mov rcx, [rsp]
    mov rax, [rsp + 8 * rcx]        ; Ładuje do rbx adres ostatniego parametru.
    sub rdi, rax                    ; Oblicza długość nazwy czegos.
    add rdi, '0'

    push rdi
    mov rsi, rsp

    mov eax, 1                      ; write
    mov edi, 1                      ; stdout
    mov edx, 1                      ; dlugosc wypisywania, bo nie chce mi sie wiecej
    syscall

    add rsp, 8

.return:
    mov eax, 60
    xor edi, edi
    syscall
