global _start

%include "call_consts.asm"

MAX_LEN equ 9

_start:
    mov rcx, [rsp]                  ; Ładuje do rcx liczbę parametrów.
    mov rdi, [rsp + 8 * rcx]        ; Ładuje do rbx adres ostatniego parametru.

    xor   rax, rax                  ; Szukamy '\0' w rdi
    mov   ecx, MAX_LEN              ; Maksymalna długość nazwy czegos.
    repne scasb

    mov rcx, [rsp]
    mov rax, [rsp + 8 * rcx]        ; Ładuje do rbx adres ostatniego parametru.
    sub rdi, rax                    ; Oblicza długość nazwy czegos.
    add rdi, '0'

    push rdi
    mov rsi, rsp                    ; W rsi mamy adres do wyniku, tzn. [rsi] = k <= 9

    mov eax, SYS_WRITE
    mov edi, STDOUT
    mov edx, 1                      ; Dlugosc wypisywania, bo nie chce mi sie wiecej.
    syscall
    add rsp, 8

.return:
    mov eax, SYS_EXIT
    xor edi, edi
    syscall
