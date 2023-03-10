global mac0

; Argumenty funkcji mac0:
;   rdi - wartość a
;   rsi - wartość x
;   rdx - wartość y
mac0:
  mov rax, rsi
  imul rax, rdx
  lea rax, [rdi+rax*1]
  ret ; Wynik powinien być w rejestrze rax.