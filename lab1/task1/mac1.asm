global mac1

; Argumenty funkcji mac1:
;   rdi - wartość a.lo
;   rsi - wartość a.hi
;   rdx - wartość x
;   rcx - wartość y
mac1:
  mov rax, rdx
  mul rcx
  add rax, rdi
  adc rdx, rsi
  ret