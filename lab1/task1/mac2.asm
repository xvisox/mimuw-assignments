global mac2

; Argumenty funkcji mac2:
;   rdi - ptr a
;   rsi - ptr x
;   rdx - wartość y
;   [rdi] - a.lo
;   [rdi+8] - a.hi
;   [rsi] - x.lo
;   [rsi+8] - x.hi
;   [rdx] - y.lo
;   [rdx+8] - y.hi
mac2:
  mov rax, [rsi] ; x.lo
  imul rax, [rdx + 8] ; x.lo * y.hi
  mov r8, rax
  mov rax, [rdx] ; y.lo
  imul rax, [rsi + 8] ; y.lo * x.hi
  add r8, rax
  mov rax, [rsi]
  mul QWORD [rdx] ; x.lo * y.lo
  add rdx, r8 ; a.hi += x.lo * y.hi + y.lo * x.hi
  add [rdi], rax ; a.lo += x.lo * y.lo
  adc [rdi + 8], rdx ; a.hi += x.lo * y.lo >> 64 
