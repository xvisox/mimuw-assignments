global delay

section .text

; n - rdi bo uint64_t
align 16
delay:
  mov rcx, rdi
  jrcxz .end
.loop:
  loop .loop
.end:
  ret


    
