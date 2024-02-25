## bsk-pwn-for-students

### 1. Numer indeksu

Hubert Michalski - hm438596

### 2. Nazwa zadania

HARD

### 3. Flaga ze zdalnego serwera

bsk{3434ccef817bf7fecb01488731355927}

### 4. Skrypt który exploituje zadanie na remote

Dostępny w pliku `solve.py`. Starałem się, żeby kod w nim zawarty był zrozumiały
i przypominał te otrzymane na labach, niemniej jednak niektóre stałe w nim nadal są "magiczne"
i kroki może niejasne na pierwszy rzut oka, więc poniżej dodałem także tok rozumowania.

### 5. Rozwiązanie

##### 1. Jak wykonać "buffer overflow" w tym przypadku?

W tym zadaniu "buffer overflow" nie jest dany tak bezpośrednio jak zazwyczaj, tzn. nie ma danego
buforu, którego można przepełnić używając `scanf("%s",...)` lub podobnych funkcji. Za to można zauważyć, że
bez problemu możemy podać długość klucza większą, niż uprzednio zadeklarowana długość danych.
Na końcu funkcji `decrypt`, znajduje się za to pętla, która przypisuje wynik xora danych z kluczem w miejsce `data[i]`.
Zatem od momentu w którym `i > data_len` to zaczynamy wykonywać xor klucza z danymi na stosie, ponieważ tam pamięć jest
alokowana przez
funkcję `alloca`. Wniosek ten jest oczywiście kluczowy do rozwiązania zadania i trzeba było już go wykorzystać w wersji
EASY.
Dodatkowo widzimy, że nie jest zbyt istotne, jaką długość ma pierwszy bufor - zatem ustaliłem, że będzie ona wynosiła
8 (funkcja `send_data_buff` ze skryptu).

#### 2. Znalezienie offsetu od początku bufora do adresu powrotu

Żeby móc podmienić adres powrotu, najpierw trzeba znaleźć jak daleko znajduje się on od początku bufora - do tego
możemy użyć GDB. Po wpisaniu długości 8 i "AAAAAAAA" przykładowo mamy:

```asm
[------------------------------------stack-------------------------------------]
0000| 0x7ffd9cc4a710 ("AAAAAAAA\307\030@")
0008| 0x7ffd9cc4a718 --> 0x4018c7 (<decrypt+23>:	mov    QWORD PTR [rbp-0x8],rax)
0016| 0x7ffd9cc4a720 --> 0x1 
0024| 0x7ffd9cc4a728 --> 0x404ced (<rand+13>:	add    rsp,0x8)
0032| 0x7ffd9cc4a730 --> 0x7ffd9cc4a8a0 --> 0x7ffd9cc4b09a ("SSH_AUTH_SOCK=/run/user/1000/keyring/ssh")
0040| 0x7ffd9cc4a738 --> 0x401aa8 (<do_magic+72>:	and    eax,0xfffffff0)
0048| 0x7ffd9cc4a740 --> 0x7ffd9cc4a710 ("AAAAAAAA\307\030@")
0056| 0x7ffd9cc4a748 --> 0x8 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
44	    puts("How long is the key?");
gdb-peda$ info frame
Stack level 0, frame at 0x7ffd9cc4a760:
 rip = 0x401907 in decrypt (easy.c:44); saved rip = 0x401b3e
 called by frame at 0x7ffd9cc4a780
 source language c.
 Arglist at 0x7ffd9cc4a750, args: 
 Locals at 0x7ffd9cc4a750, Previous frame's sp is 0x7ffd9cc4a760
 Saved registers:
  rbp at 0x7ffd9cc4a750, rip at 0x7ffd9cc4a758
gdb-peda$ 
```

Odejmujemy od "saved rip" adres bufora czyli:

```asm
0x7ffd9cc4a758 - 0x7ffd9cc4a710 = 0x48
```

Stąd magiczna stała 72 na pod koniec skryptu.

#### 3. Leakowanie adresów

Zauważmy, że xor w tym przypadku nam bardzo pomaga, ponieważ możemy po prostu wysyłać do programu
dowolną ilość bajtów `b"\0"` i dostaniemy dokładnie to, co znajduje się na stosie w danym momencie - na początku
oczywiście
zawsze będzie bufor z danymi, czyli w moim przypadku `8 * b"A"`. Do wypisywania danych ze stosu w sensownej formie
dodałem
funkcję `print_recv_stack(recv, mess_len)`. Użyłem jej do m.in. do znalezienia offsetu od początku bufora do adresu
powrotu
z `main()` do funkcji `__libc_start_main()` tzn. po prostu poprosiłem o dużo bajtów i potem przejrzałem kandydatów,
których nie było zbyt wiele.
Stąd wzięła się magiczna stała 14 * 8 na początku pliku, ponieważ potrzebujemy dokładnie tyle danych, żeby zleakować
adres,
na którego podstawie obliczymy adres bazowy `libc`. Pomysł żeby to zrobić oczywiście pochodzi z
rozwiązania `zad5_to_libc_system.py`,
tak samo jak następny krok, czyli obliczenie offsetu do odjęcia od wyciekniętego adresu. Do podejrzenia adresu powrotu
korzystamy
z zaimplementowanej wcześniej funkcji, która wypisuje stos (można np. uruchomić skrypt z flaga `VERBOSE` i `GDB`),
otrzymujemy:

```asm
0x4141414141414141  # 8 * A
...
...
0x7fff6ba4d9d0
0x562314dc8491
...
0x7f743e4280d0      # return address to libc
```

Następnie w GDB:

```asm
gdb-peda$ info proc mappings
process 8731
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x562314dc7000     0x562314dc8000     0x1000        0x0  r--p   /home/xvisox/bsk/task/hard_patched
      ...                ...                   ...        ...  ...    ...
      0x7f743e400000     0x7f743e426000    0x26000        0x0  r--p   /home/xvisox/bsk/task/libc.so.6
      0x7f743e426000     0x7f743e5a5000   0x17f000    0x26000  r-xp   /home/xvisox/bsk/task/libc.so.6
      0x7f743e5a5000     0x7f743e5fa000    0x55000   0x1a5000  r--p   /home/xvisox/bsk/task/libc.so.6
      0x7f743e5fa000     0x7f743e5fe000     0x4000   0x1f9000  r--p   /home/xvisox/bsk/task/libc.so.6
      0x7f743e5fe000     0x7f743e600000     0x2000   0x1fd000  rw-p   /home/xvisox/bsk/task/libc.so.6
      0x7f743e600000     0x7f743e60d000     0xd000        0x0  rw-p   
      0x7f743e72f000     0x7f743e734000     0x5000        0x0  rw-p   
      0x7f743e734000     0x7f743e735000     0x1000        0x0  r--p   /home/xvisox/bsk/task/ld-linux-x86-64.so.2
      ...                ...                   ...        ...  ...    ...
      0x7fff6ba2e000     0x7fff6ba4f000    0x21000        0x0  rw-p   [stack]
      0x7fff6baf7000     0x7fff6bafb000     0x4000        0x0  r--p   [vvar]
      0x7fff6bafb000     0x7fff6bafd000     0x2000        0x0  r-xp   [vdso]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0  --xp   [vsyscall]
gdb-peda$ 
```

Odejmując adresy otrzymujemy offset:

```asm
0x7f743e4280d0 - 0x7f743e400000 = 0x280D0
```

Kolejna magiczna stała rozwikłana :)

#### 4. Podsumowanie

Składając te wszystkie puzzle - najpierw musimy wyciągnąć 14 * 8 bajtów ze stosu, w dwóch celach: zleakowanie adresu
bazowego `libc` oraz wyciągnięcie bajtów potrzebnych do xora, ponieważ nie jest to zwykłe "nadpisywanie" stosu a xor
wykonywany na nim.
Zatem, aby otrzymać oczekiwaną stałą w danym miejscu potrzebujemy także wiedzieć, co znajdowało się tam wcześniej
(`prev ^ want ^ prev = want` i dokładnie to się dzieje w tym przypadku). Ma to jeszcze jedną dodatkową zaletę - nie
musimy
się bawić z wyciąganiem kanarka, ponieważ wystarczy go nie zamieniać. Następnie jak już mamy adres bazowy `libc` oraz
potrzebne bajty,
to preparujemy wiadomość zawierającą gadżety, które pozwolą wywołać shella - znalezienie ich było zupełnie analogiczne
jak w przedstawionych
rozwiązaniach, więc to pominę. Dodatkowo pamiętamy, że adres powrotu jest pod offsetem 72 oraz że musimy xorować bajty
które chcemy zamienić - tak spreparowaną
wiadomość wysyłamy i gotowe :)