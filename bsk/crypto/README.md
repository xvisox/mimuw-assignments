## bsk-crypto-for-students

### 1. Numer indeksu

Hubert Michalski - hm438596

### 2. Zadania oraz flagi

- NCG - flag{still-not-a-csprng}
- Block cipher (easy) - flag{sh0rt-fl4G}
- Block cipher (hard) - __NOT SOLVED__

### 3. Rozwiązania i opis znalezionych podatności

#### NCG

Aby wyliczyć następny stan potrzebujemy zmiennych ***a***, ***c***, ***m*** oraz ***s4*** - gdzie
ostatnie dwie mamy dane, zatem wystarczy znaleźć tylko ***a*** oraz ***c***. Mamy dany wzór:

```
s_n = ((s_{n-1} * a) xor c) mod m
```

Używając go możemy wyznaczyć równanie:

```
s_2 xor s_1 = (((s_1 * a) xor c) mod m) xor (((s_0 * a) xor c) mod m) =>
s_2 xor s_1 = (((s_1 * a) xor c) xor ((s_0 * a) xor c)) mod m =>
s_2 xor s_1 = ((s_1 * a) xor (s_0 * a)) mod m
```

Zredukowaliśmy w ten sposób ilość niewiadomych do samego ***a***, przeprowadzając podobne rozumowanie do zamieszczonego
[tutaj](https://crypto.stackexchange.com/questions/108177/solving-equation-of-xor-and-mod-operation), możemy napisać
szybki algorytm
wyznaczania kandydatów na zmienną ***a***. Nie jest to jednoznaczne i czasami się nie udaje - stąd pętla while w moim
rozwiązaniu,
jednak powinno się to udać w maksymalnie 2-3 próby. Następnie korzystamy ponownie z danego równania, żeby wyliczyć
zmienną ***c***:

```
s_1 = ((s_0 * a) xor c) mod m =>
s_1 xor (s_0 * a) = c 
```

Posiadając te wszystkie zmienne możemy bez problemu wyliczyć następny stan.

#### Block cipher (easy)

Początkowo, chcemy aby serwer wysłał nam zaszyfrowaną flagę, w tym celu możemy wykorzystać wiedzę o tym,
że pierwsza wiadomość jaką wysyła to `Hello`. Posiadając tę wiedzę oraz `iv` możemy obliczyć `iv'` które po wykonaniu
xor na
odszyfrowanej wiadomości zwróci serwerowi `flag?` a ten nam odeśle flagę. Czyli co dokładnie się dzieje podczas
wysyłania/odbierania wiadomości:

```
# wysyłanie
sth = hello xor iv
encrypted = encrypt(sth)
send(encrypted) 

# odbieranie
encrypted = receive()
sth = decrypt(encrypted)
message = sth xor iv' <-- tym możemy manipulować oraz znamy sth
```

Zatem liczymy `iv'` w następujący sposób:

```
sth = hello xor iv
iv' = sth xor flag?
```

Serwer podczas otrzymywania wiadomości wyliczy:

```
message = sth xor iv'
message = sth xor sth xor flag?
message = flag? (suckes)
```

Otrzymaliśmy w ten sposób flagę, ale jest zaszyfrowana :)  
Musimy skorzystać z serwera jako wyroczni. Zauważmy, że na wiadomości wykonywany jest `.strip()` zatem
wszystkie białe znaki z początku i końca będą usunięte przed wykonaniem porównania. Możemy wykorzystać ten fakt
aby ustalić kolejne bajty flagi tzn.: wiemy, że na początku jest `flag{**********}`, analogicznie jak poprzednio
zamieniamy to na `_flag?*********}` (gdzie `_` to biały znak)
tylko tym razem nie znamy całego `sth`. Zgadujemy więc pierwszy bajt `*` aż losowo trafimy na `?`, a poznamy to po tym,
że serwer odpowie na ten request flagą.
Powyższe kroki wykonujemy dla wszystkich 10 znaków flagi, otrzymując w ten sposób odszyfrowaną wiadomość.
