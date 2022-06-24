# Indywidualny projekt programistyczny
## Przekierowywanie telefonów - treść:
### Część 1:
"Tegoroczne duże zadanie polega na zaimplementowaniu operacji na numerach telefonów.
Na potrzeby tego zadania przyjmujemy, że numer telefonu jest to niepusty ciąg składający się z cyfr 0, 1, 2, 3, 4, 5, 6, 7, 8, 9."
### Część 2:
"Modyfikujemy definicję numeru telefonu. 
Numer telefonu jest to nadal niepusty ciąg, którego elementami są cyfry, 
ale teraz dozwolone są dwie dodatkowe cyfry. Cyfrę dziesięć reprezentujemy jako znak *, a cyfrę jedenaście – jako znak #.
Należy zaimplementować funkcję `phfwdReverse` według specyfikacji podanej w szablonie
rozwiązania udostępnionym z pierwszą częścią zadania."
### Część 3:
"Należy zaimplementować funkcję `phfwdGetReverse` która wyznacza przeciwobraz
funkcji `phfwdGet`."

## Implementacja
Rozwiązanie zadania zaimplementowałem za pomocą struktury danych Trie. W projekcie jest 
umieszczona szczegółowa dokumentacja każdej funkcji w formacie `doxygen`. Program jest odporny
na wszelkie wycieki pamięci, co zostało sprawdzone z pomocą valgrinda.

## Uruchamianie programu
W projekcie jest dostępny plik konfiguracyjny programu `cmake` więc wystarczy taka kombinacja komend:
```shell
mkdir <nazwa_folderu>
cd <nazwa_folderu>
cmake ..
make
make doc #tworzenie dokumentacji
./phone_forward 
```

## Testowanie
Żeby uruchomić wszystkie testy zawarte w `phone_forward_tests.c` wystarczy
stworzyć plik wykonywalny `phone_forward_instrumented` za pomocą komend powyżej i 
uruchomić skrypt `test.sh` za pomocą komendy:
```shell
./test.sh <nazwa_folderu>
```