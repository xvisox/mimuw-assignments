# Indywidualny projekt programistyczny

## Małe zadanie - Labirynt:

"Labirynt jest zawarty w niepustym przedziale k-wymiarowym (prostopadłościanie k-wymiarowym) składającym się z k-wymiarowych kostek
jednostkowych. Każda z takich kostek może być wypełniona, tworząc ściany labiryntu, lub pusta, tworząc przestrzeń, w której można się
poruszać. Po labiryncie można się poruszać, przechodząc pomiędzy pustymi kostkami stykającymi się ścianą (k−1)-wymiarową.

Położenie każdej kostki (pustej lub wypełnionej) określa się przez podanie jej współrzędnych, które są całkowitymi liczbami dodatnimi.

Droga w labiryncie jest to ciąg przejść między pustymi kostkami od pozycji początkowej do pozycji końcowej. Pozycje początkową i końcową
definiuje się przez podanie współrzędnych dwóch pustych kostek. Długość drogi jest to liczba przejść. Jeśli pozycja końcowa jest
jednocześnie pozycją początkową, to droga ma długość zero." \
TL;DR Labirynt k-wymiarowy :)

### Co zawiera projekt?

* Plik `makefile` który po wywołaniu polecenia `make` tworzy
  program wykonywalny o nazwie `labyrinth`.
* Skrypt testujący `test.sh` który po wykonaniu polecenia
    ```bash
    ./test.sh prog dir
    ```
  uruchamia program `prog` dla wszystkich plików wejściowych postaci `dir/*.in` i porównuje wyjście z odpowiadającymi im plikami `dir/*.out`
  i `dir/*.err`
  a następnie wypisuje, które zakończyły się powodzeniem.

* Taki sam skrypt testujący o nazwie `szybciorem.sh` który wywołuje program bez valgrinda.
* Wszystkie testy do zadania w folderze skompresowanym `tests`.

## Duże zadanie - Przekierowywanie telefonów:

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