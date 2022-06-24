# Indywidualny projekt programistyczny

## Labirynt - treść:

"Labirynt jest zawarty w niepustym przedziale k-wymiarowym (prostopadłościanie k-wymiarowym) składającym się z k-wymiarowych kostek
jednostkowych. Każda z takich kostek może być wypełniona, tworząc ściany labiryntu, lub pusta, tworząc przestrzeń, w której można się
poruszać. Po labiryncie można się poruszać, przechodząc pomiędzy pustymi kostkami stykającymi się ścianą (k−1)-wymiarową.

Położenie każdej kostki (pustej lub wypełnionej) określa się przez podanie jej współrzędnych, które są całkowitymi liczbami dodatnimi.

Droga w labiryncie jest to ciąg przejść między pustymi kostkami od pozycji początkowej do pozycji końcowej. Pozycje początkową i końcową
definiuje się przez podanie współrzędnych dwóch pustych kostek. Długość drogi jest to liczba przejść. Jeśli pozycja końcowa jest
jednocześnie pozycją początkową, to droga ma długość zero." \
TL;DR Labirynt k-wymiarowy :)

## Co zawiera projekt?

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