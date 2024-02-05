### Simple Markdown (SMD)
*v1.0*

---
Simple Markdown (SMD) to podzbiór języka Markdown zawierający niektóre
z jego konstrukcji składniowych:
- dwa stopnie nagłówków,
- akapity,
- podział wiersza,
- listy nienumerowane oraz numerowane,
- linie poziome,
- kursywę, pogrubienie oraz pogrubioną kursywę,
- wstawki z kodem oraz bloki kodu.
  Przykład zawierający wszystkie te konstrukcje składniowe znajduje się w pliku `example.md`.

Zadanie polega na zaprojektowaniu i implementacji w Kotlinie minibiblioteki zawierającej DSL
służący do tworzenia dokumentów w składni SMD. Program powinien składać się z odpowiedniego
zestawu konstrukcji bibliotecznych (funkcji, klas etc.) oraz funkcji `main` przyjmującej
jeden argument wiersza poleceń - ścieżkę do pliku. Uruchomienie programu powinno
skutkować stworzeniem z użyciem biblioteki do SMD zawartości takiej jak w pliku `example.md`
oraz zapisaniem tej zawartości do pliku pod podaną ścieżką.

Poza poprawnością zawartości pliku oceniany będzie między innymi design biblioteki
(jakość DSL) oraz idiomatyczność rozwiązania. Podobnie jak w poprzednim zadaniu
należy również zadbać o dobre praktyki programistyczne oraz zgodność z konwencjami
stosowanymi w języku.

Rozwiązanie powinno zostać przedstawione do 18 grudnia do końca dnia
w formie pull requesta z feature brancha o nazwie `smd-solution` do brancha `smd`.
Tak jak w przypadku poprzedniego zadania należy stworzyć prywatnego forka
repozytorium na wydziałowym Gitlabie oraz dodać sprawdzającego
jako reviewera stworzonego pull requesta z odpowiednimi uprawnieniami.