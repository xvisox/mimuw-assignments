### Seega
*v1.0*

---
Seega to pochodząca z Egiptu gra planszowa dla dwóch graczy rozgrywana
na kwadratowej planszy o nieparzystej liczbie pól. Jej zasady znajdują się
[tutaj](https://bonaludo.com/2015/10/01/seega-niezwykla-gra-z-egiptu/).

---
Zadanie polega na implementacji w Kotlinie gry Seega z konsolowym interfejsem tekstowym.
Uruchomienie programu powinno umożliwić zagranie w Seegę dwóm graczom na wybranym
rozmiarze planszy (5x5, 7x7, 9x9). Nie trzeba implementować gry człowieka
z komputerem ani protokołów do rozgrywki zdalnej.

Pomiędzy ruchami powinna być wyświetlana w konsoli plansza -
na przykład w taki sposób (literą `W` oznaczone są białe piony,
a literą `B` czarne piony):
```
     a   b   c   d   e
   +---+---+---+---+---+
 1 | B |   |   |   |   |
   +---+---+---+---+---+
 2 |   |   | B | W |   |
   +---+---+---+---+---+
 3 |   | W | * |   |   |
   +---+---+---+---+---+
 4 |   | W | B | B | B |
   +---+---+---+---+---+
 5 |   |   | W |   |   |
   +---+---+---+---+---+
```
Wykonanie ruchu przez gracza polega na wpisaniu odpowiedniej komendy na standardowe
wejście.
W pierwszej fazie gry dostępna jest komenda `deploy` z jednym argumentem oznaczającym
pole, na którym ma być postawiony pion (na przykład `deploy b3` powinno poskutkować
postawieniem na polu b3 piona w odpowiednim kolorze).
W drugiej fazie gry jest zamiast tego dostępna komenda `move` z dwoma argumentami -
polem, na którym stoi pion oraz kierunkiem (`up`, `down`, `left`, `right`),
w którym ma się poruszyć pion (na przykład `move d2 up` powinno poskutkować
przemieszczeniem piona z pola d2 na pole d1).

Program powinien także w odpowiednich momentach wyświetlać komunikaty pomocy,
informacje o stanie gry (czyja jest kolej na posunięcie, z jakim wynikiem
zakończyła się gra etc.) oraz inne niezbędne komunikaty.

---
Należy zadbać o poprawną obsługę wejścia i wyjścia oraz błędów, a także czystą
architekturę programu. Rozwiązanie powinno zawierać testy napisane w JUnit 5
(rozstrzygnięcie, którą część funkcjonalności można i trzeba przetestować oraz
jak to zrobić, jest częścią zadania).
Podobnie jak w poprzednich zadaniach należy również stosować
dobre praktyki programistyczne oraz konwencje języka Kotlin.

---
Rozwiązanie powinno zostać przedstawione do 29 stycznia do końca dnia
w formie pull requesta z feature brancha o nazwie `seega-solution` do brancha `seega`.
Tak jak w przypadku poprzednich zadań należy stworzyć prywatnego forka
repozytorium na wydziałowym Gitlabie oraz dodać sprawdzającego
jako reviewera stworzonego pull requesta z odpowiednimi uprawnieniami.
