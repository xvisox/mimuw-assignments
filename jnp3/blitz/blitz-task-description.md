### Blitz
*v1.0*

---
Blitz to gra kościana, w której bierze udział dwóch graczy - jeden z nich
nazywany będzie atakującym, a drugi obrońcą. Do gry używa się
jednej wielościennej kości - może to być kość sześcienna, dwudziestościenna
lub inna.

Gra składa się z serii rund. W czasie rundy gracze rzucają kolejno kością -
najpierw atakujący, potem obrońca. Następnie atakujący może podjąć decyzję
o jednokrotnym przerzuceniu kości, jeśli jest niezadowolony z wyniku.
Potem z tego samego prawa może skorzystać obrońca. Zwycięzcą rundy zostaje gracz,
który uzyskał wyższy wynik na kości. Jeśli obaj gracze uzyskają taki sam wynik,
rundę wygrywa atakujący. Gracz, który wygrał rundę, otrzymuje jeden punkt.
Po zakończeniu rundy rozpoczyna się nowa. Kolejne rundy rogzrywa się tak długo,
aż jeden z graczy osiągnie liczbę punktów ustalanych na początku gry, np. 3.
Gracze w czasie danej gry nie zamieniają się rolami, tj. atakujący w każdej rundzie
jest atakującym, a obrońca obrońcą.

Kość używana do gry może mieć różną liczbę ścianek, ale jest symetryczna w tym
znaczeniu, że prawdopodobieństwo wyrzucenia każdego wyniku z zakresu od 1 do *n*,
gdzie *n* oznacza liczbę ścianek, jest takie samo.

Gracz podejmuje decyzję o przerzuceniu lub nieprzerzuceniu kości zgodnie z przyjętą
przez siebie strategią, która może brać pod uwagę sprawowaną w danej rogzrywce
przez gracza rolę (atakujący lub obrońca), wartości wyrzucone na kości przez siebie
i przeciwnika, rodzaj kości, aktualną liczbę punktów obu graczy oraz liczbę punktów
potrzebną do wygrania gry.

Zaimplementuj grę w Blitza i zasymuluj parędziesiąt rozgrywek, pomiędzy którymi
gracze zamieniają się rolami, tzn. gracz, który w poprzedniej grze był atakującym,
w kolejnej grze jest obrońcą i odwrotnie). Symulacje takie przeprowadź dla
różnych rodzajów kości do gry. Zadbaj o to, aby program wypisywał na standardowe
wyjście komunikaty wskazujące na to, co się dzieje, żeby można było prześledzić
przebieg rozgrywki. Na końcu symulacji wypisz także statystyki opisujące procent
zwycięstw ze względu na rolę (atakującego lub obrońcy) oraz dla każdego z graczy.

Pamiętaj, aby zadanie zaimplementować zgodnie z dobrymi praktykami, zasadami
projektowania i programowania obiektowego oraz konwencjami języka Kotlin.
Rozwiązanie przedstaw w formie pull requesta z feature brancha w prywatnym
repozytorium na wydziałowym Gitlabie, które dostępne będzie dla sprawdzającego.
Jako szablonu użyj brancha `2023-10-23` z repozytorium `kotlin-mimuw/introduction`.
