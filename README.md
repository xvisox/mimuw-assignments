# Symulacja gry BajtTrade
Celem tego zadania było stworzenie symulacji rynku, w którym biorą udział Agenci,
których celem jest zdobycie jak największej liczby diamentów. Wyróżniamy dwa podstawowe
typy Agentów: Robotników i Spekulantów. Agenci posiadają różne strategie dysponowania swoimi zasobami.

## Uruchamianie projektu

Program może zostać skompilowany do pojedynczego pliku `jar` z wykorzystaniem polecenia

```shell
./kompiluj.sh
```

wynik budowania znajduje się wówczas w katalogu \
`target/BajtTrade-1.0-jar-with-dependencies.jar` \
można go uruchomić z konsoli poprzez polecenie

```shell
./uruchom.sh <argument1> <argument2>
```

Gdzie `argument1` to ścieżka do pliku wejściowego a `argument2` to ścieżka do pliku wyjściowego.
Plik wyjściowy zostanie stworzony, jeśli nie istnieje.

## Dane
Jako wejście do programu powinien zostać przekazany plik `.json`.
Przykładowe dane znajdują się w katalogu `pl/mimuw/dane/` pod nazwą `dane_full.json`.

