#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stdint.h>

// Sprawdza, czy kolejka jest pusta.
bool queue_is_empty(void);

// Sprawdza, czy kolejka jest pełna.
bool queue_is_full(void);

// Wstawia podaną liczbę na koniec kolejki.
// Jeśli kolejka jest pełna, nic nie robi.
void queue_put(int16_t x);

// Pobiera liczbę z początku kolejki.
// Jeśli kolejka jest pusta, wynik jest niezdefiniowany,
// ale stan kolejki się nie zmiania.
int16_t queue_get(void);

#endif
