/** @file
 * Interfejs klasy przechowującej listę numerów przekierowywanych.
 *
 * @author Hubert Michalski <hm438596@students.mimuw.edu.pl>
 * @copyright Uniwersytet Warszawski
 * @date 2022
 */

#ifndef __LIST_H__
#define __LIST_H__

#include <stdbool.h>

/** Struktura przechowująca listę numerów z których jest wykonywane przekierowywanie. */
struct Node {
    char *forwardedFrom;    /**< Wskaźnik na numer z którego jest wykonane przekierowywanie. */
    struct Node *next;      /**< Wskaźnik na następny węzeł listy. */
};
/** Definiuje strukturę Listy */
typedef struct Node List;

/** @brief Inicjalizacja listy.
 * @param[in, out] list  – wskaźnik na wskaźnik na strukturę listy;
 * @param[in] number     – numer który będzie przechowywany
 *                       w pierwszym węźle listy;
 * @param[in] numLength  – długość numeru @p number.
 * @return  Wartość @p true jeśli udało się alokować pamięć na
 *          stworzenie listy. Wartość @p false w przeciwnym przypadku.
 */
bool initialize(List **list, char const *number, size_t numLength);

/** @brief Dodanie węzła do listy.
 * Dodaje nowy węzeł na koniec listy o ile udało się alokować pamięć.
 * @param[in] list       – wskaźnik na wskaźnik na strukturę listy;
 * @param[in] number     – numer który będzie dodany w nowym węźle;
 * @param[in] numLength  – długość numeru @p number.
 * @return  Wartość @p true jeśli udało się alokować pamięć na
 *          nowy węzeł. Wartość @p false w przeciwnym przypadku.
 */
bool addNode(List *list, char const *number, size_t numLength);

/** @brief Usuwa pierwszy węzeł listy.
 * @param[in, out] list  – wskaźnik na wskaźnik na strukturę listy.
 */
void removeFirstNode(List **list);

/** @brief Usuwa wybrany węzeł listy.
 * Funkcja usuwa z listy @p list węzeł który przechowuje numer @p number.
 * @param[in] list    – wskaźnik na strukturę listy;
 * @param[in] number  – wybrany napis reprezentujący numer do usunięcia;
 * @param[in] compare – wskaźnik na funkcję porównująca dwa numery.
 * @return  Wartość @p true jeśli udało się znaleźć węzeł i go usunąć.
 *          Wartość @p false w przeciwnym przypadku.
 */
bool removeNode(List *list, char *number, bool (*compare)(const char *, const char *));

/** @brief Usuwa całą strukturę listy.
 * Usuwa z listy wszystkie węzły i ustawia wskaźnik @p list na NULL.
 * @param[in, out] list  – wskaźnik na wskaźnik na strukturę listy.
 */
void listDelete(List **list);

#endif /* __LIST_H__ */