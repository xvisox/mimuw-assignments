/** @file
 * Interfejs klasy przechowującej drzewo przekierowań
 * na numery lub z numerów telefonów.
 *
 * @author Hubert Michalski <hm438596@students.mimuw.edu.pl>
 * @copyright Uniwersytet Warszawski
 * @date 2022
 */

#ifndef __TRIE_H__
#define __TRIE_H__

/** Liczba cyfr. */
#define DIGITS_SIZE 12

#include <stdlib.h>
#include "list.h"

/** Drzewiasta struktura Trie przechowująca przekierowania na dany numer lub z danego numeru */
struct Trie {
    struct Trie *children[DIGITS_SIZE]; /**< Tablica dzieci danego wierzchołka w drzewie. */
    struct Trie *parent;                /**< Wskaźnik na rodzica danego wierzchołka w drzewie. */
    union {
        List *forwardsFrom;         /**< Lista numerów które przekierowują na dany numer. */
        char *forwardTo;            /**< Ciąg cyfr na który dany numer jest przekierowywany. */
    };
};
/**  Definiuje strukturę Trie */
typedef struct Trie Trie;

/** @brief Tworzy nową strukturę.
 * Tworzy nową strukturę niezawierającą żadnych przekierowań na numery lub z numerów.
 * @return Wskaźnik na utworzoną strukturę lub NULL, gdy nie udało się
 *         alokować pamięci.
 */
Trie *newTrie(void);

/** @brief Wyznacza indeks dziecka wierzchołka.
 * @param[in] trie  – wskaźnik na strukturę przechowującą przekierowania numerów.
 *
 * @return Numer indeksu dziecka o najmniejszym numerze wierzchołka @p trie.
 *         Jeśli @p trie nie ma dzieci, funkcja zwraca -1.
 */
int getChildIdx(const Trie *trie);

/** @brief Wyznacza indeks dziecka.
 * @param[in] num   – wskaźnik na napis reprezentujący numer;
 * @param[in] level - cyfra napisu reprezentującego numer.
 * @return  Indeks kolejnego dziecka w drzewie prefiksowym.
 */
int getIndex(char const *num, size_t level);

/** @brief Wyznacza indeks konkretnego dziecka podanego wierzchołka.
 * @param[in] parentNode    – wskaźnik na strukturę przechowującą przekierowania
 *                          numerów która jest ojcem @p trie;
 * @param[in] trie          – wskaźnik na strukturę przechowującą przekierowania
 *                          numerów.
 * @return  Jaki indeks ma @p trie w tablicy dzieci @p parentNode.
 *          Jeśli @p pf nie jest dzieckiem @p parentNode, zwraca -1.
 */
int findChildNode(const Trie *parentNode, const Trie *trie);

/** @brief Informuje o ilości dzieci wierzchołka.
 * @param[in] trie – wskaźnik na strukturę przechowującą przekierowania numerów.
 * @return Ilość dzieci wierzchołka @p trie.
 */
int getNumberOfChildren(const Trie *trie);

/** @brief Zwalnia strukturę.
 * Usuwa strukturę wskazywaną przez @p trie i usuwa jej przekierowanie.
 * @param[in] trie – wskaźnik na strukturę przechowującą przekierowania na numery.
 */
void freeTrieTo(Trie *trie);

/** @brief Zwalnia strukturę.
 * Usuwa strukturę wskazywaną przez @p trie i usuwa numery które na niego są przekierowywane.
 * @param[in] trie – wskaźnik na strukturę przechowującą przekierowania z numerów.
 */
void freeTrieFrom(Trie *trie);

/** @brief Usuwa strukturę.
 * Usuwa strukturę wskazywaną przez @p trie. Nic nie robi, jeśli wskaźnik ten ma
 * wartość NULL.
 * @param[in] trie     – wskaźnik na usuwaną strukturę;
 * @param[in] freeTrie – wskaźnik na funkcję zwalniającą jeden wierzchołek struktury.
 */
void trieDelete(Trie *trie, void (*freeTrie)(Trie *));

/** @brief Tworzy nowe wierzchołki drzewa i zwraca informacje czy udało się alokować pamięć.
 * Funkcja szuka pierwszego miejsca w którym musi zostać stworzony pierwszy nowy wierzchołek,
 * następnie tworzy nowe wierzchołki do końca prefiksu @p num. Jeśli zabraknie pamięci podczas
 * tworzenia wierzchołków przekazywany jest wskaźnik przez @p firstNew na pierwszy nowo utworzony
 * wierzchołek drzewa wraz z indeksem @p idxNew. Przekazuje do @p trResult  wskaźnik na miejsce
 * w którym trzeba dodać przekierowanie lub dodać numer z którego jest przekierowywany.
 * @param[in] tr             – wskaźnik na strukturę przechowującą przekierowania
 *                           numerów;
 * @param[in,out] trResult   – wskaźnik na wskaźnik na strukturę, w której trzeba
 *                           zmienić na co numer @p num jest przekierowywany lub
 *                           z jakiego numeru jest przekierowywany;
 * @param[in,out] firstNew   – wskaźnik na wskaźnik na strukturę, która będzie potrzebna
 *                           do przywrócenia struktury sprzed wywołania funkcji jeśli nie uda
 *                           się alokować pamięci;
 * @param[in,out] idxNew     - indeks dziecka którego trzeba będzie usunąć w razie błędu
 *                           alokacji pamięci;
 * @param[in] num            – wskaźnik na napis reprezentujący prefiks numerów
 *                           przekierowywanych;
 * @param[in] numLength      – długość napisu reprezentującego prefiks numerów
 *                           przekierowywanych;
 * @param[in] isTrieTo       - informacja o tym, czy aktualnie tworzymy drzewo przekierowań
 *                           na numer czy z danego numeru.
 * @return Wartość @p true, jeśli udało się alokować pamięć i dodać nowe wierzchołki drzewa.
 *         Wartość @p false, jeśli w trakcie dodawania wierzchołków zabrakło pamięci.
 */
bool allocateMemoryTrie(Trie *tr, Trie **trResult,
                        Trie **firstNew, int *idxNew,
                        char const *num, size_t numLength,
                        bool isTrieTo);

#endif /* __TRIE_H__ */