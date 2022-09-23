/** @file
 * Implementacja klasy przechowującej drzewo przekierowań
 * na numery lub z numerów telefonów.
 *
 * @author Hubert Michalski <hm438596@students.mimuw.edu.pl>
 * @copyright Uniwersytet Warszawski
 * @date 2022
 */

#include "trie.h"
#include <stdlib.h>
#include <ctype.h>

/** Różnica między wartością 10 a odpowiadającym kodzie ASCII symbolem gwiazdki. */
#define DIFF_BETWEEN_STAR_10_ASCII 32
/** Różnica między wartością 11 a odpowiadającym kodzie ASCII symbolem hasha. */
#define DIFF_BETWEEN_HASH_11_ASCII 24

extern Trie *newTrie(void) {
    Trie *trie = malloc(sizeof(*trie));
    if (!trie) return NULL;

    trie->parent = NULL;
    for (int i = 0; i < DIGITS_SIZE; i++) trie->children[i] = NULL;

    return trie;
}

extern int getChildIdx(const Trie *trie) {
    for (int i = 0; i < DIGITS_SIZE; i++) {
        if (trie->children[i]) return i;
    }
    return -1;
}

extern int getIndex(char const *num, size_t level) {
    char currentDigit = num[level];
    if (isdigit(currentDigit)) {
        return currentDigit - '0';
    } else if (currentDigit == '*') {
        return currentDigit - DIFF_BETWEEN_STAR_10_ASCII;
    } else {
        return currentDigit - DIFF_BETWEEN_HASH_11_ASCII;
    }
}

extern int findChildNode(const Trie *parentNode, const Trie *trie) {
    for (int i = 0; i < DIGITS_SIZE; i++) {
        if (parentNode->children[i] == trie) return i;
    }
    return -1;
}

extern int getNumberOfChildren(const Trie *trie) {
    int counter = 0;
    for (int i = 0; i < DIGITS_SIZE; i++) {
        if (trie->children[i]) counter++;
    }
    return counter;
}

extern void freeTrieTo(Trie *trie) {
    if (trie) free(trie->forwardTo);
    free(trie);
}

extern void freeTrieFrom(Trie *trie) {
    if (trie->forwardsFrom) listDelete(&trie->forwardsFrom);
    free(trie);
}

extern void trieDelete(Trie *trie, void (*freeTrie)(Trie *)) {
    if (trie == NULL) return;
    Trie *trieCopy = trie;
    Trie *parentNode = NULL;
    int idx;

    while (trieCopy != trie->parent) {
        if ((idx = getChildIdx(trieCopy)) != -1) {
            trieCopy = trieCopy->children[idx];
        } else {
            parentNode = trieCopy->parent;
            if (parentNode) {
                parentNode->children[findChildNode(parentNode, trieCopy)] = NULL;
            }
            if (trieCopy == trie) break;
            (*freeTrie)(trieCopy);
            trieCopy = parentNode;
        }
    }
    (*freeTrie)(trieCopy);
}

/** @brief Ustawia wartości początkowe w wierzchołku.
 * Ustawia w strukturze wskazywanej przez @p trie NULL w miejscu listy numerów
 * z których dany jest przekierowywany lub w miejsce numeru na który przekierowuje
 * zależnie od wartości parametru @p isTrieTo. Jeśli @p trie wskazuje na NULL to nic nie robi.
 * @param[in] trie      – wskaźnik na strukturę przechowującą przekierowania z lub na numery.
 * @param[in] isTrieTo  - informacja o tym czy obsługujemy drzewo przekierowań z czy na numery.
 */
static void setDefault(Trie *trie, bool isTrieTo) {
    if (!trie) return;

    if (isTrieTo) {
        trie->forwardTo = NULL;
    } else {
        trie->forwardsFrom = NULL;
    }
}

extern bool allocateMemoryTrie(
        Trie *tr, Trie **trResult,
        Trie **firstNew, int *idxNew,
        char const *num, size_t numLength,
        bool isTrieTo) {

    Trie *firstNewNode = NULL;
    Trie *trCopy = tr;
    Trie *trPrevious = trCopy;
    bool error = false;
    int index = getIndex(num, 0);
    int indexToRemove;
    size_t i = 0;

    // Szukanie pierwszego wierzchołka, który wskazuje na null.
    while (i < numLength && trCopy->children[index]) {
        trCopy = trCopy->children[index];
        trPrevious = trCopy;
        index = getIndex(num, ++i);
    }
    if (i != numLength) {
        firstNewNode = trCopy;
        indexToRemove = index;
    } else {
        *trResult = trCopy;
        return true;
    }

    // Tworzenie nowych wierzchołków.
    while (i < numLength && !error) {
        trCopy->children[index] = newTrie();
        setDefault(trCopy->children[index], isTrieTo);
        if (trCopy->children[index]) {
            trCopy = trCopy->children[index];
            trCopy->parent = trPrevious;
            trPrevious = trCopy;
        } else {
            error = true;
        }
        index = getIndex(num, ++i);
    }

    *firstNew = firstNewNode;
    *idxNew = indexToRemove;
    *trResult = trCopy;
    return !error;
}
