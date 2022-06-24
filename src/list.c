/** @file
 * Implementacja klasy przechowującej listę numerów przekierowywanych.
 *
 * @author Hubert Michalski <hm438596@students.mimuw.edu.pl>
 * @copyright Uniwersytet Warszawski
 * @date 2022
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "list.h"

/** @brief Tworzy nowy węzeł listy.
 * Alokuje pamięć na nowy węzeł listy który przechowuje kopię numeru @p num.
 * @param[in] num        - wskaźnik na napis do skopiowania;
 * @param[in] numLength  - długość napisu do skopiowania.
 * @return Wskaźnik na utworzoną strukturę lub NULL, gdy nie udało się
 *         alokować pamięci.
 */
static List *newNode(char const *num, size_t numLength) {
    List *node = malloc(sizeof(*node));
    if (!node) return NULL;

    node->forwardedFrom = malloc(sizeof(char) * (numLength + 1));
    if (!node->forwardedFrom) {
        free(node);
        return NULL;
    } else {
        strcpy(node->forwardedFrom, num);
        node->next = NULL;
        return node;
    }
}

extern bool initialize(List **list, char const *number, size_t numLength) {
    *list = newNode(number, numLength);
    return *list != NULL;
}

extern bool addNode(List *list, char const *number, size_t numLength) {
    List *currentNode = list;

    while (currentNode->next) {
        currentNode = currentNode->next;
    }
    currentNode->next = newNode(number, numLength);
    return currentNode->next != NULL;
}

/** @brief Zwalnia strukturę węzła listy.
 * Usuwa strukturę wskazywaną przez @p node.
 * @param[in] node – wskaźnik na strukturę do usunięcia.
 */
static void freeNode(List *node) {
    if (node) {
        free(node->forwardedFrom);
        free(node);
    }
}

extern void removeFirstNode(List **list) {
    List *nodeToRemove = *list;
    *list = (*list)->next;
    freeNode(nodeToRemove);
}

extern bool removeNode(List *list, char *number, bool (*compare)(const char *, const char *)) {
    List *current = list;
    while (current->next && !compare(number, current->next->forwardedFrom)) {
        current = current->next;
    }
    if (!current->next) return false;

    List *newNextNode = current->next->next;
    freeNode(current->next);
    current->next = newNextNode;
    return true;
}

extern void listDelete(List **list) {
    if (*list == NULL) return;

    List *currentNode = *list;
    List *nextNode = currentNode->next;
    while (nextNode) {
        freeNode(currentNode);
        currentNode = nextNode;
        nextNode = nextNode->next;
    }
    freeNode(currentNode);
    *list = NULL;
}
