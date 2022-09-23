/** @file
 * Implementacja interfejsu klasy
 * przechowującej przekierowania numerów telefonicznych
 *
 * @author Hubert Michalski <hm438596@students.mimuw.edu.pl>
 * @copyright Uniwersytet Warszawski
 * @date 2022
 */

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "phone_forward.h"
#include "list.h"
#include "trie.h"

/** Domyślny rozmiar tablicy numerów w strukturze PhoneNumbers. */
#define DEFAULT_NUMS_SIZE 2

/** Struktura przechowująca przekierowania numerów telefonów. */
struct PhoneForward {
    Trie *fwdToTrie;     /**< Drzewo przekierowań numerów na inne. */
    Trie *fwdFromTrie;   /**< Drzewo numerów które są przekierowywane. */
};

/** Struktura przechowująca ciąg numerów telefonów. */
struct PhoneNumbers {
    char **numbers;   /**< Tablica numerów. */
    size_t size;      /**< Rozmiar tablicy numerów. */
    size_t quantity;  /**< Ilość numerów w tablicy */
};

/** @brief Sprawdza czy znak jest cyfrą.
 * @param[in] c – dany znak.
 * @return  Wartość @p true, jeśli znak jest cyfrą.
 *          Wartość @p false, w przeciwnym przypadku.
 */
static bool extendedIsDigit(char c) {
    return isdigit(c) || c == '#' || c == '*';
}

/** @brief Wyznacza długość numeru.
 * @param[in] num – wskaźnik na napis reprezentujący numer.
 * @return  Długość numeru jeśli był poprawny,
 *          jeśli numer nie był poprawny zwraca wartość 0.
 */
static size_t getLength(char const *num) {
    if (!num) return 0;

    size_t i = 0;
    while (extendedIsDigit(num[i])) i++;
    return num[i] == '\0' ? i : 0;
}

extern PhoneForward *phfwdNew(void) {
    PhoneForward *phoneForward = malloc(sizeof(*phoneForward));
    if (!phoneForward) return NULL;
    phoneForward->fwdToTrie = phoneForward->fwdFromTrie = NULL;

    // Alokowanie pamięci na drzewo przekierowań na numery.
    phoneForward->fwdToTrie = newTrie();
    if (!phoneForward->fwdToTrie) {
        free(phoneForward);
        return NULL;
    }
    phoneForward->fwdToTrie->forwardTo = NULL;

    // Alokowanie pamięci na drzewo przekierowań z numerów.
    phoneForward->fwdFromTrie = newTrie();
    if (!phoneForward->fwdFromTrie) {
        freeTrieTo(phoneForward->fwdToTrie);
        free(phoneForward);
        return NULL;
    }
    phoneForward->fwdFromTrie->forwardsFrom = NULL;

    return phoneForward;
}

extern void phfwdDelete(PhoneForward *pf) {
    if (pf == NULL) return;

    trieDelete(pf->fwdToTrie, freeTrieTo);
    trieDelete(pf->fwdFromTrie, freeTrieFrom);
    free(pf);
}

/** @brief Sprawdza czy pierwszy numer jest prefiksem drugiego.
 * @param[in] num1  - wskaźnik na pierwszy numer;
 * @param[in] num2  - wskaźnik na drugi numer.
 * @return Wartość @p true jeśli @p num1 jest prefiksem @p num2.
 *         Wartość @p false w przeciwnym przypadku.
 */
bool isNum1PrefixOfNum2(const char *num1, const char *num2) {
    // Używam strlen, ponieważ mam pewność, że num1 i num2 kończą się '\0'.
    size_t num1Length = strlen(num1);
    size_t num2Length = strlen(num2);
    return num2Length < num1Length ? false : memcmp(num1, num2, num1Length) == 0;
}

/** @brief Sprawdza czy pierwszy numer taki sam jak drugi.
 * @param[in] num1  - wskaźnik na pierwszy numer;
 * @param[in] num2  - wskaźnik na drugi numer.
 * @return Wartość @p true jeśli @p num1 jest takim samym numerem
 *         jak @p num2. Wartość @p false w przeciwnym przypadku.
 */
extern bool isNum1EqualNum2(const char *num1, const char *num2) {
    return strcmp(num1, num2) == 0;
}

/** @brief Usuwa przekierowanie z drzewa przekierowań z numeru.
 * @param[in] trToRemove - wskaźnik na strukturę w której trzeba
 *                       usunąć numer @p num
 * @param[in] pf         – wskaźnik na strukturę przechowującą przekierowania
 *                       numerów;
 * @param[in] num        – wskaźnik na napis reprezentujący prefiks numerów,
 *                       z którego wykonywane jest przekierowywanie.
 */
static void removeForwarding(Trie *trToRemove, PhoneForward *pf, char const *num) {
    size_t i = 0;
    size_t fwdLength = getLength(trToRemove->forwardTo);
    Trie *trCopy = pf->fwdFromTrie;
    while (i < fwdLength) {
        trCopy = trCopy->children[getIndex(trToRemove->forwardTo, i)];
        i++;
    }
    // Jeśli nie zostanie usunięty żaden węzeł, to znaczy, że szukany prefiks jest w pierwszym węźle.
    if (!removeNode(trCopy->forwardsFrom, (char *) num, isNum1PrefixOfNum2)) removeFirstNode(&trCopy->forwardsFrom);
    if (getNumberOfChildren(trCopy) != 0) return;

    // Usuwanie nieużywanych wierzchołków drzewa fwdFrom.
    Trie *last = NULL;
    while (getNumberOfChildren(trCopy) <= 1 && trCopy->forwardsFrom == NULL && trCopy->parent) {
        last = trCopy;
        trCopy = trCopy->parent;
    }
    if (last) {
        for (i = 0; i < DIGITS_SIZE; i++) {
            trieDelete(last->children[i], freeTrieFrom);
            last->children[i] = NULL;
        }
    }
}

/** @brief Zamienia przekierowanie numeru.
 * Zamienia przekierowanie numeru przechowywane w @p trCopy na @p num2.
 * Informuje użytkownika czy operacja się powiodła.
 * @param[in] trie         - wskaźnik na miejsce w którym trzeba zmienić
 *                         przekierowanie telefonu;
 * @param[in] pf           – wskaźnik na strukturę przechowującą przekierowania
 *                         numerów;
 * @param[in] num1         – wskaźnik na napis reprezentujący prefiks numerów,
 *                         z którego wykonywane jest przekierowywanie;
 * @param[in] num2         – wskaźnik na napis reprezentujący prefiks numerów,
 *                         na które jest wykonywane przekierowanie;
 * @param[in] num2Length   – długość napisu reprezentującego prefiks numerów
 *                         na które jest wykonywane przekierowanie.
 * @return Wartość @p true, jeśli udało się zamienić przekierowanie.
 *         Wartość @p false, jeśli w trakcie zmiany przekierowania
 *         na dłuższy napis zabrakło pamięci.
 */
static bool changeForwarding(Trie *trie, PhoneForward *pf, char const *num1, char const *num2, size_t num2Length) {
    if (trie->forwardTo) {
        Trie *trCopy = pf->fwdFromTrie;
        size_t i = 0;
        size_t fwdLength = getLength(trie->forwardTo);
        while (i < fwdLength) {
            trCopy = trCopy->children[getIndex(trie->forwardTo, i)];
            i++;
        }
        // Jeśli nie zostanie usunięty żaden węzeł, to znaczy, że szukany numer jest w pierwszym węźle.
        if (!removeNode(trCopy->forwardsFrom, (char *) num1, isNum1EqualNum2)) removeFirstNode(&trCopy->forwardsFrom);
        free(trie->forwardTo);
    }
    trie->forwardTo = malloc(sizeof(char) * (size_t) (num2Length + 1));

    if (trie->forwardTo) {
        strcpy(trie->forwardTo, num2);
        return true;
    } else {
        return false;
    }
}

/** @brief Dodaje do listy numer z którego jest przekierowanie.
 * Dodaje informacje do wierzchołka z którego numeru
 * jest wykonywane przekierowywanie na dany numer.
 * @param[in] tr          – wskaźnik na strukturę w której trzeba
 *                        dodać numer @p num;
 * @param[in] num1        – wskaźnik na napis reprezentujący prefiks numerów,
 *                        z którego wykonywane jest przekierowywanie;
 * @param[in] num1Length  – długość napisu @p num1.
 * @return Wartość @p true, jeśli udało dodać przekierowanie.
 *         Wartość @p false, jeśli w trakcie dodawania
 *         przekierowania zabrakło pamięci.
 */
static bool addReversedForwarding(Trie *tr, char const *num1, size_t num1Length) {
    if (tr->forwardsFrom == NULL) {
        return initialize(&tr->forwardsFrom, num1, num1Length);
    } else {
        return addNode(tr->forwardsFrom, num1, num1Length);
    }
}

extern bool phfwdAdd(PhoneForward *pf, char const *num1, char const *num2) {
    size_t num1Length = getLength(num1);
    size_t num2Length = getLength(num2);

    if (!pf || num1Length == 0 || num2Length == 0 || strcmp(num1, num2) == 0)
        return false;

    Trie *trResultTo, *trResultFrom;
    Trie *trRemoveTo, *trRemoveFrom;
    int idx1, idx2;
    idx1 = idx2 = -1;
    bool error = false;

    error = error || !allocateMemoryTrie(pf->fwdToTrie, &trResultTo, &trRemoveTo, &idx1, num1, num1Length, true);
    error = error || !allocateMemoryTrie(pf->fwdFromTrie, &trResultFrom, &trRemoveFrom, &idx2, num2, num2Length, false);
    error = error || !changeForwarding(trResultTo, pf, num1, num2, num2Length);
    error = error || !addReversedForwarding(trResultFrom, num1, num1Length);

    if (error) {
        // Przywracanie struktury do punktu sprzed wywołania funkcji.
        if (idx1 != -1) {
            trieDelete(trRemoveTo->children[idx1], freeTrieTo);
            trRemoveTo->children[idx1] = NULL;
        }
        if (idx2 != -1) {
            trieDelete(trRemoveFrom->children[idx2], freeTrieFrom);
            trRemoveFrom->children[idx2] = NULL;
        }
    }

    return !error;
}

/** @brief Zwalnia strukturę.
 * Usuwa strukturę wskazywaną przez @p trie i usuwa jej przekierowanie.
 * Usuwa również jej przekierowanie z drzewa numerów które przekierowują
 * tzn. @p pf->fwdFromTrie.
 * @param[in] trie – wskaźnik na strukturę przechowującą przekierowania na numery;
 * @param[in] pf   – wskaźnik na strukturę przechowującą przekierowania numerów;
 * @param[in] num  – wskaźnik na napis reprezentujący prefiks numerów,
 *                   z którego wykonywane jest przekierowywanie.
 */
static void freeAndRemoveForwarding(Trie *trie, PhoneForward *pf, char const *num) {
    if (trie->forwardTo) {
        removeForwarding(trie, pf, num);
    }
    free(trie->forwardTo);
    free(trie);
}

/** @brief Usuwa strukturę i przekierowania w obu drzewach.
 * Usuwa strukturę wskazywaną przez @p trie i usuwa występujące przekierowania na numery
 * w drzewie przekierowań z numerów.  Nic nie robi, jeśli wskaźnik ten ma wartość NULL.
 * @param[in] trie      – wskaźnik na usuwaną strukturę;
 * @param[in] pf        – wskaźnik na strukturę przechowującą przekierowania numerów;
 * @param[in] num       – wskaźnik na napis reprezentujący prefiks numerów,
 *                      z którego wykonywane jest przekierowywanie.
 */
static void trieDeleteWithForwarding(Trie *trie, PhoneForward *pf, char const *num) {
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
            freeAndRemoveForwarding(trieCopy, pf, num);
            trieCopy = parentNode;
        }
    }
    freeAndRemoveForwarding(trieCopy, pf, num);
}

/** Usuwa wszystkie dzieci danego wierzchołka.
 * Usuwa wszystkie struktury na jakie wskazuje tablica dzieci @p fwdToTrie,
 * następnie podmienia je na NULL i usuwa wszystkie przekierowania z @p pf->fwdFromTrie,
 * które zostały po drodze usunięte podczas czyszczenia tablicy @p fwdToTrie->children.
 * @param[in] fwdToTrie - wskaźnik na wierzchołek którego dzieci mają być usunięte;
 * @param[in] pf        – wskaźnik na strukturę przechowującą przekierowania numerów;
 * @param[in] num       – wskaźnik na numer z którego wykonywane jest przekierowywanie.
 */
static void removeChildren(Trie *fwdToTrie, PhoneForward *pf, char const *num) {
    free(fwdToTrie->forwardTo);
    fwdToTrie->forwardTo = NULL;
    for (int i = 0; i < DIGITS_SIZE; i++) {
        trieDeleteWithForwarding(fwdToTrie->children[i], pf, num);
        fwdToTrie->children[i] = NULL;
    }
}

extern void phfwdRemove(PhoneForward *pf, char const *num) {
    // Sprawdzenie, czy pf i num nie wskazują na null i czy numer jest prawidłowy.
    size_t numLength = getLength(num);
    if (numLength == 0 || !pf) return;

    size_t i = 0;
    Trie *trCopy = pf->fwdToTrie;
    while (i < numLength && trCopy) {
        trCopy = trCopy->children[getIndex(num, i)];
        i++;
    }

    // Jeśli pfCopy wskazuje na NULL, to podany prefiks nie istnieje.
    if (trCopy) {
        if (trCopy->forwardTo) {
            removeForwarding(trCopy, pf, num);
        }
        removeChildren(trCopy, pf, num);

        // Usuwanie nieużywanych wierzchołków drzewa fwdTo.
        Trie *last = NULL;
        while (getNumberOfChildren(trCopy) <= 1 && trCopy->forwardTo == NULL && trCopy->parent) {
            last = trCopy;
            trCopy = trCopy->parent;
        }
        if (last) removeChildren(last, pf, num);
    }
}

/** @brief Tworzy nową strukturę przechowującą numery.
 * Tworzy nową strukturę niezawierającą żadnych numerów o rozmiarze @p DEFAULT_NUMS_SIZE.
 * @return Wskaźnik na utworzoną strukturę lub NULL, gdy nie udało się
 *         alokować pamięci.
 */
static PhoneNumbers *newPhoneNumbers(void) {
    PhoneNumbers *phoneNumbers = malloc(sizeof(*phoneNumbers));
    if (!phoneNumbers) return NULL;

    phoneNumbers->numbers = malloc((DEFAULT_NUMS_SIZE) * sizeof(char *));
    phoneNumbers->size = DEFAULT_NUMS_SIZE;
    phoneNumbers->quantity = 0;

    if (phoneNumbers->numbers == NULL) {
        free(phoneNumbers);
        return NULL;
    } else {
        phoneNumbers->numbers[0] = NULL;
        return phoneNumbers;
    }
}

/** @brief Zmienia strukturę PhoneNumbers.
 * Zwalnia alokowaną pamięć na tablice w strukturze i zmienia wskaźnik na NULL.
 * Funkcja jest wykorzystywana przy błędzie danych.
 * @param[in] phoneNumbers – wskaźnik na strukturę przechowującą numery telefonów.
 */
static void changePhoneNumbers(PhoneNumbers *phoneNumbers) {
    free(phoneNumbers->numbers);
    phoneNumbers->size = 0;
    phoneNumbers->numbers = NULL;
}

/** @brief Wyznacza przekierowany numer.
 * Tworzy nowy numer z @p num i z @p longestPrefix.
 * @param[in] longestPrefix – wskaźnik na strukturę przechowującą najdłuższy
 *                          znaleziony prefiks;
 * @param[in] num           – wskaźnik na napis reprezentujący prefiks numerów
 *                          przekierowywanych;
 * @param[in] numLength     – długość napisu reprezentującego prefiks numerów
 *                          przekierowywanych;
 * @param[in] prefixLength  – długość napisu na który jest przekierowywany numer.
 * @return Wskaźnik na utworzony numer lub NULL, gdy nie udało się
 *         alokować pamięci.
 */
static char *getForwardedNumber(char *longestPrefix, char const *num, size_t numLength, size_t prefixLength) {
    char *phoneNumber;
    size_t newPrefixLength = getLength(longestPrefix);
    size_t newPhoneNumSize = numLength - prefixLength + newPrefixLength;

    phoneNumber = malloc((size_t) (newPhoneNumSize + 1) * sizeof(char));
    if (!phoneNumber) return NULL;

    // Złożenie nowego numeru z num i podanego prefiksu.
    strcpy(phoneNumber, longestPrefix);
    size_t j = newPrefixLength;
    for (size_t i = prefixLength; i < numLength; i++) {
        phoneNumber[j++] = num[i];
    }
    phoneNumber[newPhoneNumSize] = '\0';

    return phoneNumber;
}

/** @brief Wyznacza najdłuższy prefiks w drzewie.
 * Szuka w drzewie przekierowań najdłuższego pasującego prefiksu do numeru @p num.
 * Jeśli taki prefiks zostanie znaleziony zwraca przez @p prefixLength jego długość.
 * @param[in] tr                  – wskaźnik na strukturę przechowującą
 *                                przekierowania numerów.
 * @param[in] num                 – wskaźnik na napis reprezentujący prefiks numerów
 *                                przekierowywanych;
 * @param[in] numLength           – długość napisu reprezentującego prefiks numerów
 *                                przekierowywanych;
 * @param[in, out] prefixLength   – długość napisu na który jest przekierowywany numer.
 * @return Wskaźnik na strukturę z najdłuższym znalezionym prefiksem. Jeśli przekierowanie
 *         prefiksu podanego numeru nie znajduje się w drzewie, zwraca NULL.
 */
static Trie *findLongestPrefix(Trie const *tr, char const *num, size_t numLength, size_t *prefixLength) {
    size_t i = 0;
    Trie *longestPrefix = NULL;
    Trie *trCopy = (Trie *) tr;

    while (i <= numLength && trCopy) {
        if (trCopy->forwardTo != NULL) {
            longestPrefix = trCopy;
            *prefixLength = i;
        }
        if (i != numLength) trCopy = trCopy->children[getIndex(num, i)];
        i++;
    }
    return longestPrefix;
}

extern PhoneNumbers *phfwdGet(PhoneForward const *pf, char const *num) {
    // Sprawdzenie, czy pf jest poprawne.
    if (!pf) return NULL;
    size_t numLength = getLength(num);
    // Sprawdzenie, czy udało się alokować pamięć i czy numer jest poprawny.
    PhoneNumbers *phoneNumbers = newPhoneNumbers();
    if (!phoneNumbers) return NULL;
    if (numLength == 0) {
        changePhoneNumbers(phoneNumbers);
        return phoneNumbers;
    }

    size_t prefixLength = 0;
    char *phoneNumber;
    Trie *longestPrefix = findLongestPrefix(pf->fwdToTrie, num, numLength, &prefixLength);
    // Jeśli istnieje jakikolwiek prefiks num, to tworzymy nowy, przekierowany numer.
    if (longestPrefix) {
        phoneNumber = getForwardedNumber(longestPrefix->forwardTo, num, numLength, prefixLength);
        if (!phoneNumber) {
            phnumDelete(phoneNumbers);
            return NULL;
        }
        // W przeciwnym wypadku zwracamy kopię podanego numeru.
    } else {
        phoneNumber = malloc((size_t) (numLength + 1) * sizeof(char));
        if (!phoneNumber) {
            phnumDelete(phoneNumbers);
            return NULL;
        }
        strcpy(phoneNumber, num);
    }
    phoneNumbers->numbers[0] = phoneNumber;
    phoneNumbers->quantity++;
    return phoneNumbers;
}

extern char const *phnumGet(PhoneNumbers const *pnum, size_t idx) {
    if (!pnum || idx >= pnum->quantity) {
        return NULL;
    } else {
        return pnum->numbers[idx];
    }
}

extern void phnumDelete(PhoneNumbers *pnum) {
    if (pnum) {
        if (pnum->numbers) {
            for (size_t i = 0; i < pnum->quantity; i++) {
                free(pnum->numbers[i]);
            }
        }
        free(pnum->numbers);
        free(pnum);
    }
}

/** @brief Zwiększa pamięć w tablicy numerów struktury PhoneNumbers.
 * Zwiększa ilość pamięci przeznaczonej na tablice numerów w strukturze @p phnum.
 * @param[in] phnum - wskaźnik na strukturę przechowująca numery telefonów.
 * @return  Wartość @p true, jeśli udało się alokować pamięć.
 *          Wartość @p false, w przeciwnym przypadku.
 */
static bool getMoreMemory(PhoneNumbers *phnum) {
    size_t currentSize = phnum->size;
    size_t newSize = (currentSize / 2 + 1) * 3;
    char **newArray = realloc(phnum->numbers, newSize * sizeof(*phnum->numbers));
    if (!newArray) return false;
    phnum->numbers = newArray;
    phnum->size = newSize;
    return true;
}

/** @brief Zwraca kopię numeru.
 * Zwraca kopię numeru @p num o ile udało się alokować pamięć. Jeśli alokowanie
 * pamięci nie powiodło się, zwraca NULL.
 * @param[in] num       - wskaźnik na napis reprezentujący numer;
 * @param[in] numLength - długość numeru @p num.
 * @return  Kopia numeru jeśli udało się alokować pamięć,
 *          w przeciwny przypadku NULL.
 */
static char *getCopiedNumber(char const *num, size_t numLength) {
    char *copyOfNum = malloc(sizeof(char) * (numLength + 1));
    if (!copyOfNum) return NULL;
    strcpy(copyOfNum, num);
    return copyOfNum;
}

/** @brief Porównuje który numer jest pierwszy.
 * Sprawdza który numer jest pierwszy w kolejności leksykograficznej.
 * @param[in] arg1 - wskaźnik na napis;
 * @param[in] arg2 - wskaźnik na napis.
 * @return Wartość @p 0 jeśli numery są takie same.
 *         Wartość @p 1 jeśli @p arg1 jest przed @p arg2.
 *         Wartość @p -1 jeśli @p arg2 jest przed @p arg1.
 */
int comparator(const char *arg1, const char *arg2) {
    size_t i = 0;
    while (arg1[i] == arg2[i] && (arg1[i] != '\0' && arg2[i] != '\0')) {
        i++;
    }

    if (arg1[i] == '\0' && arg2[i] == '\0') {
        return 0;
    } else if (arg1[i] == '\0') {
        return -1;
    } else if (arg2[i] == '\0') {
        return 1;
    } else {
        return getIndex(arg1, i) > getIndex(arg2, i) ? 1 : -1;
    }
}

/** @brief Funkcja przekazywana do porównywania numerów.
 * @param[in] a - wskaźnik na element do porównania;
 * @param[in] b - wskaźnik na element do porównania.
 * @return Funkcje porównującą numery.
 */
static int compareNumbers(const void *a, const void *b) {
    return comparator(*(const char **) a, *(const char **) b);
}

/** @brief Szuka pierwszego wystąpienia elementu w tablicy numerów.
 * @param[in] phoneNumbers - wskaźnik na strukturę przechowującą
 *                         numery telefonów;
 * @param[in] index        - indeks elementu którego szukamy.
 * @return Pierwszy indeks pod którym wystąpił element o indeksie @p index
 *         w tablicy @p phoneNumbers->numbers. Funkcja zawsze zwraca indeks
 *         mniejszy lub równy parametrowi @p index.
 */
static size_t firstOccurrence(PhoneNumbers *phoneNumbers, size_t index) {
    char **array = phoneNumbers->numbers;
    char *element = phoneNumbers->numbers[index];
    size_t arrayLength = phoneNumbers->quantity + 1;

    for (size_t i = 0; i < arrayLength; i++) {
        if (strcmp(array[i], element) == 0) {
            return i;
        }
    }
    return 0;
}

/** @brief Usuwa strukturę jeśli wystąpił błąd.
 * Sprawdza czy wystąpił błąd alokacji pamięci, jeśli tak - zwalnia
 * strukturę PhoneNumbers @p phoneNumbers.
 * @param[in] isError      - przekazywana wartość czy wystąpił błąd;
 * @param[in] phoneNumbers - wskaźnik na strukturę przechowującą
 *                         numery telefonów.
 * @return Pierwszy indeks pod którym wystąpił element o indeksie @p index
 *         w tablicy @p phoneNumbers->numbers. Funkcja zawsze zwraca indeks
 *         mniejszy lub równy parametrowi @p index.
 */
static bool isMemoryError(bool isError, PhoneNumbers *phoneNumbers) {
    if (isError) {
        phnumDelete(phoneNumbers);
        return true;
    }
    return false;
}

extern PhoneNumbers *phfwdReverse(PhoneForward const *pf, char const *num) {
    // Sprawdzenie, czy pf jest poprawne.
    if (!pf) return NULL;
    size_t numLength = getLength(num);
    // Sprawdzenie, czy udało się alokować pamięć i czy numer jest poprawny.
    PhoneNumbers *phoneNumbers = newPhoneNumbers();
    if (!phoneNumbers) return NULL;
    if (numLength == 0) {
        changePhoneNumbers(phoneNumbers);
        return phoneNumbers;
    }

    size_t i, index;
    i = index = 0;
    Trie *trCopy = pf->fwdFromTrie;
    List *current = NULL;

    // Dodawanie tego samego numeru do listy.
    phoneNumbers->numbers[index] = getCopiedNumber(num, numLength);
    phoneNumbers->quantity++;
    if (isMemoryError(phoneNumbers->numbers[index++] == NULL, phoneNumbers))
        return NULL;

    while (i <= numLength && trCopy) {
        if (trCopy->forwardsFrom) {
            current = trCopy->forwardsFrom;
            while (current) {
                // Jeśli kolejny numer by się nie zmieścił w tablicy, zwiększamy pamięć.
                if (index == phoneNumbers->size)
                    if (isMemoryError(!getMoreMemory(phoneNumbers), phoneNumbers))
                        return NULL;

                phoneNumbers->numbers[index] = getForwardedNumber(current->forwardedFrom, num, numLength, i);
                if (isMemoryError(phoneNumbers->numbers[index] == NULL, phoneNumbers))
                    return NULL;

                // Jeśli taki sam numer wystąpił wcześniej, to jest on usuwany.
                if (firstOccurrence(phoneNumbers, index) != index) {
                    free(phoneNumbers->numbers[index]);
                } else {
                    phoneNumbers->quantity++;
                    index++;
                }
                current = current->next;
            }
        }
        if (i != numLength) trCopy = trCopy->children[getIndex(num, i)];
        i++;
    }
    // Sortowanie wynikowej tablicy.
    qsort((const char **) phoneNumbers->numbers, phoneNumbers->quantity, sizeof(const char *), compareNumbers);
    return phoneNumbers;
}

extern PhoneNumbers *phfwdGetReverse(PhoneForward const *pf, char const *num) {
    PhoneNumbers *phoneNumbersReverse = phfwdReverse(pf, num);
    // Sprawdzenie poprawności danych i czy udało się alokować pamięć.
    if (phoneNumbersReverse == NULL || phoneNumbersReverse->size == 0)
        return phoneNumbersReverse;
    // Nowa struktura, która będzie przekazywana jako wynik.
    PhoneNumbers *phoneNumbers = newPhoneNumbers();
    if (!phoneNumbers) return NULL;

    size_t index = 0;
    PhoneNumbers *phfwdGetResult;
    char *numberToCompare;
    for (size_t i = 0; i < phoneNumbersReverse->quantity; i++) {
        phfwdGetResult = phfwdGet(pf, phoneNumbersReverse->numbers[i]);
        if (isMemoryError(!phfwdGetResult, phoneNumbers)) {
            phnumDelete(phoneNumbersReverse);
            return NULL;
        }
        numberToCompare = phfwdGetResult->numbers[0];
        // Jeśli wynik phfwdGet jest równy num, to dodajemy dany numer do wyniku funkcji.
        if (numberToCompare && strcmp(numberToCompare, num) == 0) {
            // Zwiększenie pamięci na kolejny numer.
            if (index == phoneNumbers->size) {
                if (isMemoryError(!getMoreMemory(phoneNumbers), phoneNumbers)) {
                    phnumDelete(phoneNumbersReverse);
                    return NULL;
                }
            }

            phoneNumbers->numbers[index] = phoneNumbersReverse->numbers[i];
            phoneNumbers->quantity++;
            index++;
        } else {
            // Jeśli dany numer nie należy do wyniku funkcji, to można go usunąć.
            free(phoneNumbersReverse->numbers[i]);
        }
        // Usuwamy strukturę, która była potrzebna tylko do sprawdzenia wyniku.
        phnumDelete(phfwdGetResult);
    }
    // Zwalnianie pamięci po funkcji reverse.
    if (phoneNumbersReverse->quantity > 0) {
        free(phoneNumbersReverse->numbers);
        free(phoneNumbersReverse);
    }
    return phoneNumbers;
}
