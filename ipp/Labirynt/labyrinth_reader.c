#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "labyrinth_reader.h"
#include "error_handle.h"

#define SIZE_MAX_LEN 20

// Function to read input and ignore all whitespace characters.
static char getCharImproved() {
    char stdin_char = (char) getchar();
    while (isspace(stdin_char) && stdin_char != '\n') {
        stdin_char = (char) getchar();
    }
    return stdin_char;
}

// Multiplication with overflow handling.
static size_t safeMultiplication(size_t a, size_t b, bool *overflow) {
    size_t result = a * b;
    if (result < a || result < b) {
        *overflow = true;
    }
    return result;
}

// Utility function to compute next size of an array.
static size_t more(size_t size) {
    bool overflow = false;
    size = safeMultiplication((size / 2 + 1), 3, &overflow);
    return !overflow ? size : SIZE_MAX;
}

// Utility function to reverse an array.
static void reverseArray(char *array, size_t size) {
    for (size_t i = 0; i < size / 2; i++) {
        char temp = array[i];
        array[i] = array[size - 1 - i];
        array[size - 1 - i] = temp;
    }
}

// Returns next number from input.
static size_t readNextNumber(char firstChar, bool *error, bool *endOfLine) {
    char number[SIZE_MAX_LEN + 3];
    memset(number, 0, SIZE_MAX_LEN + 3);
    char nextChar;
    int i = 1;
    number[0] = firstChar;

    while (isdigit(nextChar = (char) getchar()) && i < SIZE_MAX_LEN + 2) {
        // Ignores all leading zeroes except the first one.
        if (!(number[0] == '0' && nextChar == '0' && i == 1)) {
            number[i] = nextChar;
            i++;
        }
    }
    size_t stdin_number = strtoull(number, NULL, 10);

    // ERROR HANDLE
    if (!isspace(nextChar)) *error = nextChar != EOF;
    *error = *error || errno;
    *endOfLine = nextChar == '\n';
    return stdin_number;
}

// If labyrinth size if greater than SIZE_MAX we can already tell that it will be too big.
static void checkLabyrinthSize(size_t *dimension, size_t i, size_t *numbersArray, bool *overflow) {
    *dimension = safeMultiplication(*dimension, numbersArray[i], overflow);
    if (*overflow) {
        printError(MEMORY_OVERFLOW);
        free(numbersArray);
        exit(1);
    }
}

// Reads whole line of input and returns array of numbers with error handling.
static size_t *readLine(bool *error, size_t *k, bool computeDimension) {
    size_t size = 1;
    size_t i = 0;
    size_t dimension = 1;
    size_t *numbersArray = malloc(sizeof(size_t));
    checkMemory(numbersArray == NULL);
    bool overflow, endOfLine;
    overflow = endOfLine = (*error) = false;

    char nextChar = getCharImproved();
    (*error) = !isdigit(nextChar) || nextChar == EOF;
    while (isdigit(nextChar) && nextChar != '\n' && !overflow && !(*error)) {
        // Allocating more memory for the array.
        if (i == size) {
            size = more(size);
            numbersArray = realloc(numbersArray, (size_t) size * sizeof(*numbersArray));
            checkMemory(numbersArray == NULL);
        }
        numbersArray[i] = readNextNumber(nextChar, &overflow, &endOfLine);

        *error = *error || overflow || numbersArray[i] == 0;
        if (computeDimension && !(*error)) checkLabyrinthSize(&dimension, i, numbersArray, &overflow);

        nextChar = endOfLine ? '\n' : getCharImproved();
        i++;
    }
    // ERROR HANDLE
    *error = *error || overflow || isalpha(nextChar);
    *k = i;
    return numbersArray;
}

// Checks if all coordinates aren't beyond given dimensions.
static bool isBeyondDimension(size_t *coordinates, size_t *dimensions, size_t k) {
    for (size_t i = 0; i < k; i++) {
        if (coordinates[i] > dimensions[i])
            return true;
    }
    return false;
}

// Reads first three lines of input and returns them written down in arrays.
extern bool getInputArrays(size_t **start, size_t **end, size_t **dim, size_t *k_dim) {
    int line = 1;
    size_t k = 0;
    size_t first_k = 0;
    size_t *startCoordinates, *endCoordinates, *dimensions;
    bool error = false;
    startCoordinates = endCoordinates = dimensions = NULL;

    dimensions = readLine(&error, &first_k, true);
    if (!error) {
        startCoordinates = readLine(&error, &k, false);
        error = error || first_k != k || isBeyondDimension(startCoordinates, dimensions, k);
        line++;
    }
    if (!error) {
        endCoordinates = readLine(&error, &k, false);
        error = error || first_k != k || isBeyondDimension(endCoordinates, dimensions, k);
        line++;
    }
    *dim = dimensions;
    *start = startCoordinates;
    *end = endCoordinates;
    *k_dim = first_k;
    if (error) {
        printError(line);
        exit(1);
    }
    return !error;
}

// Returns total size of an binary array.
static size_t getNumberOfBits(char *hex, int n) {
    int decimal = 0;
    int i = 1;
    int j = 0;
    size_t result = 4 * (n - 1);

    if (isdigit(hex[0]))
        decimal = hex[0] - '0';
    else
        decimal = hex[0] - 'A' + 10;

    while (decimal / i != 0) {
        i = i * 2;
        j++;
    }
    return result + j;
}

// Reads fourth line of input and returns reversed array of hexadecimal number.
extern char *getHexArray(bool *error, size_t *length, size_t dimension) {
    size_t i = 0;
    size_t size = 1;
    char *hexVisited = malloc((size_t) size * sizeof(char));
    checkMemory(hexVisited == NULL);
    hexVisited[0] = 'X';

    char nextChar = (char) getchar();
    while (isxdigit(nextChar = (char) getchar())) {
        // Ignores all leading zeroes except the first one.
        if (!(hexVisited[0] == '0' && nextChar == '0' && i == 1)) {
            // Allocating more memory for the array.
            if (size == i) {
                size = more(size);
                hexVisited = realloc(hexVisited, ((size_t) size) * sizeof *hexVisited);
                checkMemory(hexVisited == NULL);
            }
            hexVisited[i] = toupper(nextChar);
            i++;
        }
    }
    // ERROR HANDLING
    if (nextChar != '\n' && nextChar != EOF)
        *error = !isspace(nextChar) || getCharImproved() != '\n';
    *error = *error || getNumberOfBits(hexVisited, i) > dimension;

    if (!(*error)) reverseArray(hexVisited, i);
    else printError(ERROR_FOURTH_LINE);

    *length = i;
    return hexVisited;
}

// Reads fourth line of input and returns array of fife numbers.
extern unsigned int *getRArray(bool *error) {
    int i = 0;
    size_t temp;
    bool overflow, endOfLine;
    overflow = endOfLine = false;

    unsigned int *R_Array = malloc((size_t) 6 * sizeof(unsigned int));
    checkMemory(R_Array == NULL);

    char nextChar = getCharImproved();
    while (nextChar != '\n' && nextChar != EOF && !overflow) {
        temp = readNextNumber(nextChar, &overflow, &endOfLine);
        if (temp > UINT_MAX) {
            overflow = true;
        } else {
            R_Array[i] = temp;
        }
        nextChar = endOfLine ? '\n' : getCharImproved();
        i++;
    }
    // ERROR HANDLING
    *error = overflow || R_Array[2] == 0 || i != 5;
    if (*error) printError(ERROR_FOURTH_LINE);
    return R_Array;
}

extern bool isHexInput() {
    char nextChar = getCharImproved();
    if (nextChar == '0') {
        return true;
    } else if (nextChar == 'R') {
        return false;
    } else {
        printError(ERROR_FOURTH_LINE);
        exit(1);
    }
}

// Checks if there is a next line of an input.
extern bool noNextLine() {
    if (getCharImproved() != EOF) {
        printError(ERROR_FIFTH_LINE);
        return false;
    }
    return true;
}
