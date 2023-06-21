#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include "labyrinth_utility.h"
#include "bit_operations.h"
#include "error_handle.h"

#define UINT_PLUS1 4294967296
#define BITS_IN_INT 32

// Computes dimension of whole labyrinth.
extern size_t computeDimension(size_t *dimensions, size_t k) {
    size_t result = 1;
    for (size_t i = 0; i < k; i++) {
        result *= dimensions[i];
    }
    return result;
}

// Returns the value (0/1) of chosen bit from hexadecimal number.
static int getBitValue(char *hexVisited, size_t numberOfBit) {
    int positionInHex = numberOfBit / 4;
    int position = numberOfBit % 4;
    char hexValue = hexVisited[positionInHex];
    int decimal;

    if (isdigit(hexValue)) {
        decimal = hexValue - '0';
    } else {
        decimal = hexValue - 'A' + 10;
    }
    return (decimal & (1 << position)) > 0;
}

// Converts coordinates to a number of bit in binary notation.
extern size_t getBitPosition(size_t *coordinates, size_t *dimensions, size_t k) {
    size_t result = 0;
    size_t dimension = 1;

    for (size_t i = 0; i < k; i++) {
        result += (coordinates[i] - 1) * dimension;
        dimension = dimension * dimensions[i];
    }
    return result;
}

// Checks if position is correct.
static bool isPositionCorrect(int *binaryVisited, size_t bit) {
    return !CheckBit(binaryVisited, bit);
}

// Checks if start and end positions are not in walls.
extern bool isInputCorrect(Labyrinth *labyrinth) {
    bool correctStart = isPositionCorrect(labyrinth->visited, labyrinth->start);
    if (!correctStart)
        printError(ERROR_SECOND_LINE);
    bool correctEnd = isPositionCorrect(labyrinth->visited, labyrinth->end);
    if (correctStart && !correctEnd)
        printError(ERROR_THIRD_LINE);
    return correctStart && correctEnd;
}

// Computes dimension const in hash equation.
static size_t getConst(size_t *dimensions, size_t k) {
    size_t result = 0;
    size_t dim = 1;

    for (size_t i = 0; i < k; i++) {
        result += dim;
        dim *= dimensions[i];
    }
    return result;
}

// Unhashes bit to given coordinates array.
static void unhashCoordinates(size_t *dimensions, size_t k, size_t bit, size_t sumOfDims, size_t *unhashed) {
    size_t dimension = computeDimension(dimensions, k);

    for (size_t i = 0; i < k; i++) {
        dimension /= dimensions[k - 1 - i];
        sumOfDims -= dimension;

        if (i != k - 1 && bit % dimension < sumOfDims) {
            unhashed[k - i - 1] = (bit / dimension) - 1;
            bit -= (unhashed[k - i - 1] * dimension);
            while (bit < sumOfDims) {
                unhashed[k - i - 1]--;
                bit += dimension;
            }
        } else {
            unhashed[k - i - 1] = bit / dimension;
            bit = bit % dimension;
        }
    }
}

// Returns unhashed coordinates of choosen bit.
static size_t *getUnhashedCoordinates(size_t bit, size_t k, size_t *dimensions) {
    size_t dimension = computeDimension(dimensions, k);
    size_t equationConst = getConst(dimensions, k);
    size_t *unhashed = malloc(sizeof(size_t) * (size_t) (k));
    checkMemory(unhashed == NULL);

    if (bit == 0) {
        for (size_t i = 0; i < k; i++)
            unhashed[i] = 1;
    } else {
        bit += equationConst;
        size_t sumOfDims = 0;
        // Loop for computing sum of dimensions.
        for (size_t i = 0; i < k; i++) {
            dimension /= dimensions[k - 1 - i];
            sumOfDims += dimension;
        }
        unhashCoordinates(dimensions, k, bit, sumOfDims, unhashed);
    }
    return unhashed;
}

// Converts hexadecimal number to binary array of visited nodes.
extern int *convertHexToBinary(char *hexVisited, size_t dimension, size_t n) {
    int *binaryVisited = NULL;
    size_t size = dimension + (4 - dimension % 4);
    binaryVisited = calloc((size / BITS_IN_INT) + 1, sizeof(int));
    checkMemory(binaryVisited == NULL);
    size_t j = 0;

    for (size_t i = 0; i < n; i++) {
        for (int k = 0; k < 4; k++) {
            if (getBitValue(hexVisited, j)) {
                SetBit(binaryVisited, j);
            }
            j++;
        }
    }
    return binaryVisited;
}

// Computes modulo without overflowing unsigned integer.
static unsigned int computeModuloSum(unsigned int a, unsigned int b, unsigned int s_i, unsigned int m) {
    unsigned int firstElement = ((a % m) * (s_i % m)) % m;
    unsigned int result = ((firstElement % m) + (b % m)) % m;
    return result;
}

// Converts RArray to binary array of visited nodes.
extern int *convertRToBinary(unsigned int *RArray, size_t *n, size_t dimension) {
    int *binaryVisited = NULL;
    size_t size = dimension + (4 - dimension % 4);
    binaryVisited = calloc((size / BITS_IN_INT) + 1, sizeof(int));
    checkMemory(binaryVisited == NULL);
    unsigned int a, b, m, r, s0, i;
    a = RArray[0];
    b = RArray[1];
    m = RArray[2];
    r = RArray[3];
    s0 = RArray[4];

    unsigned int s_i = s0;
    size_t currentBit = 0;
    for (i = 1; i < r + 1; i++) {
        s_i = computeModuloSum(a, b, s_i, m);
        currentBit = s_i % dimension;
        while (currentBit < dimension) {
            SetBit(binaryVisited, currentBit);
            currentBit += UINT_PLUS1;
        }
    }
    *n = size;
    return binaryVisited;
}

// Returns an array of neighboring nodes.
extern size_t *getNeighbours(size_t start, size_t k, size_t *dimensions, size_t *n) {
    size_t *neighbours = malloc(sizeof(size_t) * (size_t) (2 * k));
    checkMemory(neighbours == NULL);
    size_t *startCoordinates = getUnhashedCoordinates(start, k, dimensions);
    size_t j = 0;

    for (size_t i = 0; i < k; i++) {
        if ((startCoordinates[i] + 1) <= dimensions[i]) {
            startCoordinates[i]++;
            neighbours[j++] = getBitPosition(startCoordinates, dimensions, k);
            startCoordinates[i]--;
        }
        if ((startCoordinates[i] - 1) > 0) {
            startCoordinates[i]--;
            neighbours[j++] = getBitPosition(startCoordinates, dimensions, k);
            startCoordinates[i]++;
        }
    }

    *n = j;
    free(startCoordinates);
    return neighbours;
}

extern Labyrinth *getLabyrinth(size_t startBit, size_t endBit, size_t k, int *binaryVisited) {
    Labyrinth *labyrinth = malloc(sizeof(Labyrinth));
    checkMemory(labyrinth == NULL);
    labyrinth->visited = binaryVisited;
    labyrinth->end = endBit;
    labyrinth->start = startBit;
    labyrinth->k = k;
    return labyrinth;
}
