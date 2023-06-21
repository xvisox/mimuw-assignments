#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include "queue.h"
#include "labyrinth_reader.h"
#include "labyrinth_utility.h"
#include "labyrinth_solver.h"
#include "error_handle.h"

size_t *startCoordinates, *endCoordinates, *dimensions;
char *hexVisited;
unsigned int *RArray;

static void clean_main() {
    free(startCoordinates);
    free(endCoordinates);
    free(dimensions);
    free(hexVisited);
    free(RArray);
}

int main() {
    atexit(clean_main);
    bool correctInput = true;
    size_t k = 0; // Number of dimensions.
    correctInput = getInputArrays(&startCoordinates, &endCoordinates, &dimensions, &k);

    if (correctInput) {
        size_t dimension = computeDimension(dimensions, k);
        size_t startBit = getBitPosition(startCoordinates, dimensions, k);
        size_t endBit = getBitPosition(endCoordinates, dimensions, k);
        size_t size = 0;
        bool error = false;
        int *binaryVisited = NULL;

        if (isHexInput()) {
            hexVisited = getHexArray(&error, &size, dimension);
            if (error) exit(1);
            binaryVisited = convertHexToBinary(hexVisited, dimension, size);
        } else {
            RArray = getRArray(&error);
            if (error) exit(1);
            binaryVisited = convertRToBinary(RArray, &size, dimension);
        }
        
        Labyrinth *labyrinth = getLabyrinth(startBit, endBit, k, binaryVisited);
        correctInput = correctInput && !error && isInputCorrect(labyrinth) && noNextLine();
        if (correctInput) solveLabyrinth(labyrinth, dimensions);

        free(binaryVisited);
        free(labyrinth);
    }
    return !correctInput;
}
