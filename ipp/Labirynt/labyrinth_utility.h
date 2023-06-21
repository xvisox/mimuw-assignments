#ifndef LABYRINTH_UTILITY_H
#define LABYRINTH_UTILITY_H

typedef struct Labyrinth {
    size_t start;
    size_t end;
    size_t k;
    int *visited;
} Labyrinth;

size_t getBitPosition(size_t *coordinates, size_t *dimensions, size_t k);

size_t computeDimension(size_t *dimensions, size_t k);

bool isInputCorrect(Labyrinth *labyrinth);

int *convertHexToBinary(char *hexVisited, size_t dimension, size_t n);

int *convertRToBinary(unsigned int *RArray, size_t *n, size_t dimension);

size_t *getNeighbours(size_t start, size_t k, size_t *dimensions, size_t *n);

Labyrinth *getLabyrinth(size_t startBit, size_t endBit, size_t k, int *binaryVisited);

#endif