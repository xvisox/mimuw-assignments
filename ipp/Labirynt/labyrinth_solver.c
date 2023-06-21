#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include "labyrinth_utility.h"
#include "labyrinth_solver.h"
#include "queue.h"
#include "bit_operations.h"
#include "error_handle.h"

// Breadth-first search algorithm for finding path to the end.
static size_t bfs(Labyrinth *labyrinth, size_t *dimensions, bool *pathFound) {
    Queue currentQueue, nextQueue;
    init(&currentQueue);
    init(&nextQueue);
    size_t neighSize, length, currentNode, resultLength, *neighbours;
    length = resultLength = 0;
    push(&currentQueue, labyrinth->start);

    while ((!empty(currentQueue) || !empty(nextQueue)) && !(*pathFound)) {
        while (!empty(currentQueue)) {
            currentNode = pop(&currentQueue);
            if (!CheckBit(labyrinth->visited, currentNode)) {
                if (currentNode == labyrinth->end) {
                    resultLength = length;
                    *pathFound = true;
                } else {
                    SetBit(labyrinth->visited, currentNode);
                    neighbours = getNeighbours(currentNode, labyrinth->k, dimensions, &neighSize);
                    for (size_t i = 0; i < neighSize; i++) {
                        if (!CheckBit(labyrinth->visited, neighbours[i])) {
                            push(&nextQueue, neighbours[i]);
                        }
                    }
                    free(neighbours);
                }
            }
        }
        length++;
        copyQueue(&nextQueue, &currentQueue);
    }
    if (!empty(currentQueue))
        clearQueue(&currentQueue);
    if (!empty(nextQueue))
        clearQueue(&nextQueue);
    return resultLength;
}

static void printSolution(bool pathFound, size_t length) {
    pathFound ? printf("%lu\n", length) : printf("NO WAY\n");
}

// Finds the shortest path from start to end unless it doesn't exist. 
extern void solveLabyrinth(Labyrinth *labyrinth, size_t *dimensions) {
    bool pathFound = false;
    size_t length = 0;

    if (labyrinth->start == labyrinth->end) {
        length = 0;
        pathFound = true;
    } else {
        length = bfs(labyrinth, dimensions, &pathFound);
    }
    printSolution(pathFound, length);
}
