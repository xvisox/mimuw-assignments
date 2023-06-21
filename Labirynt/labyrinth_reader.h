#ifndef LABYRINTH_READER_H
#define LABYRINTH_READER_H

bool getInputArrays(size_t **start, size_t **end, size_t **dim, size_t *n);

char *getHexArray(bool *error, size_t *length, size_t dimension);

unsigned int *getRArray(bool *error);

bool isHexInput();

bool noNextLine();

#endif