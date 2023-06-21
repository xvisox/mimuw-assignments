#ifndef ERROR_HANDLE_H
#define ERROR_HANDLE_H

#define MEMORY_OVERFLOW 0
#define ERROR_FIRST_LINE 1
#define ERROR_SECOND_LINE 2
#define ERROR_THIRD_LINE 3
#define ERROR_FOURTH_LINE 4
#define ERROR_FIFTH_LINE 5

static inline void printError(int line) {
    fprintf(stderr, "ERROR %d\n", line);
}

static inline void checkMemory(bool isError) {
    if (isError) {
        printError(MEMORY_OVERFLOW);
        exit(1);
    }
}

#endif
