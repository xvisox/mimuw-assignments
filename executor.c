#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"

#define MAX_N_TASKS 4096
#define MAX_LINE_LENGTH 1022
#define MAX_COMMAND_LENGTH 511

struct Task {
    char last_err[MAX_LINE_LENGTH];
    char last_out[MAX_LINE_LENGTH];
    int pid;
};

int next_task_id = 0;
struct Task tasks[MAX_N_TASKS];

void run(char **args) {
    int pid = fork();

    if (pid == 0) {
        // FIXME: DEBUG FUNC.
        print_buffer(args);


        execv(args[0], args);
        fprintf(stderr, "Error: exec failed\n");
        exit(0);
    } else {
        tasks[next_task_id++].pid = pid;
    }
}

int main() {
    char buffer[MAX_COMMAND_LENGTH];

    int line = 0;
    while (read_line(buffer, MAX_COMMAND_LENGTH, stdin)) {
        char **parts = split_string(buffer);

        if (is_empty(parts)) {
            // FIXME: DEBUG FUNC.
            fprintf(stderr, "Omitting empty command: %d\n", line++);
            free_split_string(parts);
            continue;
        }
        // FIXME: DEBUG FUNC.
        print_buffer(parts);

        // Command navigation.
        if (strcmp(parts[0], "run") == 0) {
            run(parts + 1);
        }

        // Clearing split buffer parts.
        free_split_string(parts);
        line++;
    }

    return 0;
}