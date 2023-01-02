#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <semaphore.h>
#include "utils.h"
#include "err.h"

#define READ 0
#define WRITE 1
#define PRINT_COMMAND(text, pid) if (debug) {printf("Pid: %d executed: %s\n", pid ,text); }
#define MAX_N_TASKS 4096
#define MAX_LINE_LENGTH 1024
#define MAX_COMMAND_LENGTH 512

struct Task {
    char last_err[MAX_LINE_LENGTH];
    char last_out[MAX_LINE_LENGTH];
    int status;
    pid_t pid;
    sem_t mutex_err;
    sem_t mutex_out;
};

struct SharedStorage {
    struct Task tasks[MAX_N_TASKS];
    int task_id_stack[MAX_N_TASKS];
    int stack_top;
    int next_task_id;
    bool command;
    sem_t mutex;
    sem_t block;
};

const unsigned int NAP_MILISECS = 1000;
bool debug = false;

// Auxiliary function to print exit status of a process.
void print_exit_status(int status, int my_task_id) {
    if (WIFEXITED(status)) {
        printf("Task %d ended: status %d.\n", my_task_id, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("Task %d ended: signalled.\n", my_task_id);
    }
}

pid_t run(char **args, struct SharedStorage *storage) {
    pid_t wrapper = fork();
    if (wrapper != 0) return wrapper;

    int child_stdout[2];
    int child_stderr[2];
    pid_t pid;

    ASSERT_SYS_OK(pipe(child_stdout));
    ASSERT_SYS_OK(pipe(child_stderr));

    pid = fork();
    ASSERT_SYS_OK(pid);

    if (pid == 0) {
        // Close the read end of the stdout pipe and
        // connect the write end of the stdout pipe to stdout.
        ASSERT_SYS_OK(close(child_stdout[READ]));
        ASSERT_SYS_OK(dup2(child_stdout[WRITE], STDOUT_FILENO));

        // Close the read end of the stderr pipe and
        // connect the write end of the stderr pipe to stderr.
        ASSERT_SYS_OK(close(child_stderr[READ]));
        ASSERT_SYS_OK(dup2(child_stderr[WRITE], STDERR_FILENO));

        // Close the write ends of the pipes
        ASSERT_SYS_OK(close(child_stdout[WRITE]));
        ASSERT_SYS_OK(close(child_stderr[WRITE]));

        // Execute the program
        execv(args[0], args);
        fprintf(stderr, "execv failed\n");
        _exit(EXIT_FAILURE);
    } else {
        // Initialize the task
        pid_t my_pid = pid;
        int my_task_id = storage->next_task_id++;
        storage->tasks[my_task_id].pid = my_pid;

        // Close the write ends of the pipes
        ASSERT_SYS_OK(close(child_stdout[WRITE]));
        ASSERT_SYS_OK(close(child_stderr[WRITE]));

        // Create a helper process to read from the stdout pipe
        if (fork() == 0) {
            // This is the helper process for stdout
            // Close the read end of the stdout pipe
            ASSERT_SYS_OK(close(child_stderr[READ]));
            char buffer[MAX_LINE_LENGTH];
            FILE *file = fdopen(child_stdout[READ], "r");
            while (read_line(buffer, sizeof(buffer) - 1, file)) {
                // Wait for the semaphore, someone is reading the output
                sem_wait(&storage->tasks[my_task_id].mutex_out);
                // Copy the data to shared memory
                strcpy(storage->tasks[my_task_id].last_out, buffer);
                // Post the semaphore
                sem_post(&storage->tasks[my_task_id].mutex_out);
            }
            // Close the read end of the stdout pipe
            ASSERT_SYS_OK(close(child_stdout[READ]));
            _exit(EXIT_SUCCESS);
        }

        // Same for stderr...
        if (fork() == 0) {
            ASSERT_SYS_OK(close(child_stdout[READ]));
            char buffer[MAX_LINE_LENGTH];
            FILE *file = fdopen(child_stderr[READ], "r");
            while (read_line(buffer, sizeof(buffer) - 1, file)) {
                sem_wait(&storage->tasks[my_task_id].mutex_err);
                strcpy(storage->tasks[my_task_id].last_err, buffer);
                sem_post(&storage->tasks[my_task_id].mutex_err);
            }
            ASSERT_SYS_OK(close(child_stderr[READ]));
            _exit(EXIT_SUCCESS);
        }

        // Releasing the block for the main process
        sem_post(&storage->block);
        // Wait for the child process to finish
        ASSERT_SYS_OK(waitpid(pid, &storage->tasks[my_task_id].status, 0));

        sem_wait(&storage->mutex);
        if (!storage->command) {
            // If the command was not executed, print the exit status
            print_exit_status(storage->tasks[my_task_id].status, my_task_id);
        } else {
            // If the command was executed, save the exit status for later
            push(storage->task_id_stack, &storage->stack_top, my_task_id);
        }
        sem_post(&storage->mutex);

        // Close the read ends of the pipes
        ASSERT_SYS_OK(close(child_stdout[READ]));
        ASSERT_SYS_OK(close(child_stderr[READ]));
    }

    // Wrapper process exits
    _exit(EXIT_SUCCESS);
}

void out(struct SharedStorage *storage, int task_id) {
    // Wait for the semaphore, someone is writing to the last_out
    sem_wait(&storage->tasks[task_id].mutex_out);
    printf("Task %d stdout: '%s'.\n", task_id, storage->tasks[task_id].last_out);
    sem_post(&storage->tasks[task_id].mutex_out);
}

void err(struct SharedStorage *storage, int task_id) {
    // Wait for the semaphore, someone is writing to the last_err
    sem_wait(&storage->tasks[task_id].mutex_err);
    printf("Task %d stderr: '%s'.\n", task_id, storage->tasks[task_id].last_err);
    sem_post(&storage->tasks[task_id].mutex_err);
}

void kill_task(struct SharedStorage *storage, int task_id) {
    kill(storage->tasks[task_id].pid, SIGKILL);
}

void sleep_executor(int seconds) {
    usleep(NAP_MILISECS * seconds);
}

void init_shared_storage(struct SharedStorage *storage) {
    storage->next_task_id = 0;
    storage->stack_top = -1;
    storage->command = false;
    sem_init(&storage->mutex, 1, 1);
    sem_init(&storage->block, 1, 1);
    for (int i = 0; i < MAX_N_TASKS; i++) {
        sem_init(&storage->tasks[i].mutex_out, 1, 1);
        sem_init(&storage->tasks[i].mutex_err, 1, 1);
    }
}

void clear_shared_storage(struct SharedStorage *storage) {
    sem_destroy(&storage->mutex);
    sem_destroy(&storage->block);
    for (int i = 0; i < MAX_N_TASKS; i++) {
        sem_destroy(&storage->tasks[i].mutex_out);
        sem_destroy(&storage->tasks[i].mutex_err);
    }
}

void change_command_status(struct SharedStorage *storage, bool command) {
    sem_wait(&storage->mutex);
    storage->command = command;
    sem_post(&storage->mutex);
}

int main() {
    char buffer[MAX_COMMAND_LENGTH];

    // Initialize the shared storage.
    struct SharedStorage *shared_storage = mmap(
            NULL,
            sizeof(struct SharedStorage),
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS,
            -1,
            0);
    if (shared_storage == MAP_FAILED) {
        syserr("mmap");
    }
    init_shared_storage(shared_storage);

    int programs = 0;
    bool quit = false;

    while (read_line(buffer, MAX_COMMAND_LENGTH, stdin) && !quit) {
        char **parts = split_string(buffer);

        if (is_empty(parts)) {
            free_split_string(parts);
            continue;
        }

        PRINT_COMMAND(parts[0], getpid())
        change_command_status(shared_storage, true);
        sem_wait(&shared_storage->block);
        // Command navigation.
        if (strcmp(parts[0], "run") == 0) {
            int my_task_id = shared_storage->next_task_id;

            run(&parts[1], shared_storage);
            sem_wait(&shared_storage->block);
            printf("Task %d started: pid %d.\n", my_task_id, shared_storage->tasks[my_task_id].pid);
            programs++;
        } else if (strcmp(parts[0], "out") == 0) {
            out(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "err") == 0) {
            err(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "sleep") == 0) {
            sleep_executor(atoi(parts[1]));
        } else if (strcmp(parts[0], "kill") == 0) {
            kill_task(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "quit") == 0) {
            for (int i = 0; i < programs; i++) {
                kill_task(shared_storage, i);
            }
            quit = true;
        }

        // Inform processes that the command has finished.
        change_command_status(shared_storage, false);
        sem_post(&shared_storage->block);

        // Printing the exit statuses of the tasks that finished
        // during the execution of the last command.
        while (!is_empty_stack(&shared_storage->stack_top)) {
            int task_id = pop(shared_storage->task_id_stack, &shared_storage->stack_top);
            print_exit_status(shared_storage->tasks[task_id].status, task_id);
        }

        free_split_string(parts);
    }

    for (int i = 0; i < programs; i++) {
        ASSERT_SYS_OK(wait(NULL));
    }
    clear_shared_storage(shared_storage);

    return 0;
}