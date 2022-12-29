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
#define DEBUG if (debug)
#define PRINT_COMMAND(text, pid) if (command) {printf("Pid: %d executed: %s\n", pid ,text); }
#define MAX_N_TASKS 4096
#define MAX_LINE_LENGTH 1024
#define MAX_COMMAND_LENGTH 512

struct Task {
    char last_err[MAX_LINE_LENGTH];
    char last_out[MAX_LINE_LENGTH];
    pid_t pid;
    sem_t mutex_err;
    sem_t mutex_out;
};

struct SharedStorage {
    struct Task tasks[MAX_N_TASKS];
    sem_t mutex;
    int next_task_id;
};

const unsigned int NAP_MILISECS = 1000;
bool debug = false;
bool command = false;

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
        ASSERT_SYS_OK(execv(args[0], args));
        fprintf(stderr, "execv failed");
        exit(EXIT_FAILURE);
    } else {
        // This is the parent process
        pid_t my_pid = pid;
        int my_task_id = storage->next_task_id++;

        // Initialize the task
        storage->tasks[my_task_id].pid = my_pid;
        printf("Task %d started: pid %d.\n", my_task_id, my_pid);

        // Close the write end of the stdout pipe
        ASSERT_SYS_OK(close(child_stdout[WRITE]));
        // Create a helper process to read from the stdout pipe
        if (fork() == 0) {
            // This is the helper process for stdout
            char buffer[MAX_LINE_LENGTH];
            ssize_t n_read;
            while ((n_read = read(child_stdout[READ], buffer, sizeof(buffer) - 1)) > 0) {
                // Wait for the semaphore, someone is reading the output
                sem_wait(&storage->tasks[my_task_id].mutex_out);
                // Copy the data to shared memory
                strncpy(storage->tasks[my_task_id].last_out, buffer, n_read);
                storage->tasks[my_task_id].last_out[n_read - 1] = '\0';
                // Post the semaphore
                sem_post(&storage->tasks[my_task_id].mutex_out);

                DEBUG printf("stdout: %.*s", (int) n_read, buffer);
            }
            // Close the read end of the stdout pipe
            ASSERT_SYS_OK(close(child_stdout[READ]));
            exit(EXIT_SUCCESS);
        }

        // Same for stderr, so I won't comment it
        ASSERT_SYS_OK(close(child_stderr[WRITE]));
        if (fork() == 0) {
            char buffer[MAX_LINE_LENGTH];
            ssize_t n_read;
            while ((n_read = read(child_stderr[READ], buffer, sizeof(buffer) - 1)) > 0) {
                sem_wait(&storage->tasks[my_task_id].mutex_err);
                strncpy(storage->tasks[my_task_id].last_err, buffer, n_read);
                storage->tasks[my_task_id].last_err[n_read - 1] = '\0';
                sem_post(&storage->tasks[my_task_id].mutex_err);

                DEBUG printf("stderr: %.*s", (int) n_read, buffer);
            }
            ASSERT_SYS_OK(close(child_stderr[READ]));
            exit(EXIT_SUCCESS);
        }

        // Wait for the child process to finish
        int status;
        ASSERT_SYS_OK(waitpid(pid, &status, 0));

        if (WIFEXITED(status)) {
            printf("Task %d ended: status %d.\n", my_task_id, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Task %d ended: signalled.\n", my_task_id);
        }

        // Close the read ends of the pipes
        ASSERT_SYS_OK(close(child_stdout[READ]));
        ASSERT_SYS_OK(close(child_stderr[READ]));
    }

    // Wrapper process exits
    exit(EXIT_SUCCESS);
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
    // Kill the process
    kill(storage->tasks[task_id].pid, SIGKILL);
}

void sleep_seconds(int seconds) {
    usleep(NAP_MILISECS * seconds);
}

void init_shared_storage(struct SharedStorage *storage) {
    storage->next_task_id = 0;
    sem_init(&storage->mutex, 1, 1);
    for (int i = 0; i < MAX_N_TASKS; i++) {
        sem_init(&storage->tasks[i].mutex_out, 1, 1);
        sem_init(&storage->tasks[i].mutex_err, 1, 1);
    }
}

void clear_shared_storage(struct SharedStorage *storage) {
    sem_destroy(&storage->mutex);
    for (int i = 0; i < MAX_N_TASKS; i++) {
        sem_destroy(&storage->tasks[i].mutex_out);
        sem_destroy(&storage->tasks[i].mutex_err);
    }
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

    int line = 0, programs = 0;
    while (read_line(buffer, MAX_COMMAND_LENGTH, stdin)) {
        char **parts = split_string(buffer);

        if (is_empty(parts)) {
            DEBUG fprintf(stderr, "Omitting empty command: %d\n", line++);
            free_split_string(parts);
            continue;
        }
        DEBUG print_buffer(parts);

        // Command navigation.
        if (strcmp(parts[0], "run") == 0) {
            PRINT_COMMAND("run", getpid())
            run(&parts[1], shared_storage);
            programs++;
        } else if (strcmp(parts[0], "out") == 0) {
            PRINT_COMMAND("out", getpid())
            out(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "err") == 0) {
            PRINT_COMMAND("err", getpid())
            err(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "sleep") == 0) {
            PRINT_COMMAND("sleep", getpid())
            sleep_seconds(atoi(parts[1]));
        } else if (strcmp(parts[0], "kill") == 0) {
            PRINT_COMMAND("kill", getpid())
            kill_task(shared_storage, atoi(parts[1]));
        } else if (strcmp(parts[0], "quit") == 0) {
            PRINT_COMMAND("quit", getpid())
            free_split_string(parts);
            break;
        }

        free_split_string(parts);
        line++;
    }

    for (int i = 0; i < programs; i++) {
        ASSERT_SYS_OK(wait(NULL));
    }
    clear_shared_storage(shared_storage);

    return 0;
}