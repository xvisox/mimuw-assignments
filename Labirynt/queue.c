#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "queue.h"
#include "error_handle.h"

extern bool empty(Queue q) {
    return (q.head == NULL);
}

extern void init(Queue *q) {
    q->head = NULL;
}

static void pushNext(size_t x, List *list) {
    List *temp = malloc(sizeof(List));
    checkMemory(temp == NULL);
    temp->val = x;
    list->next = temp;
}

extern void push(Queue *q, size_t x) {
    if (q->head == NULL) {
        q->head = malloc(sizeof(List));
        checkMemory(q->head == NULL);
        q->head->val = x;
        q->tail = q->head;
    } else {
        pushNext(x, q->tail);
        q->tail = q->tail->next;
    }
}

extern size_t pop(Queue *q) {
    List *temp = q->head;
    size_t x = q->head->val;

    if (q->head == q->tail) {
        q->head = NULL;
        q->tail = NULL;
    } else {
        q->head = q->head->next;
    }

    free(temp);
    return x;
}

extern size_t first(Queue q) {
    return q.head->val;
}

extern void clearQueue(Queue *q) {
    while (!empty(*q))
        pop(q);
    q->head = NULL;
    q->tail = NULL;
}

extern void copyQueue(Queue *from, Queue *to) {
    *to = *from;
    from->head = NULL;
    from->tail = NULL;
}
