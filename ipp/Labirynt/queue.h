#ifndef QUEUE_H
#define QUEUE_H

typedef struct Node {
    size_t val;
    struct Node *next;
} List;

typedef struct listQ {
    List *head, *tail;
} Queue;

bool empty(Queue q);

void init(Queue *q);

void push(Queue *q, size_t x);

size_t pop(Queue *q);

size_t first(Queue q);

void clearQueue(Queue *q);

void copyQueue(Queue *from, Queue *to);

#endif