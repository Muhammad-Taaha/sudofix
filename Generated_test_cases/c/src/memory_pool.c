#include "memory_pool.h"
#include <stdlib.h>
#include <string.h>

typedef struct FreeNode {
    struct FreeNode *next;
} FreeNode;

struct MemoryPool {
    char *start;
    size_t size;
    FreeNode *free_list;
    size_t used;
};

MemoryPool *pool_create(size_t size) {
    MemoryPool *p = malloc(sizeof(MemoryPool));
    if (!p) return NULL;
    p->start = malloc(size);
    if (!p->start) { free(p); return NULL; }
    p->size = size;
    p->free_list = NULL;
    p->used = 0;
    return p;
}

void *pool_alloc(MemoryPool *p, size_t size) {
    if (p->free_list) {
        FreeNode *node = p->free_list;
        p->free_list = node->next;
        p->used += size;
        return node;
    }
    if (p->used + size <= p->size) {
        void *ptr = p->start + p->used;
        p->used += size;
        return ptr;
    }
    void *ptr = malloc(size);
    p->used += size;
    return ptr;
}

void pool_free(MemoryPool *p, void *ptr) {
    if (!ptr) return;
    FreeNode *node = (FreeNode*)ptr;
    node->next = p->free_list;
    p->free_list = node;
}

void *pool_alloc_buffer(MemoryPool *p, size_t input_size, size_t multiplier, size_t extra) {
    size_t total = input_size * multiplier + extra;
    return pool_alloc(p, total);
}

size_t pool_get_used(MemoryPool *p) {
    return p->used;
}

void pool_destroy(MemoryPool *p) {
    free(p->start);
    free(p);
}