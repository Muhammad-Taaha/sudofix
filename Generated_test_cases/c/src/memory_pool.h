#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include "common.h"

typedef struct MemoryPool MemoryPool;

MemoryPool *pool_create(size_t size);
void *pool_alloc(MemoryPool *pool, size_t size);
void pool_free(MemoryPool *pool, void *ptr);
void *pool_alloc_buffer(MemoryPool *pool, size_t input_size, size_t multiplier, size_t extra);
size_t pool_get_used(MemoryPool *pool);
void pool_destroy(MemoryPool *pool);

#endif