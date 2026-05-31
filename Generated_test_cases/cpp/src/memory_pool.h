#pragma once
#include "common.h"
#include <cstddef>

class MemoryPool {
public:
    explicit MemoryPool(size_t poolSize);
    ~MemoryPool();
    void* alloc(size_t size);
    void free(void* ptr);
    void* allocBuffer(size_t input_size, size_t multiplier, size_t extra);
    size_t getUsedMemory();
private:
    struct FreeNode { FreeNode* next; };
    char* pool_start = nullptr;
    size_t pool_size = 0;
    FreeNode* free_list = nullptr;
    size_t used_memory = 0;
};
