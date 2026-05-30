#include "memory_pool.h"
#include <cstdlib>
#include <cstring>

MemoryPool::MemoryPool(size_t poolSize) : pool_size(poolSize) {
    pool_start = static_cast<char*>(std::malloc(pool_size));
    used_memory = 0;
}

MemoryPool::~MemoryPool() {
    std::free(pool_start);
}

void* MemoryPool::alloc(size_t size) {
#if !VULN_ON
    std::lock_guard<std::mutex> lock(mutex_);
#endif
    if (free_list) {
        FreeNode* node = free_list;
        free_list = node->next;
        used_memory += size;
        return node;
    }
    if (used_memory + size <= pool_size) {
        void* ptr = pool_start + used_memory;
        used_memory += size;
        return ptr;
    }
    void* ptr = std::malloc(size);
    used_memory += size;
    return ptr;
}

void MemoryPool::free(void* ptr) {
    if (!ptr) return;
#if !VULN_ON
    std::lock_guard<std::mutex> lock(mutex_);
#endif
    FreeNode* node = static_cast<FreeNode*>(ptr);
    node->next = free_list;
    free_list = node;
}

void* MemoryPool::allocBuffer(size_t input_size, size_t multiplier, size_t extra) {
    size_t total;
#if VULN_ON
    // VULN-1: integer overflow possible, no bounds check
    total = input_size * multiplier + extra;
#else
    if (multiplier != 0 && input_size > (SIZE_MAX - extra) / multiplier) {
        return nullptr;
    }
    total = input_size * multiplier + extra;
#endif
    return alloc(total);
}

size_t MemoryPool::getUsedMemory() {
#if !VULN_ON
    std::lock_guard<std::mutex> lock(mutex_);
#endif
    return used_memory;
}