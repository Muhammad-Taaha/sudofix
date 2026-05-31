#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "common.h"

typedef struct ThreadPool ThreadPool;

ThreadPool *thread_pool_create(int num_threads);
void thread_pool_enqueue(ThreadPool *pool, void (*func)(void*), void *arg);
void thread_pool_destroy(ThreadPool *pool);

#endif