#include "thread_pool.h"
#include <stdlib.h>
#include <pthread.h>

typedef struct Task {
    void (*func)(void*);
    void *arg;
    struct Task *next;
} Task;

struct ThreadPool {
    pthread_t *threads;
    int num_threads;
    Task *head;
    Task *tail;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int stop;
};

static void *worker(void *arg) {
    ThreadPool *pool = (ThreadPool*)arg;
    while (1) {
        pthread_mutex_lock(&pool->mutex);
        while (pool->head == NULL && !pool->stop)
            pthread_cond_wait(&pool->cond, &pool->mutex);
        if (pool->stop && pool->head == NULL) {
            pthread_mutex_unlock(&pool->mutex);
            return NULL;
        }
        Task *task = pool->head;
        pool->head = task->next;
        if (pool->head == NULL) pool->tail = NULL;
        pthread_mutex_unlock(&pool->mutex);
        task->func(task->arg);
        free(task);
    }
}

ThreadPool *thread_pool_create(int num_threads) {
    ThreadPool *pool = malloc(sizeof(ThreadPool));
    if (!pool) return NULL;
    pool->num_threads = num_threads;
    pool->head = pool->tail = NULL;
    pool->stop = 0;
    pthread_mutex_init(&pool->mutex, NULL);
    pthread_cond_init(&pool->cond, NULL);
    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    for (int i = 0; i < num_threads; i++)
        pthread_create(&pool->threads[i], NULL, worker, pool);
    return pool;
}

void thread_pool_enqueue(ThreadPool *pool, void (*func)(void*), void *arg) {
    Task *task = malloc(sizeof(Task));
    task->func = func;
    task->arg = arg;
    task->next = NULL;
    pthread_mutex_lock(&pool->mutex);
    if (pool->tail == NULL) {
        pool->head = pool->tail = task;
    } else {
        pool->tail->next = task;
        pool->tail = task;
    }
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
}

void thread_pool_destroy(ThreadPool *pool) {
    pthread_mutex_lock(&pool->mutex);
    pool->stop = 1;
    pthread_cond_broadcast(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
    for (int i = 0; i < pool->num_threads; i++)
        pthread_join(pool->threads[i], NULL);
    free(pool->threads);
    Task *task = pool->head;
    while (task) {
        Task *next = task->next;
        free(task);
        task = next;
    }
    pthread_mutex_destroy(&pool->mutex);
    pthread_cond_destroy(&pool->cond);
    free(pool);
}