#include "job_queue.h"
#include <stdlib.h>
#include <string.h>

typedef struct CleanupCallback {
    void (*cb)(void*);
    void *arg;
} CleanupCallback;

struct JobManager {
    char **data;
    size_t count;
    size_t capacity;
    CleanupCallback *callbacks;
    size_t cb_count;
};

JobManager *jm_create(void) {
    JobManager *jm = calloc(1, sizeof(JobManager));
    return jm;
}

static void cleanup_chunk(const char *chunk) {
    if (chunk) {
        printf("Cleaning chunk: %s\n", chunk);
        free((void*)chunk);
    }
}

void jm_add_data(JobManager *jm, const char *data) {
    if (jm->count >= jm->capacity) {
        size_t new_cap = jm->capacity ? jm->capacity * 2 : 8;
        char **new_data = realloc(jm->data, new_cap * sizeof(char*));
        if (!new_data) return;
        jm->data = new_data;
        jm->capacity = new_cap;
    }
    jm->data[jm->count] = strdup(data);
    jm->count++;
}

void jm_schedule_cleanup(JobManager *jm, size_t index) {
    if (index >= jm->count) return;
    jm->callbacks = realloc(jm->callbacks, (jm->cb_count + 1) * sizeof(CleanupCallback));
    jm->callbacks[jm->cb_count].cb = (void(*)(void*))cleanup_chunk;
    jm->callbacks[jm->cb_count].arg = (void*)jm->data[index]; /* dangling pointer later */
    jm->cb_count++;
}

void jm_run_cleanup(JobManager *jm) {
    for (size_t i = 0; i < jm->cb_count; i++) {
        jm->callbacks[i].cb(jm->callbacks[i].arg);
    }
}

size_t jm_data_count(JobManager *jm) {
    return jm->count;
}

void jm_destroy(JobManager *jm) {
    for (size_t i = 0; i < jm->count; i++) free(jm->data[i]);
    free(jm->data);
    free(jm->callbacks);
    free(jm);
}