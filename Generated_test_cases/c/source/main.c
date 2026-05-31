#include "common.h"
#include "config_reader.h"
#include "thread_pool.h"
#include "logger.h"
#include "memory_pool.h"
#include "job_queue.h"
#include "directory_cleaner.h"
#include "pipeline.h"
#include "resource_handler.h"
#include "info_leak.h"
#include "http_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

volatile int running = 1;

typedef struct {
    MemoryPool *pool;
    JobConfig *job;
    Logger *log;
} TransformArg;

typedef struct {
    JobManager *jm;
    JobConfig *job;
} DataManageArg;

typedef struct {
    JobConfig *job;
    Logger *log;
} PipelineArg;

void transform_task(void *arg) {
    TransformArg *a = arg;
    size_t len = strlen(a->job->pattern);
    if (len == 0) len = 1;
    void *buf = pool_alloc_buffer(a->pool, len, a->job->multiplier, 1);
    if (!buf) {
        logger_log(a->log, "Transform allocation failed");
        free(a);
        return;
    }
    char *cbuf = buf;
    for (size_t i = 0; i < a->job->multiplier; i++) {
        memcpy(cbuf + i * len, a->job->pattern, len);
    }
    cbuf[a->job->multiplier * len] = '\0';
    char logmsg[512];
    snprintf(logmsg, sizeof(logmsg), "Transformed: %s", cbuf);
    logger_log(a->log, logmsg);
    pool_free(a->pool, buf);
    free(a);
}

void data_manage_task(void *arg) {
    DataManageArg *a = arg;
    for (int i = 0; i < a->job->data_chunks_count; i++) {
        jm_add_data(a->jm, a->job->data_chunks[i]);
    }
    if (a->job->schedule_cleanup_at < jm_data_count(a->jm)) {
        jm_schedule_cleanup(a->jm, a->job->schedule_cleanup_at);
    }
    for (int i = 0; i < 1000; i++) {
        char pad[64];
        snprintf(pad, sizeof(pad), "padding %d", i);
        jm_add_data(a->jm, pad);
    }
    jm_run_cleanup(a->jm);
    free(a);
}

void cleanup_task(void *arg) {
    JobConfig *job = arg;
    recursive_delete(job->dir);
    free(job);
}

void pipeline_task(void *arg) {
    PipelineArg *a = arg;
    char out[1024] = {0};
    execute_pipeline(a->job->cmd, a->job->pattern, out, sizeof(out));
    char logmsg[1100];
    snprintf(logmsg, sizeof(logmsg), "Pipeline output: %s", out);
    logger_log(a->log, logmsg);
    free(a);
}

void process_files_task(void *arg) {
    JobConfig *job = arg;
    process_files(job->file1, job->file2);
    free(job);
}

void leak_task(void *arg) {
    (void)arg;
    FILE *f = fopen("leak_log.bin", "ab");
    if (f) {
        log_leaky_entry(f, 1, "sensitive data");
        fclose(f);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config.json>\n", argv[0]);
        return 1;
    }
    AppConfig cfg = read_config(argv[1]);
    Logger *log = logger_create(cfg.log_file, 1024*1024);
    MemoryPool *pool = pool_create(cfg.pool_size);
    ThreadPool *tp = thread_pool_create(4);
    JobManager *jm = jm_create();
    HttpServer *hs = http_server_create(cfg.port, pool);
    if (!hs) { fprintf(stderr, "Could not start HTTP server\n"); }

    for (int i = 0; i < cfg.jobs_count; i++) {
        JobConfig *job = &cfg.jobs[i];
        if (strcmp(job->type, "transform") == 0) {
            TransformArg *arg = malloc(sizeof(TransformArg));
            arg->pool = pool; arg->job = job; arg->log = log;
            thread_pool_enqueue(tp, transform_task, arg);
        } else if (strcmp(job->type, "data_manage") == 0) {
            DataManageArg *arg = malloc(sizeof(DataManageArg));
            arg->jm = jm; arg->job = job;
            thread_pool_enqueue(tp, data_manage_task, arg);
        } else if (strcmp(job->type, "cleanup_dir") == 0) {
            JobConfig *jcopy = malloc(sizeof(JobConfig));
            memcpy(jcopy, job, sizeof(JobConfig));
            thread_pool_enqueue(tp, cleanup_task, jcopy);
        } else if (strcmp(job->type, "pipeline") == 0) {
            PipelineArg *arg = malloc(sizeof(PipelineArg));
            arg->job = job; arg->log = log;
            thread_pool_enqueue(tp, pipeline_task, arg);
        } else if (strcmp(job->type, "process_files") == 0) {
            JobConfig *jcopy = malloc(sizeof(JobConfig));
            memcpy(jcopy, job, sizeof(JobConfig));
            thread_pool_enqueue(tp, process_files_task, jcopy);
        } else if (strcmp(job->type, "log_leak") == 0) {
            thread_pool_enqueue(tp, leak_task, NULL);
        }
    }

    if (hs) http_server_run(hs);

    thread_pool_destroy(tp);
    jm_destroy(jm);
    http_server_destroy(hs);
    pool_destroy(pool);
    logger_destroy(log);
    free_config(&cfg);
    return 0;
}