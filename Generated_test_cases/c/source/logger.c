#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct Logger {
    FILE *file;
    char filename[256];
    size_t max_size;
    size_t current_size;
    pthread_mutex_t mutex;
};

Logger *logger_create(const char *filename, size_t max_size) {
    Logger *log = malloc(sizeof(Logger));
    if (!log) return NULL;
    strncpy(log->filename, filename, sizeof(log->filename)-1);
    log->max_size = max_size;
    log->file = fopen(filename, "a");
    log->current_size = 0;
    if (log->file) {
        fseek(log->file, 0, SEEK_END);
        log->current_size = ftell(log->file);
    }
    pthread_mutex_init(&log->mutex, NULL);
    return log;
}

void logger_log(Logger *log, const char *msg) {
    pthread_mutex_lock(&log->mutex);
    if (!log->file) { pthread_mutex_unlock(&log->mutex); return; }
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(log->file, "%s %s\n", timestamp, msg);
    fflush(log->file);
    log->current_size = ftell(log->file);
    if (log->current_size >= log->max_size) {
        fclose(log->file);
        char backup[512];
        snprintf(backup, sizeof(backup), "%s.old", log->filename);
        rename(log->filename, backup);
        log->file = fopen(log->filename, "a");
        log->current_size = 0;
    }
    pthread_mutex_unlock(&log->mutex);
}

void logger_destroy(Logger *log) {
    if (log->file) fclose(log->file);
    pthread_mutex_destroy(&log->mutex);
    free(log);
}