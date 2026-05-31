#ifndef CONFIG_READER_H
#define CONFIG_READER_H

#include "common.h"
#include <cjson/cJSON.h>

typedef struct {
    char type[64];
    char pattern[256];
    size_t multiplier;
    char dir[256];
    char cmd[256];
    char file1[256];
    char file2[256];
    char **data_chunks;
    int data_chunks_count;
    size_t schedule_cleanup_at;
} JobConfig;

typedef struct {
    int port;
    char log_file[256];
    size_t pool_size;
    int jobs_count;
    JobConfig *jobs;
    char cleanup_dir[256];
    char pipeline_cmd[256];
} AppConfig;

AppConfig read_config(const char *path);
void free_config(AppConfig *cfg);

#endif