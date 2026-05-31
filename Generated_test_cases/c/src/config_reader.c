#include "config_reader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (!data) { fclose(f); return NULL; }
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);
    return data;
}

AppConfig read_config(const char *path) {
    AppConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    char *json_str = read_file(path);
    if (!json_str) {
        fprintf(stderr, "Cannot read config file\n");
        return cfg;
    }
    cJSON *root = cJSON_Parse(json_str);
    free(json_str);
    if (!root) return cfg;

    cJSON *port = cJSON_GetObjectItem(root, "port");
    if (cJSON_IsNumber(port)) cfg.port = port->valueint;

    cJSON *log = cJSON_GetObjectItem(root, "log_file");
    if (cJSON_IsString(log)) strncpy(cfg.log_file, log->valuestring, sizeof(cfg.log_file)-1);

    cJSON *psize = cJSON_GetObjectItem(root, "pool_size");
    if (cJSON_IsNumber(psize)) cfg.pool_size = (size_t)psize->valuedouble;

    cJSON *jobs = cJSON_GetObjectItem(root, "jobs");
    if (cJSON_IsArray(jobs)) {
        cfg.jobs_count = cJSON_GetArraySize(jobs);
        cfg.jobs = calloc(cfg.jobs_count, sizeof(JobConfig));
        for (int i = 0; i < cfg.jobs_count; i++) {
            cJSON *job = cJSON_GetArrayItem(jobs, i);
            if (!job) continue;
            JobConfig *jc = &cfg.jobs[i];
            cJSON *type = cJSON_GetObjectItem(job, "type");
            if (cJSON_IsString(type)) strncpy(jc->type, type->valuestring, sizeof(jc->type)-1);
            cJSON *pattern = cJSON_GetObjectItem(job, "pattern");
            if (cJSON_IsString(pattern)) strncpy(jc->pattern, pattern->valuestring, sizeof(jc->pattern)-1);
            cJSON *mult = cJSON_GetObjectItem(job, "multiplier");
            if (cJSON_IsNumber(mult)) jc->multiplier = (size_t)mult->valuedouble;
            cJSON *dir = cJSON_GetObjectItem(job, "dir");
            if (cJSON_IsString(dir)) strncpy(jc->dir, dir->valuestring, sizeof(jc->dir)-1);
            cJSON *cmd = cJSON_GetObjectItem(job, "cmd");
            if (cJSON_IsString(cmd)) strncpy(jc->cmd, cmd->valuestring, sizeof(jc->cmd)-1);
            cJSON *f1 = cJSON_GetObjectItem(job, "file1");
            if (cJSON_IsString(f1)) strncpy(jc->file1, f1->valuestring, sizeof(jc->file1)-1);
            cJSON *f2 = cJSON_GetObjectItem(job, "file2");
            if (cJSON_IsString(f2)) strncpy(jc->file2, f2->valuestring, sizeof(jc->file2)-1);
            cJSON *chunks = cJSON_GetObjectItem(job, "data_chunks");
            if (cJSON_IsArray(chunks)) {
                jc->data_chunks_count = cJSON_GetArraySize(chunks);
                jc->data_chunks = calloc(jc->data_chunks_count, sizeof(char*));
                for (int c = 0; c < jc->data_chunks_count; c++) {
                    cJSON *chunk = cJSON_GetArrayItem(chunks, c);
                    if (cJSON_IsString(chunk))
                        jc->data_chunks[c] = strdup(chunk->valuestring);
                }
            }
            cJSON *sc = cJSON_GetObjectItem(job, "schedule_cleanup_at");
            if (cJSON_IsNumber(sc)) jc->schedule_cleanup_at = (size_t)sc->valuedouble;
        }
    }
    cJSON_Delete(root);
    return cfg;
}

void free_config(AppConfig *cfg) {
    for (int i = 0; i < cfg->jobs_count; i++) {
        for (int c = 0; c < cfg->jobs[i].data_chunks_count; c++)
            free(cfg->jobs[i].data_chunks[c]);
        free(cfg->jobs[i].data_chunks);
    }
    free(cfg->jobs);
}