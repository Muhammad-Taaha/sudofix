#ifndef JOB_QUEUE_H
#define JOB_QUEUE_H

#include "common.h"

typedef struct JobManager JobManager;

JobManager *jm_create(void);
void jm_add_data(JobManager *jm, const char *data);
void jm_schedule_cleanup(JobManager *jm, size_t index);
void jm_run_cleanup(JobManager *jm);
size_t jm_data_count(JobManager *jm);
void jm_destroy(JobManager *jm);

#endif