#ifndef LOGGER_H
#define LOGGER_H

#include "common.h"

typedef struct Logger Logger;

Logger *logger_create(const char *filename, size_t max_size);
void logger_log(Logger *log, const char *msg);
void logger_destroy(Logger *log);

#endif