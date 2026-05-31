#ifndef INFO_LEAK_H
#define INFO_LEAK_H

#include <stdio.h>
void log_leaky_entry(FILE *logfile, int level, const char *msg);

#endif