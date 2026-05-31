#include "info_leak.h"
#include <string.h>
#include <time.h>

typedef struct {
    int level;
    char message[64];
    time_t timestamp;
} LogRecord;

void log_leaky_entry(FILE *logfile, int level, const char *msg) {
    char work_buf[128];
    strcpy(work_buf, "Stack secret: 12345");
    LogRecord rec;
    rec.level = level;
    strncpy(rec.message, msg, sizeof(rec.message)-1);
    rec.message[sizeof(rec.message)-1] = '\0';
    rec.timestamp = time(NULL);
    fwrite(&rec, sizeof(rec), 1, logfile);
}