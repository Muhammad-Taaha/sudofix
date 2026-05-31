#include "info_leak.h"
#include <cstring>
#include <ctime>

struct LogRecord {
    int level;
    char message[64];
    time_t timestamp;
};

void logVulnerableEntry(FILE* logfile, int level, const char* msg) {
    char working_buffer[100];
    std::memcpy(working_buffer, "Processing: LogRecord entry", 28);
    LogRecord rec;
    rec.level = level;
    std::strncpy(rec.message, msg, sizeof(rec.message)-1);
    rec.message[sizeof(rec.message)-1] = '\0';
    rec.timestamp = std::time(nullptr);
    fwrite(&rec, sizeof(rec), 1, logfile);
}