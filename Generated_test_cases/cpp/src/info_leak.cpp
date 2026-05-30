#include "info_leak.h"
#include <cstring>
#include <ctime>

struct LogRecord {
    int level;
    char message[64];
    time_t timestamp;
};

void logVulnerableEntry(FILE* logfile, int level, const char* msg) {
#if VULN_ON
    // VULN-INFO: place known pattern on stack to demonstrate leak
    char dummy[100];
    std::memcpy(dummy, "SECRET_STACK_DATA_LEAK", 22);
#endif
    LogRecord rec;
#if VULN_ON
    // VULN-INFO: Uninitialized padding bytes written to log
    rec.level = level;
    std::strncpy(rec.message, msg, sizeof(rec.message)-1);
    rec.message[sizeof(rec.message)-1] = '\0';
    rec.timestamp = std::time(nullptr);
#else
    // FIX-INFO: Zero-initialize struct to prevent information leak
    std::memset(&rec, 0, sizeof(rec));
    rec.level = level;
    std::strncpy(rec.message, msg, sizeof(rec.message)-1);
    rec.message[sizeof(rec.message)-1] = '\0';
    rec.timestamp = std::time(nullptr);
#endif
    fwrite(&rec, sizeof(rec), 1, logfile);
}