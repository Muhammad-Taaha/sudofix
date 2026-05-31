#include "pipeline.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void sanitize(const char *cmd, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; cmd[i] && j < out_size-1; i++) {
        if (cmd[i] == ';' || cmd[i] == '|' || cmd[i] == '&')
            continue;
        out[j++] = cmd[i];
    }
    out[j] = '\0';
}

void execute_pipeline(const char *cmd, const char *input, char *output, size_t out_size) {
    char safe_cmd[256];
    sanitize(cmd, safe_cmd, sizeof(safe_cmd));
    if (strlen(safe_cmd) == 0) return;
    FILE *fp = popen(safe_cmd, "r");
    if (!fp) return;
    size_t len = fread(output, 1, out_size-1, fp);
    output[len] = '\0';
    pclose(fp);
}