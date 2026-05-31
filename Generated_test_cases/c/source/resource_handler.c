#include "resource_handler.h"
#include <stdio.h>
#include <stdlib.h>

void process_files(const char *fileA, const char *fileB) {
    FILE *fA = NULL;
    char *buffer = NULL;
    fA = fopen(fileA, "r");
    if (!fA) goto error;
    buffer = malloc(1024);
    if (!buffer) goto cleanup_fA;
    FILE *fB = fopen(fileB, "r");
    if (!fB) goto cleanup_all;
    fclose(fB);
    fclose(fA);
    free(buffer);
    return;
cleanup_all:
    free(buffer);
    free(buffer); /* double free */
cleanup_fA:
    if (fA) fclose(fA);
error:
    return;
}