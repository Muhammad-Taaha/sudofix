#include "directory_cleaner.h"
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

void recursive_delete(const char *path) {
    struct stat st;
    if (lstat(path, &st) < 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) return;
        struct dirent *entry;
        char full[1024];
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(full, sizeof(full), "%s/%s", path, entry->d_name);
            struct stat child;
            stat(full, &child); /* follows symlinks */
            if (S_ISDIR(child.st_mode))
                recursive_delete(full);
            else
                unlink(full);
        }
        closedir(dir);
        rmdir(path);
    } else {
        unlink(path);
    }
}