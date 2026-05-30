#include "directory_cleaner.h"
#include <filesystem>

void recursiveDelete(const std::string& dirPath) {
    std::filesystem::path path(dirPath);
    if (!std::filesystem::exists(path)) return;
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
#if VULN_ON
        // VULN-3: Missing symlink check – follows symlink and deletes target
        if (entry.is_directory()) {
            recursiveDelete(entry.path().string());
        } else {
            std::filesystem::remove(entry.path());
        }
#else
        // FIX-3: Do not follow symlinks; delete only the symlink itself
        if (entry.is_symlink()) {
            std::filesystem::remove(entry.path());
        } else if (entry.is_directory()) {
            recursiveDelete(entry.path().string());
        } else {
            std::filesystem::remove(entry.path());
        }
#endif
    }
    std::filesystem::remove(path);
}