#include "directory_cleaner.h"
#include <filesystem>

void recursiveDelete(const std::string& dirPath) {
    std::filesystem::path path(dirPath);
    if (!std::filesystem::exists(path)) return;
    for (const auto& entry : std::filesystem::directory_iterator(path)) {
        if (entry.is_directory()) {
            recursiveDelete(entry.path().string());
        } else {
            std::filesystem::remove(entry.path());
        }
    }
    std::filesystem::remove(path);
}