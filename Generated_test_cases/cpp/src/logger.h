#pragma once
#include "common.h"
#include <fstream>
#include <mutex>

class Logger {
public:
    explicit Logger(const std::string& filename, size_t maxSize = 1024*1024);
    void log(const std::string& message);
private:
    void rotate();
    std::string filename_;
    size_t maxSize_;
    std::ofstream file_;
    std::mutex mutex_;
    size_t currentSize_ = 0;
};