#pragma once
#include "common.h"
#include <vector>
#include <functional>
#include <string>

class JobManager {
public:
    void addData(const std::string& data);
    void scheduleCleanup(size_t index);
    void runCleanup();
    size_t getDataCount() const { return dataChunks.size(); }
private:
    std::vector<std::string> dataChunks;
    std::vector<std::function<void()>> cleanupCallbacks;
    void cleanupChunk(const std::string* chunk);
};