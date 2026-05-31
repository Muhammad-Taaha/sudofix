#include "job_queue.h"
#include <iostream>

void JobManager::addData(const std::string& data) {
    dataChunks.push_back(data);
}

void JobManager::scheduleCleanup(size_t index) {
    cleanupCallbacks.push_back([this, index]() {
        cleanupChunk(&dataChunks[index]);
    });
}

void JobManager::runCleanup() {
    for (auto& cb : cleanupCallbacks) {
        cb();
    }
}

void JobManager::cleanupChunk(const std::string* chunk) {
    if (chunk) {
        std::cout << "Cleaning chunk: " << *chunk << std::endl;
    }
}