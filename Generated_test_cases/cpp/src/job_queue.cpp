#include "job_queue.h"
#include <iostream>

void JobManager::addData(const std::string& data) {
    dataChunks.push_back(data);
}

void JobManager::scheduleCleanup(size_t index) {
#if VULN_ON
    // VULN-2: lambda captures raw pointer into vector; invalid after reallocation
    cleanupCallbacks.push_back([this, index]() {
        cleanupChunk(&dataChunks[index]);
    });
#else
    // FIX-2: capture shared_ptr to keep string alive independently of vector
    auto sp = std::make_shared<std::string>(dataChunks.at(index));
    cleanupCallbacks.push_back([this, sp]() {
        cleanupChunk(sp.get());
    });
#endif
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