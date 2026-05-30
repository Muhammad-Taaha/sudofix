#include "common.h"
#include "config_reader.h"
#include "thread_pool.h"
#include "logger.h"
#include "memory_pool.h"
#include "job_queue.h"
#include "directory_cleaner.h"
#include "pipeline.h"
#include "resource_handler.h"
#include "info_leak.h"
#include "http_server.h"
#include <asio.hpp>
#include <iostream>
#include <csignal>

std::atomic<bool> running{true};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <config.json>" << std::endl;
        return 1;
    }
    try {
        AppConfig config = readConfig(argv[1]);
        Logger logger(config.log_file);
        MemoryPool memPool(config.pool_size);
        ThreadPool threadPool(4);
        asio::io_context io_context;
        HttpServer httpServer(io_context, config.port, &memPool);
        std::thread httpThread([&]() { httpServer.run(); });

        // Process jobs
        JobManager jobManager;
        for (auto& job : config.jobs) {
            if (job.type == "transform") {
                threadPool.enqueue([&memPool, job, &logger]() {
                    size_t len = job.pattern.length();
                    if (len == 0) len = 1;
                    void* buf = memPool.allocBuffer(len, job.multiplier, 1);
                    if (!buf) {
                        logger.log("Transform allocation failed");
                        return;
                    }
                    char* cbuf = static_cast<char*>(buf);
                    for (size_t i = 0; i < job.multiplier; ++i) {
                        memcpy(cbuf + i * len, job.pattern.data(), len);
                    }
                    cbuf[job.multiplier * len] = '\0';
                    logger.log(std::string("Transformed: ") + cbuf);
                    memPool.free(buf);
                });
            } else if (job.type == "data_manage") {
                threadPool.enqueue([&jobManager, job]() {
                    for (auto& chunk : job.data_chunks) {
                        jobManager.addData(chunk);
                    }
                    if (job.schedule_cleanup_at < jobManager.getDataCount()) {
                        jobManager.scheduleCleanup(job.schedule_cleanup_at);
                    }
                    for (int i = 0; i < 1000; ++i) {
                        jobManager.addData("padding data to cause realloc " + std::to_string(i));
                    }
                    jobManager.runCleanup();
                });
            } else if (job.type == "cleanup_dir") {
                threadPool.enqueue([job]() {
                    recursiveDelete(job.dir);
                });
            } else if (job.type == "pipeline") {
                threadPool.enqueue([job, &logger]() {
                    std::string output = executePipeline(job.cmd, job.pattern);
                    logger.log("Pipeline output: " + output);
                });
            } else if (job.type == "process_files") {
                threadPool.enqueue([job]() {
                    try {
                        processFiles(job.file1, job.file2);
                    } catch (...) {}
                });
            } else if (job.type == "log_leak") {
                threadPool.enqueue([]() {
                    FILE* leakFile = fopen("leak_log.bin", "ab");
                    if (leakFile) {
                        logVulnerableEntry(leakFile, 1, "sensitive data");
                        fclose(leakFile);
                    }
                });
            }
        }

        threadPool.stop();
        httpServer.shutdown();
        httpThread.join();
    } catch (const std::exception& e) {
        std::cerr << "Fatal: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}