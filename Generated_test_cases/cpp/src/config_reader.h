#pragma once
#include "common.h"
#include <nlohmann/json.hpp>

struct JobConfig {
    std::string type;
    std::string pattern;
    size_t multiplier = 1;
    std::string dir;
    std::string cmd;
    std::string file1;
    std::string file2;
    std::vector<std::string> data_chunks;
    size_t schedule_cleanup_at = 0;
};

struct AppConfig {
    int port = 8080;
    std::string log_file = "engine.log";
    size_t pool_size = 1024*1024;
    std::vector<JobConfig> jobs;
    std::string cleanup_dir;
    std::string pipeline_cmd;
};

AppConfig readConfig(const std::string& path);