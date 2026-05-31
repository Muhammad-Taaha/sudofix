#include "config_reader.h"
#include <fstream>

AppConfig readConfig(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) throw std::runtime_error("Cannot open config");
    nlohmann::json j;
    ifs >> j;
    AppConfig cfg;
    cfg.port = j.value("port", 8080);
    cfg.log_file = j.value("log_file", "engine.log");
    cfg.pool_size = j.value("pool_size", 1024*1024);
    cfg.cleanup_dir = j.value("cleanup_dir", "");
    cfg.pipeline_cmd = j.value("pipeline_cmd", "");
    if (j.contains("jobs")) {
        for (auto& job_json : j["jobs"]) {
            JobConfig job;
            job.type = job_json.value("type", "");
            job.pattern = job_json.value("pattern", "");
            job.multiplier = job_json.value("multiplier", 1);
            job.dir = job_json.value("dir", "");
            job.cmd = job_json.value("cmd", "");
            job.file1 = job_json.value("file1", "");
            job.file2 = job_json.value("file2", "");
            if (job_json.contains("data_chunks")) {
                for (auto& chunk : job_json["data_chunks"]) {
                    job.data_chunks.push_back(chunk.get<std::string>());
                }
            }
            job.schedule_cleanup_at = job_json.value("schedule_cleanup_at", 0);
            cfg.jobs.push_back(job);
        }
    }
    return cfg;
}