#include "pipeline.h"
#include <cstdio>
#include <array>
#include <memory>

static std::string sanitize(const std::string& cmd) {
    std::string result = cmd;
    std::string::size_type pos = 0;
    while ((pos = result.find_first_of(";|&")) != std::string::npos) {
        result.erase(pos, 1);
    }
    return result;
}

std::string executePipeline(const std::string& cmd, const std::string& input) {
    std::string sanitized = sanitize(cmd);
    if (sanitized.empty()) return "";
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(sanitized.c_str(), "r"), pclose);
    if (!pipe) return "";
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}