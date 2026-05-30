#include "pipeline.h"
#include <cstdio>
#include <array>
#include <memory>

static std::string sanitize(const std::string& cmd) {
#if VULN_ON
    // VULN-5: Incomplete sanitizer – misses backticks, $(), etc.
    std::string result = cmd;
    std::string::size_type pos = 0;
    while ((pos = result.find_first_of(";|&")) != std::string::npos) {
        result.erase(pos, 1);
    }
    return result;
#else
    // FIX-5: Strict whitelist – only allow safe characters
    for (char c : cmd) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != ' ' && c != '.' && c != '-' && c != '_') {
            return "";
        }
    }
    return cmd;
#endif
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