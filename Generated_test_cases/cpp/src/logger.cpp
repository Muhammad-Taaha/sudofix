#include "logger.h"
#include <ctime>
#include <iomanip>

Logger::Logger(const std::string& filename, size_t maxSize) 
    : filename_(filename), maxSize_(maxSize) {
    file_.open(filename_, std::ios::app);
    if (file_) {
        file_.seekp(0, std::ios::end);
        currentSize_ = file_.tellp();
    }
}

void Logger::log(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!file_.is_open()) return;
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " " << message << "\n";
    std::string entry = oss.str();
    file_ << entry;
    file_.flush();
    currentSize_ += entry.size();
    if (currentSize_ >= maxSize_) {
        rotate();
    }
}

void Logger::rotate() {
    file_.close();
    std::string backup = filename_ + ".old";
    std::rename(filename_.c_str(), backup.c_str());
    file_.open(filename_, std::ios::app);
    currentSize_ = 0;
}
