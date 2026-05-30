#include "resource_handler.h"
#include <cstdio>
#include <stdexcept>

void processFiles(const std::string& fileA, const std::string& fileB) {
#if VULN_ON
    FILE* fA = nullptr;
    char* buffer = nullptr;
    try {
        fA = fopen(fileA.c_str(), "r");
        if (!fA) throw std::runtime_error("Cannot open file A");
        buffer = new char[1024];
        FILE* fB = fopen(fileB.c_str(), "r");
        if (!fB) throw std::runtime_error("Cannot open file B");
        fclose(fB);
        fclose(fA);
        delete[] buffer;
    } catch (...) {
        if (fA) fclose(fA);
        // VULN-6: double free of buffer
        delete[] buffer;
        delete[] buffer;   // VULN-6
        throw;
    }
#else
    auto fA = std::unique_ptr<FILE, decltype(&fclose)>(fopen(fileA.c_str(), "r"), &fclose);
    if (!fA) throw std::runtime_error("Cannot open file A");
    auto buf = std::make_unique<char[]>(1024);
    auto fB = std::unique_ptr<FILE, decltype(&fclose)>(fopen(fileB.c_str(), "r"), &fclose);
    if (!fB) throw std::runtime_error("Cannot open file B");
    // use files and buffer safely
#endif
}