#include "resource_handler.h"
#include <cstdio>
#include <stdexcept>

void processFiles(const std::string& fileA, const std::string& fileB) {
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
        delete[] buffer;
        delete[] buffer;
        throw;
    }
}