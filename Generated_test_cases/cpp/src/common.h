#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <iostream>
#include <cstring>
#include <fstream>
#include <mutex>
#include <atomic>
#include <thread>
#include <chrono>
#include <regex>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>

#ifdef USE_VULNERABLE
#define VULN_ON 1
#else
#define VULN_ON 0
#endif