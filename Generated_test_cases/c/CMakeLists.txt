cmake_minimum_required(VERSION 3.14)
project(DeepVulnerableEngineC LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(cjson
  GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
  GIT_TAG v1.7.16
)
FetchContent_MakeAvailable(cjson)

add_executable(DeepVulnerableEngineC
  src/main.c
  src/config_reader.c
  src/thread_pool.c
  src/logger.c
  src/http_server.c
  src/memory_pool.c
  src/job_queue.c
  src/directory_cleaner.c
  src/pipeline.c
  src/resource_handler.c
  src/info_leak.c
)

target_include_directories(DeepVulnerableEngineC PRIVATE src)
target_link_libraries(DeepVulnerableEngineC PRIVATE cjson)

if(UNIX)
  target_link_libraries(DeepVulnerableEngineC PRIVATE pthread)
endif()