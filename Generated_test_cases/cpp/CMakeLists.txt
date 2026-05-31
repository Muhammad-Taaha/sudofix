cmake_minimum_required(VERSION 3.14)
project(DeepVulnerableEngine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(json)

FetchContent_Declare(asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-28-0
)
FetchContent_GetProperties(asio)
if(NOT asio_POPULATED)
  FetchContent_Populate(asio)
  add_library(asio INTERFACE)
  target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
  add_library(asio::asio ALIAS asio)
endif()

add_executable(DeepVulnerableEngine
  src/main.cpp
  src/thread_pool.cpp
  src/config_reader.cpp
  src/logger.cpp
  src/http_server.cpp
  src/memory_pool.cpp
  src/job_queue.cpp
  src/directory_cleaner.cpp
  src/pipeline.cpp
  src/resource_handler.cpp
  src/info_leak.cpp
)

target_include_directories(DeepVulnerableEngine PRIVATE src)
target_link_libraries(DeepVulnerableEngine PRIVATE nlohmann_json::nlohmann_json asio::asio)

if(UNIX)
  target_link_libraries(DeepVulnerableEngine PRIVATE pthread)
endif()