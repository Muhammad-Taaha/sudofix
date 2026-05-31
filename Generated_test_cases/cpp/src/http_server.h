#pragma once
#include "common.h"
#include <asio.hpp>
#include <atomic>

class MemoryPool;

class HttpServer {
public:
    HttpServer(asio::io_context& io, unsigned short port, MemoryPool* pool);
    void run();
    void shutdown();
private:
    asio::ip::tcp::acceptor acceptor_;
    MemoryPool* pool_;
    std::atomic<bool> running_{true};
};