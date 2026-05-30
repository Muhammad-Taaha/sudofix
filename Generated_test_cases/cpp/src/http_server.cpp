#include "http_server.h"
#include "memory_pool.h"
#include <thread>
#include <sstream>

HttpServer::HttpServer(asio::io_context& io, unsigned short port, MemoryPool* pool)
    : acceptor_(io, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)), pool_(pool) {}

void HttpServer::run() {
    while (running_) {
        asio::ip::tcp::socket socket(acceptor_.get_executor());
        acceptor_.accept(socket);
        std::thread([this, s = std::move(socket)]() mutable {
            try {
                asio::streambuf buf;
                asio::read_until(s, buf, "\r\n\r\n");
                std::istream is(&buf);
                std::string line;
                std::getline(is, line);
                if (line.find("GET /status") == 0) {
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
                    std::ostringstream json;
                    json << "{\"pool_usage\": " << pool_->getUsedMemory() << "}";
                    response += json.str();
                    asio::write(s, asio::buffer(response));
                } else {
                    std::string response = "HTTP/1.1 404 Not Found\r\n\r\n";
                    asio::write(s, asio::buffer(response));
                }
            } catch (...) {}
        }).detach();
    }
}

void HttpServer::shutdown() {
    running_ = false;
    // Unblock accept by making a dummy connection
    try {
        asio::io_context tmp_io;
        asio::ip::tcp::socket s(tmp_io);
        s.connect(acceptor_.local_endpoint());
    } catch (...) {}
}