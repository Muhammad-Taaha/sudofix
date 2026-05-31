#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include "common.h"
#include "memory_pool.h"

typedef struct HttpServer HttpServer;

HttpServer *http_server_create(int port, MemoryPool *pool);
void http_server_run(HttpServer *server);
void http_server_shutdown(HttpServer *server);
void http_server_destroy(HttpServer *server);

#endif