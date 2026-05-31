#include "http_server.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct HttpServer {
    int port;
    int sockfd;
    MemoryPool *pool;
    volatile int running;
};

static void *client_handler(void *arg);

HttpServer *http_server_create(int port, MemoryPool *pool) {
    HttpServer *srv = malloc(sizeof(HttpServer));
    if (!srv) return NULL;
    srv->port = port;
    srv->pool = pool;
    srv->running = 1;
    srv->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv->sockfd < 0) { free(srv); return NULL; }
    int opt = 1;
    setsockopt(srv->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(srv->sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(srv->sockfd, 10) < 0) {
        close(srv->sockfd); free(srv); return NULL;
    }
    return srv;
}

void http_server_run(HttpServer *server) {
    while (server->running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client = accept(server->sockfd, (struct sockaddr*)&client_addr, &client_len);
        if (client < 0) continue;
        pthread_t tid;
        int *pclient = malloc(sizeof(int));
        *pclient = client;
        pthread_create(&tid, NULL, client_handler, pclient);
        pthread_detach(tid);
    }
}

static void *client_handler(void *arg) {
    int client = *(int*)arg;
    free(arg);
    char buf[2048];
    read(client, buf, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';
    if (strstr(buf, "GET /status") == buf) {
        char resp[256];
        size_t used = pool_get_used(NULL); /* will be fixed later */
        snprintf(resp, sizeof(resp),
                 "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"pool_usage\": %zu}",
                 used);
        write(client, resp, strlen(resp));
    } else {
        const char *resp = "HTTP/1.1 404 Not Found\r\n\r\n";
        write(client, resp, strlen(resp));
    }
    close(client);
    return NULL;
}

void http_server_shutdown(HttpServer *server) {
    server->running = 0;
    int tmp = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(server->port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(tmp, (struct sockaddr*)&addr, sizeof(addr));
    close(tmp);
}

void http_server_destroy(HttpServer *server) {
    close(server->sockfd);
    free(server);
}