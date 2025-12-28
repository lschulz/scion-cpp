// Copyright (c) 2024-2025 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "console.h"
#include "format.h"
#include "scion/scion.h"

#define OPTPARSE_IMPLEMENTATION
#include "optparse.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#else
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

struct arguments {
    const char* daemon_addr;
    const char* local_addr;
    const char* remote_addr;
    const char* message;
    int count;
    bool interactive;
    bool stun;
    bool quiet;
};

static const char* HELP_MESSAGE = \
    "Usage: echo -local LOCAL -remote REMOTE -msg MESSAGE -count COUNT\n"
    "  LOCAL   Local IP address and port (required for servers)\n"
    "  REMOTE  Scion address of the remote server (only for clients)\n"
    "  MESSAGE The message clients will send to the server\n"
    "  COUNT   Number of messages to send\n"
    "Optional Flags:\n"
    "  -interactive Prompt for path selection (client only)\n"
    "  -stun        Attempt NAT traversal (client only)\n"
    "  -quiet       Don't print addresses and paths";

bool parse_args(int argc, char* argv[], struct arguments* args)
{
    static const struct optparse_long longopts[] = {
        { "help", 'h', OPTPARSE_NONE },
        { "sciond", 'd', OPTPARSE_REQUIRED },
        { "local", 'l', OPTPARSE_REQUIRED },
        { "remote", 'r', OPTPARSE_REQUIRED },
        { "msg", 'm', OPTPARSE_REQUIRED },
        { "count", 'c', OPTPARSE_REQUIRED },
        { "interactive", 'i', OPTPARSE_NONE},
        { "stun", 's', OPTPARSE_NONE},
        { "quiet", 'q', OPTPARSE_NONE},
        { 0 }
    };

    memset(args, 0, sizeof(struct arguments));
    args->count = 1;
    args->message = "Hello!";

    struct optparse options;
    optparse_init(&options, argv);

    int opt = -1;
    while ((opt = optparse_long(&options, longopts, NULL)) != -1) {
        switch (opt)
        {
        case 'd':
            args->daemon_addr = options.optarg;
            break;
        case 'l':
            args->local_addr = options.optarg;
            break;
        case 'r':
            args->remote_addr = options.optarg;
            break;
        case 'm':
            args->message = options.optarg;
            break;
        case 'c':
            args->count = atoi(options.optarg);
            break;
        case 'i':
            args->interactive = true;
            break;
        case 's':
            args->stun = true;
            break;
        case 'q':
            args->quiet = true;
            break;
        case 'h':
        default:
            puts(HELP_MESSAGE);
            return false;
        }
    };

    // Check for mandatory options
    if (!args->local_addr && !args->remote_addr) {
        puts("At least one of local (for servers) and remote (for clients) is required");
        return false;
    }

    if (!args->daemon_addr) {
        args->daemon_addr = getenv("SCION_DAEMON_ADDRESS");
    }

    return true;
}

////////////
// Server //
////////////

struct Server
{
    scion_socket* socket;
    scion_raw_path* path;
    scion_hdr_cache* headers;
    struct sockaddr_scion from;
    struct sockaddr_storage next_hop;
    struct scion_packet pkt;
    char buffer[1024];
    bool quiet;
};

void server_received(scion_error status, void* recvd, size_t n, void* user_ptr);
void server_sent(scion_error err, size_t n, void* user_ptr);

int run_server(struct Server* srv,
    scion_context* ctx, const struct sockaddr_storage* bind, const struct arguments* args)
{
    memset(srv, 0, sizeof(struct Server));

    // Create and bind UDP socket
    scion_error err = scion_socket_create(ctx, &srv->socket, SOCK_DGRAM);
    if (err) {
        printf("Allocating socket failed\n");
        return EXIT_FAILURE;
    }
    err = scion_bind(srv->socket, (const struct sockaddr*)bind, sizeof(*bind));
    if (err) {
        printf("Can't bind to %s (%s:%d)\n", args->local_addr, scion_error_string(err), err);
        return EXIT_FAILURE;
    }

    CON_CURSES(curses_init_server());
    {
        struct sockaddr_scion bound;
        scion_getsockname(srv->socket, &bound);
        char buffer[64];
        size_t buffer_len = sizeof(buffer);
        if (!scion_print_ep(&bound, buffer, &buffer_len))
            console_printf("Server listening at %s\nPress q to quit.\n", buffer);
    }

    // Receive and echo back
    srv->path = scion_raw_path_allocate();
    if (!srv->path) return EXIT_FAILURE;
    srv->headers = scion_hdr_cache_allocate();
    if (!srv->headers) return EXIT_FAILURE;
    srv->pkt.addr = &srv->from;
    srv->pkt.underlay = (struct sockaddr*)&srv->next_hop;
    srv->pkt.underlay_len = sizeof(srv->next_hop);
    SCION_SET_PATH(srv->pkt, srv->path);
    srv->quiet = args->quiet;

    struct scion_async_recv_handler handler = {
        &server_received, srv
    };
    scion_recv_async(srv->socket, srv->buffer, sizeof(srv->buffer), &srv->pkt, handler);
    return EXIT_SUCCESS;
}

void server_cleanup(struct Server* srv)
{
    CON_CURSES(curses_end_server());
    scion_hdr_cache_free(srv->headers);
    scion_raw_path_free(srv->path);
    scion_close(srv->socket);
}

void server_received(scion_error err, void* recvd, size_t n, void* user_ptr)
{
    struct Server* srv = user_ptr;
    if (!recvd) {
        console_printf("Error: %s:%d\n", scion_error_string(err), err);
        return;
    }
    if (!srv->quiet) {
        char str[128];
        size_t str_len = sizeof(str);
        if (!scion_print_ep(&srv->from, str, &str_len))
            console_printf("Received %zu bytes from %s\n", n, str);
        str_len = sizeof(srv->buffer);
        if (!scion_raw_path_print(srv->path, str, &str_len))
            console_printf("Path: %s\n", str);
    }
    if (!scion_raw_path_reverse(srv->path)) {
        struct scion_async_send_handler handler = {
            &server_sent, srv
        };
        scion_send_async(srv->socket, srv->headers, recvd, n, &srv->pkt, handler);
    }
}

void server_sent(scion_error err, size_t n, void* user_ptr)
{
    struct Server* srv = user_ptr;
    if (err) {
        console_printf("Error: %s:%d\n", scion_error_string(err), err);
        return;
    }
    struct scion_async_recv_handler handler = {
        &server_received, srv
    };
    scion_recv_async(srv->socket, srv->buffer, sizeof(srv->buffer), &srv->pkt, handler);
}

////////////
// Client //
////////////

struct Client
{
    scion_timer* timer;
    scion_path* path;
    scion_socket* socket;
    scion_hdr_cache* headers;
    struct sockaddr_scion from;
    struct sockaddr_storage next_hop;
    socklen_t next_hop_len;
    struct scion_packet pkt;
    char buffer[1024];
    const struct arguments* args;
    int i;
};

void client_stun_sent(scion_error err, size_t n, void* user_ptr);
void client_stun_received(scion_error err, void* recvd, size_t n, void* user_ptr);
void client_sent(scion_error err, size_t n, void* user_ptr);
void client_received(scion_error err, void* recvd, size_t n, void* user_ptr);
void client_timeout(scion_error err, void* user_ptr);

int client_init(struct Client* cl,
    scion_context* ctx, const struct sockaddr_storage* bind, const struct arguments* args)
{
    memset(cl, 0, sizeof(struct Client));

    cl->timer = scion_timer_allocate(ctx);
    if (!cl->timer) return EXIT_FAILURE;

    struct sockaddr_scion remote;
    size_t len = sizeof(remote);
    if (scion_resolve_name(ctx, args->remote_addr, &remote, &len)) {
        printf("Can't resolve %s\n", args->remote_addr);
        return EXIT_FAILURE;
    }

    // Get paths to destination AS
    scion_path* paths[32];
    size_t path_count = sizeof(paths) / sizeof(*paths);
    const uint64_t dst_as = scion_ntohll(remote.sscion_addr.sscion_isd_asn);
    scion_error err = scion_query_paths(ctx, dst_as, paths, &path_count);
    if (err != SCION_OK && err != SCION_BUFFER_TOO_SMALL) {
        printf("Error fetching paths (%s:%d)\n", scion_error_string(err), err);
        return EXIT_FAILURE;
    }
    if (err == SCION_BUFFER_TOO_SMALL) {
        path_count = sizeof(paths) / sizeof(*paths);
    }
    if (path_count == 0) {
        char buffer[128] = {0};
        size_t len = sizeof(buffer);
        err = scion_print_ep(&remote, buffer, &len);
        if (err == SCION_OK || err == SCION_BUFFER_TOO_SMALL) {
            printf("No path to %s\n", buffer);
        }
        return EXIT_FAILURE;
    }

    // Select one path
    size_t selection = 0;
    if (args->interactive) {
        char buffer[128] = {0};
        for (size_t i = 0; i < path_count; ++i) {
            size_t len = sizeof(buffer);
            err = scion_path_print(paths[i], buffer, &len);
            if (err == SCION_OK || err == SCION_BUFFER_TOO_SMALL) {
                printf("[%2zu] %s\n", i, buffer);
            }
        }
        while (true) {
            printf("Choose path: ");
            if (scanf("%zu", &selection) == 1 && selection < path_count) {
                break;
            }
        }
    } else {
        selection = (size_t)rand() % path_count;
    }
    cl->path = paths[selection];
    paths[selection] = NULL;
    scion_release_paths(paths, path_count); // release paths we didn't choose

    cl->next_hop_len = sizeof(cl->next_hop);
    err = scion_path_next_hop(cl->path, (struct sockaddr*)&cl->next_hop, &cl->next_hop_len);
    if (err == SCION_PATH_IS_EMPTY) {
        if (scion_sockaddr_get_host(&remote, (struct sockaddr*)&cl->next_hop, cl->next_hop_len))
        return EXIT_FAILURE;
    } else if (err) {
        return EXIT_FAILURE;
    }

    // Create and connect UDP socket
    err = scion_socket_create(ctx, &cl->socket, SOCK_DGRAM);
    if (err) {
        printf("Allocating socket failed\n");
        return EXIT_FAILURE;
    }
    err = scion_bind(cl->socket, (const struct sockaddr*)bind, sizeof(*bind));
    if (err) {
        printf("Can't bind to %s (%s:%d)\n", args->local_addr, scion_error_string(err), err);
        return EXIT_FAILURE;
    }
    err = scion_connect(cl->socket, &remote);
    if (err) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

void client_cleanup(struct Client* cl)
{
    scion_hdr_cache_free(cl->headers);
    scion_close(cl->socket);
    scion_release_paths(&cl->path, 1);
    scion_timer_free(cl->timer);
}

void client_get_stun_mapping(scion_context* ctx, struct Client* cl)
{
    struct sockaddr_storage stun_server;
    memcpy(&stun_server, &cl->next_hop, cl->next_hop_len);
    if (stun_server.ss_family == AF_INET)
        ((struct sockaddr_in*)&stun_server)->sin_port = htons(3478);
    else if (stun_server.ss_family == AF_INET6)
        ((struct sockaddr_in6*)&stun_server)->sin6_port = htons(3478);

    struct scion_async_send_handler handler = {
        &client_stun_sent, cl
    };
    scion_request_stun_mapping_async(cl->socket,
        (struct sockaddr*)&stun_server, cl->next_hop_len, handler);
    if (scion_run_for(ctx, 500) < 2) {
        // STUN timed out, cancel socket operations and run completion handlers
        scion_cancel(cl->socket);
        scion_restart(ctx);
        scion_run(ctx);
    }
}

void client_stun_sent(scion_error err, size_t n, void* user_ptr)
{
    struct Client* cl = user_ptr;
    struct scion_async_recv_handler handler = {
        &client_stun_received, cl
    };
    scion_recv_stun_response_async(cl->socket, handler);
}

void client_stun_received(scion_error err, void* recvd, size_t n, void* user_ptr)
{
    struct Client* cl = user_ptr;
    if (err == SCION_STUN_RECEIVED) {
        struct sockaddr_scion addr;
        scion_getmapped(cl->socket, &addr);
        char buffer[128] = {0};
        size_t len = sizeof(buffer);
        if (!scion_print_ep(&addr, buffer, &len))
            printf("SNAT mapped address: %s\n", buffer);
    } else {
        printf("Can't get SNAT address mapping: %s\n", scion_error_string(err));
    }
}

int client_run(struct Client* cl,
    scion_context* ctx, const struct sockaddr_storage* bind, const struct arguments* args)
{
    // Send message
    cl->headers = scion_hdr_cache_allocate();
    if (!cl->headers) return EXIT_FAILURE;
    SCION_SET_PATH(cl->pkt, cl->path);
    cl->pkt.underlay = (struct sockaddr*)&cl->next_hop;
    cl->pkt.underlay_len = sizeof(cl->next_hop);
    cl->args = args;
    struct scion_async_send_handler handler = {
        &client_sent, cl
    };
    scion_send_async(cl->socket, cl->headers, args->message, strlen(args->message), &cl->pkt, handler);
    return EXIT_SUCCESS;
}

void client_sent(scion_error err, size_t n, void* user_ptr)
{
    struct Client* cl = user_ptr;
    if (err) {
        printf("Error: %s:%d\n", scion_error_string(err), err);
        return;
    }
    struct scion_async_recv_handler handler = {
        &client_received, cl
    };
    cl->pkt.addr = &cl->from;
    SCION_SET_PATH(cl->pkt, NULL);
    scion_recv_async(cl->socket, cl->buffer, sizeof(cl->buffer), &cl->pkt, handler);
    scion_timer_set_timeout(cl->timer, 1000);
    struct scion_wait_handler timer_handler = {
        &client_timeout, cl
    };
    scion_timer_wait_async(cl->timer, timer_handler);
}

void client_received(scion_error err, void* recvd, size_t n, void* user_ptr)
{
    struct Client* cl = user_ptr;
    // client_timeout might cancel operations if the timer has already expired
    scion_timer_cancel(cl->timer);
    if (!recvd) {
        printf("Error: %s:%d\n", scion_error_string(err), err);
        return;
    }
    if (!cl->args->quiet) {
        char addr[128];
        size_t addr_len = sizeof(addr);
        if (!scion_print_ep(&cl->from, addr, &addr_len))
            printf("Received %zu bytes from %s:\n", n, addr);
    }
    print_buffer(recvd, n);
    if (++(cl->i) < cl->args->count) {
        struct scion_async_send_handler handler = {
            &client_sent, cl
        };
        scion_send_cached_async(
            cl->socket, cl->headers, cl->args->message, strlen(cl->args->message), &cl->pkt, handler);
    }
}

void client_timeout(scion_error err, void* user_ptr)
{
    struct Client* cl = user_ptr;
    if (err == SCION_CANCELLED) return;
    printf("No response\n");
    scion_cancel(cl->socket);
}

int main(int argc, char* argv[])
{
    struct arguments args;
    if (!parse_args(argc, argv, &args))
        return EXIT_FAILURE;

    // Initialize host context
    scion_context* ctx = NULL;
    struct scion_context_opts opts;
    memset(&opts, 0, sizeof(struct scion_context_opts));
    opts.daemon_address = args.daemon_addr;
    scion_error err = scion_create_host_context(&ctx, &opts);
    if (err) {
        printf("Failed to created host context (%s:%d)\n", scion_error_string(err), err);
        return EXIT_FAILURE;
    }

    // Parse bind address
    struct sockaddr_storage bind_addr = {0};
    if (!args.local_addr) {
        bind_addr.ss_family = AF_INET;
    } else {
        const char* phost = NULL;
        size_t host_len = 0;
        uint16_t port = 0;
        if (scion_split_host_port(args.local_addr, &phost, &host_len, &port)) {
            printf("Invalid bind address: %s\n", args.local_addr);
            scion_delete_host_context(ctx);
            return EXIT_FAILURE;
        }
        char host[128];
        if (host_len > sizeof(host) - 1) host_len = sizeof(host) - 1;
        memcpy(host, phost, host_len);
        host[host_len] = '\0';
        struct addrinfo* res = NULL;
        if (getaddrinfo(host, NULL, NULL, &res)) {
            printf("Invalid bind address: %s\n", args.local_addr);
            scion_delete_host_context(ctx);
            return EXIT_FAILURE;
        }
        if (res) {
            memcpy(&bind_addr, res->ai_addr, res->ai_addrlen);
            if (bind_addr.ss_family == AF_INET)
                ((struct sockaddr_in*)&bind_addr)->sin_port = port;
            else if (bind_addr.ss_family == AF_INET6)
                ((struct sockaddr_in*)&bind_addr)->sin_port = port;
            freeaddrinfo(res);
        }
    }

    int result = 0;
    if (args.remote_addr) {
        struct Client* client = malloc(sizeof(struct Client));
        result = client_init(client, ctx, &bind_addr, &args);
        if (result == EXIT_SUCCESS) {
            if (args.stun) {
                client_get_stun_mapping(ctx, client);
                scion_restart(ctx);
            }
            if (client_run(client, ctx, &bind_addr, &args) == EXIT_SUCCESS) {
                scion_run(ctx);
            }
        }
        client_cleanup(client);
        free(client);
    } else {
        struct Server* server = malloc(sizeof(struct Server));
        result = run_server(server, ctx, &bind_addr, &args);
        if (result == EXIT_SUCCESS) {
            CON_WIN32(HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE));
            CON_WIN32(while (!isKeyPressed(hConsoleInput, 'Q')))
            CON_CURSES(while (curses_get_char() != 'q'))
            {
                CON_CURSES(curses_refresh_screen());
                scion_run_for(ctx, 100);
            }
        }
        server_cleanup(server);
        free(server);
    }

    scion_delete_host_context(ctx);
    return result;
}
