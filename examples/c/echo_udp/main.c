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
#define poll WSAPoll
#else
#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <poll.h>
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

int run_server(
    scion_context* ctx, const struct sockaddr_storage* bind, const struct arguments* args)
{
    // Create and bind UDP socket
    scion_socket* socket;
    scion_error err = scion_socket_create(ctx, &socket, SOCK_DGRAM);
    if (err) {
        printf("Allocating socket failed\n");
        return EXIT_FAILURE;
    }
    err = scion_bind(socket, (const struct sockaddr*)bind, sizeof(*bind));
    if (err) {
        printf("Can't bind to %s (%s:%d)\n", args->local_addr, scion_error_string(err), err);
        goto cleanup1;
    }

    CON_WIN32(HANDLE hConsoleInput = GetStdHandle(STD_INPUT_HANDLE));
    CON_CURSES(curses_init_server());
    {
        struct sockaddr_scion bound;
        scion_getsockname(socket, &bound);
        char buffer[64];
        size_t buffer_len = sizeof(buffer);
        if (!scion_print_ep(&bound, buffer, &buffer_len))
            console_printf("Server listening at %s\nPress q to quit.\n", buffer);
    }

    // Receive and echo back
    scion_raw_path* path = scion_raw_path_allocate();
    if (!path) goto cleanup2;
    scion_hdr_cache* headers = scion_hdr_cache_allocate();
    if (!headers) goto cleanup3;
    struct sockaddr_scion from;
    struct sockaddr_storage next_hop;
    struct scion_packet pkt = {0};
    pkt.addr = &from;
    pkt.underlay = (struct sockaddr*)&next_hop;
    pkt.underlay_len = sizeof(next_hop);
    SCION_SET_PATH(pkt, path);
    char buffer[1024];
    struct pollfd fds[1] = {{
        .fd = scion_underlay_handle(socket),
        .events = POLLIN,
        .revents = 0,
    }};
    CON_WIN32(while (!isKeyPressed(hConsoleInput, 'Q')))
    CON_CURSES(while (curses_get_char() != 'q'))
    {
        CON_CURSES(curses_refresh_screen());
        int pret = poll(fds, sizeof(fds) / sizeof(*fds), 100);
        if (pret == 0) { // timeout
            continue;
        } else if (pret < 0) {
            console_printf("poll failed\n");
            goto cleanup4;
        }

        size_t n = sizeof(buffer);
        char* recvd = scion_recv(socket, buffer, &n, &pkt, &err);
        if (!recvd) {
            console_printf("Error: %s:%d\n", scion_error_string(err), err);
            goto cleanup4;
        }
        if (!args->quiet) {
            char str[128];
            size_t str_len = sizeof(str);
            if (!scion_print_ep(&from, str, &str_len))
                console_printf("Received %zu bytes from %s\n", n, str);
            str_len = sizeof(buffer);
            if (!scion_raw_path_print(path, str, &str_len))
                console_printf("Path: %s\n", str);
        }
        if (!scion_raw_path_reverse(path)) {
            err = scion_send(socket, headers, recvd, &n, &pkt);
            if (err) {
                console_printf("Error: %s:%d\n", scion_error_string(err), err);
                goto cleanup4;
            }
        }
    }

cleanup4:
    scion_hdr_cache_free(headers);
cleanup3:
    scion_raw_path_free(path);
cleanup2:
    CON_CURSES(curses_end_server());
cleanup1:
    scion_close(socket);
    if (err) return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

void get_stun_mapping(scion_socket* socket, const struct sockaddr* next_hop, socklen_t next_hop_len)
{
    scion_error err;
    struct sockaddr_storage stun_server;
    memcpy(&stun_server, next_hop, next_hop_len);
    if (stun_server.ss_family == AF_INET)
        ((struct sockaddr_in*)&stun_server)->sin_port = htons(3478);
    else if (stun_server.ss_family == AF_INET6)
        ((struct sockaddr_in6*)&stun_server)->sin6_port = htons(3478);

    err = scion_request_stun_mapping(socket, (struct sockaddr*)&stun_server, next_hop_len);
    if (err) {
        printf("Sending STUN request failed\n");
        return;
    }

    // use poll for the timeout
    struct pollfd fds = {
        .fd = scion_underlay_handle(socket),
        .events = POLLIN,
    };
    if (poll(&fds, 1, 500) <= 0) {
        printf("Can't get SNAT address mapping: %s\n", "Timeout");
        return;
    }

    // TODO: If an unrelated packet was received first, this can still hang forever.
    err = scion_recv_stun_response(socket);
    if (err == SCION_STUN_RECEIVED) {
        struct sockaddr_scion addr;
        scion_getmapped(socket, &addr);
        char buffer[128] = {0};
        size_t len = sizeof(buffer);
        if (!scion_print_ep(&addr, buffer, &len))
            printf("SNAT mapped address: %s\n", buffer);
    } else {
        printf("Can't get SNAT address mapping: %s\n", scion_error_string(err));
    }
}

int run_client(
    scion_context* ctx, const struct sockaddr_storage* bind, const struct arguments* args)
{
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
    scion_path* path = NULL;
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
            size_t selection = 0;
            if (scanf("%zu", &selection) == 1 && selection < path_count) {
                path = paths[selection];
                break;
            }
        }
    } else {
        path = paths[(size_t)rand() % path_count];
    }
    struct sockaddr_storage next_hop;
    socklen_t next_hop_len = sizeof(next_hop);
    err = scion_path_next_hop(path, (struct sockaddr*)&next_hop, &next_hop_len);
    if (err == SCION_PATH_IS_EMPTY) {
        if (scion_sockaddr_get_host(&remote, (struct sockaddr*)&next_hop, next_hop_len))
            goto cleanup1;
    } else if (err) {
        goto cleanup1;
    }

    // Create and connect UDP socket
    scion_socket* socket;
    err = scion_socket_create(ctx, &socket, SOCK_DGRAM);
    if (err) {
        printf("Allocating socket failed\n");
        goto cleanup1;
    }
    err = scion_bind(socket, (const struct sockaddr*)bind, sizeof(*bind));
    if (err) {
        printf("Can't bind to %s (%s:%d)\n", args->local_addr, scion_error_string(err), err);
        goto cleanup2;
    }
    err = scion_connect(socket, &remote);
    if (err) goto cleanup2;

    // STUN
    if (args->stun) {
        get_stun_mapping(socket, (struct sockaddr*)&next_hop, next_hop_len);
    }

    // Send message
    scion_hdr_cache* headers = scion_hdr_cache_allocate();
    if (!headers) goto cleanup2;
    struct scion_packet out_pkt = {0};
    SCION_SET_PATH(out_pkt, path);
    out_pkt.underlay = (struct sockaddr*)&next_hop;
    out_pkt.underlay_len = sizeof(next_hop);
    struct sockaddr_scion from;
    struct scion_packet in_pkt = {0};
    in_pkt.addr = &from;
    char buffer[1024];
    for (int i = 0; i < args->count; ++i) {
        size_t n = strlen(args->message);
        err = scion_send(socket, headers, args->message, &n, &out_pkt);
        if (err) {
            printf("Error: %s:%d\n", scion_error_string(err), err);
            goto cleanup3;
        }
        size_t m = sizeof(buffer);
        char* recvd = scion_recv(socket, buffer, &m, &in_pkt, &err);
        if (!recvd) {
            printf("Error: %s:%d\n", scion_error_string(err), err);
            goto cleanup3;
        }
        if (!args->quiet) {
            char addr[128];
            size_t addr_len = sizeof(addr);
            if (!scion_print_ep(&from, addr, &addr_len))
                printf("Received %zu bytes from %s:\n", m, addr);
        }
        print_buffer(recvd, m);
    }

cleanup3:
    scion_hdr_cache_free(headers);
cleanup2:
    scion_close(socket);
cleanup1:
    scion_release_paths(paths, path_count);
    if (err) return EXIT_FAILURE;
    return EXIT_SUCCESS;
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
        result = run_client(ctx, &bind_addr, &args);
    } else {
        result = run_server(ctx, &bind_addr, &args);
    }

    scion_delete_host_context(ctx);
    return result;
}
