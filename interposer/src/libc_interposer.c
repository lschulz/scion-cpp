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

#include "interposer.h"
#include "log.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

#include <dlfcn.h>
#include <pthread.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <unistd.h>

// Disable -Wpedantic because
// 1. Casting void* to a function pointer is undefined in ISO C, but allowed in
// POSIX. (necessary for dlsym)
// 2. Signatures of overriden functions are not truly compatible in ISO C.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"

#define LOG_CALLS 1

LIBC_BIND libc_bind = NULL;
LIBC_GETADDRINFO libc_getaddrinfo = NULL;
LIBC_FREEADDRINFO libc_freeaddrinfo = NULL;
LIBC_GETNAMEINFO libc_getnameinfo = NULL;
LIBC_INET_PTON libc_inet_pton = NULL;
LIBC_INET_NTOP libc_inet_ntop = NULL;
LIBC_SOCKET libc_socket = NULL;
LIBC_GETSOCKOPT libc_getsockopt = NULL;
LIBC_SETSOCKOPT libc_setsockopt = NULL;
LIBC_ACCEPT libc_accept = NULL;
LIBC_ACCEPT4 libc_accept4 = NULL;
LIBC_CONNECT libc_connect = NULL;
LIBC_GETPEERNAME libc_getpeername = NULL;
LIBC_GETSOCKNAME libc_getsockname = NULL;
LIBC_LISTEN libc_listen = NULL;
LIBC_SHUTDOWN libc_shutdown = NULL;
LIBC_RECV libc_recv = NULL;
LIBC_RECVFROM libc_recvfrom = NULL;
LIBC_RECVMSG libc_recvmsg = NULL;
LIBC_SEND libc_send = NULL;
LIBC_SENDTO libc_sendto = NULL;
LIBC_SENDMSG libc_sendmsg = NULL;
LIBC_READ libc_read = NULL;
LIBC_WRITE libc_write = NULL;
LIBC_FCNTL libc_fcntl = NULL;
LIBC_CLOSE libc_close = NULL;
#if _GNU_SOURCE
LIBC_RECVMMSG libc_recvmmsg = NULL;
LIBC_SENDMMSG libc_sendmmsg = NULL;
#endif // _GNU_SOURCE

// If true, stop stop calling the interposer functions.
static bool g_disable = false;
// Thread local flag to prevent calls in the interposer from being intercepted
// themselves.
static thread_local bool tl_recursive = false;

#define CHECK_SYMBOL(x) if (x == NULL) { \
    interposer_log(LEVEL_FATAL, "Symbol not found: %s", #x); \
    abort(); \
}

static void load_symbols()
{
    libc_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
    CHECK_SYMBOL(libc_getaddrinfo);
    libc_freeaddrinfo = dlsym(RTLD_NEXT, "freeaddrinfo");
    CHECK_SYMBOL(libc_freeaddrinfo);
    libc_getnameinfo = dlsym(RTLD_NEXT, "getnameinfo");
    CHECK_SYMBOL(libc_freeaddrinfo);
    libc_inet_pton = dlsym(RTLD_NEXT, "inet_pton");
    CHECK_SYMBOL(libc_freeaddrinfo);
    libc_inet_ntop = dlsym(RTLD_NEXT, "inet_ntop");
    CHECK_SYMBOL(libc_freeaddrinfo);
    libc_socket = dlsym(RTLD_NEXT, "socket");
    CHECK_SYMBOL(libc_socket);
    libc_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    CHECK_SYMBOL(libc_getsockopt);
    libc_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    CHECK_SYMBOL(libc_setsockopt);
    libc_accept = dlsym(RTLD_NEXT, "accept");
    CHECK_SYMBOL(libc_accept);
    libc_accept4 = dlsym(RTLD_NEXT, "accept4");
    CHECK_SYMBOL(libc_accept4);
    libc_bind = dlsym(RTLD_NEXT, "bind");
    CHECK_SYMBOL(libc_bind);
    libc_connect = dlsym(RTLD_NEXT, "connect");
    CHECK_SYMBOL(libc_connect);
    libc_getpeername = dlsym(RTLD_NEXT, "getpeername");
    CHECK_SYMBOL(libc_getpeername);
    libc_getsockname = dlsym(RTLD_NEXT, "getsockname");
    CHECK_SYMBOL(libc_getsockname);
    libc_listen = dlsym(RTLD_NEXT, "listen");
    CHECK_SYMBOL(libc_listen);
    libc_shutdown = dlsym(RTLD_NEXT, "shutdown");
    CHECK_SYMBOL(libc_shutdown);
    libc_recv = dlsym(RTLD_NEXT, "recv");
    CHECK_SYMBOL(libc_recv);
    libc_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    CHECK_SYMBOL(libc_recvfrom);
    libc_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
    CHECK_SYMBOL(libc_recvmsg);
    libc_send = dlsym(RTLD_NEXT, "send");
    CHECK_SYMBOL(libc_send);
    libc_sendto = dlsym(RTLD_NEXT, "sendto");
    CHECK_SYMBOL(libc_sendto);
    libc_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
    CHECK_SYMBOL(libc_sendmsg);
    libc_read = dlsym(RTLD_NEXT, "read");
    CHECK_SYMBOL(libc_read);
    libc_write = dlsym(RTLD_NEXT, "write");
    CHECK_SYMBOL(libc_write);
    libc_fcntl = dlsym(RTLD_NEXT, "fcntl");
    CHECK_SYMBOL(libc_fcntl);
    libc_close = dlsym(RTLD_NEXT, "close");
    CHECK_SYMBOL(libc_close);
#if _GNU_SOURCE
    libc_recvmmsg = dlsym(RTLD_NEXT, "recvmmsg");
    CHECK_SYMBOL(libc_recvmmsg);
    libc_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg");
    CHECK_SYMBOL(libc_sendmmsg);
#endif // _GNU_SOURCE
}

static void initialize()
{
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    static bool static_initialized = false;
    bool initialized = __atomic_load_n(&static_initialized, __ATOMIC_ACQUIRE);
    if (!initialized) {
        pthread_mutex_lock(&mutex);
        initialized = __atomic_load_n(&static_initialized, __ATOMIC_RELAXED);
        if (!initialized) {
            load_symbols();
            __atomic_store_n(&static_initialized, true, __ATOMIC_RELEASE);
        }
        pthread_mutex_unlock(&mutex);
    }
}

void stop_interposer()
{
    __atomic_store_n(&g_disable, true, __ATOMIC_SEQ_CST);
}

#if LOG_CALLS
static const char* str_domain(int domain)
{
    switch (domain) {
    case AF_UNIX:
        return "AF_UNIX";
    case AF_INET:
        return "AF_INET";
    case AF_INET6:
        return "AF_INET6";
    case AF_SCION:
        return "AF_SCION";
    case AF_XDP:
        return "AF_XDP";
    default:
        return "OTHER";
    }
}

static const char* str_socket_type(int type)
{
    switch (type & 0x3fff) {
    case SOCK_STREAM:
        return "SOCK_STREAM";
    case SOCK_DGRAM:
        return "SOCK_DGRAM";
    case SOCK_SEQPACKET:
        return "SOCK_SEQPACKET";
    case SOCK_RAW:
        return "SOCK_RAW";
    default:
        return "UNKNOWN";
    }
}

static const char* str_protocol(int protocol)
{
    switch (protocol) {
    case IPPROTO_ICMP:
        return "IPPROTO_ICMP";
    case IPPROTO_IP:
        return "IPPROTO_IP";
    case IPPROTO_TCP:
        return "IPPROTO_TCP";
    case IPPROTO_UDP:
        return "IPPROTO_UDP";
    default:
        return "UNKNOWN";
    }
}

static const char* str_sockopt_level(int protocol)
{
    switch (protocol) {
    case SOL_SOCKET:
        return "SOL_SOCKET";
    case IPPROTO_IP:
        return "IPPROTO_IP";
    case IPPROTO_TCP:
        return "IPPROTO_TCP";
    case IPPROTO_UDP:
        return "IPPROTO_UDP";
    default:
        return "UNKNOWN";
    }
}

static const char* str_sockoptname(int level, int optname)
{
    if (level == SOL_SOCKET) {
        switch (optname) {
        case SO_ACCEPTCONN:
            return "SO_ACCEPTCONN";
        case SO_ATTACH_BPF:
            return "SO_ATTACH_BPF";
        case SO_ATTACH_REUSEPORT_EBPF:
            return "SO_ATTACH_REUSEPORT_EBPF";
        case SO_BINDTODEVICE:
            return "SO_BINDTODEVICE";
        case SO_BROADCAST:
            return "SO_BROADCAST";
        case SO_DEBUG:
            return "SO_DEBUG";
        case SO_DETACH_BPF:
            return "SO_DETACH_BPF";
        case SO_DOMAIN:
            return "SO_DOMAIN";
        case SO_ERROR:
            return "SO_ERROR";
        case SO_DONTROUTE:
            return "SO_DONTROUTE";
        case SO_KEEPALIVE:
            return "SO_KEEPALIVE";
        case SO_LINGER:
            return "SO_LINGER";
        case SO_LOCK_FILTER:
            return "SO_LOCK_FILTER";
        case SO_MARK:
            return "SO_MARK";
        case SO_OOBINLINE:
            return "SO_OOBINLINE";
        case SO_PRIORITY:
            return "SO_PRIORITY";
        case SO_PROTOCOL:
            return "SO_PROTOCOL";
        case SO_RCVBUF:
            return "SO_RCVBUF";
        case SO_RCVBUFFORCE:
            return "SO_RCVBUFFORCE";
        case SO_RCVLOWAT:
            return "SO_RCVLOWAT";
        case SO_SNDLOWAT:
            return "SO_SNDLOWAT";
        case SO_RCVTIMEO:
            return "SO_RCVTIMEO";
        case SO_SNDTIMEO:
            return "SO_SNDTIMEO";
        case SO_REUSEADDR:
            return "SO_REUSEADDR";
        case SO_REUSEPORT:
            return "SO_REUSEPORT";
        case SO_SNDBUF:
            return "SO_SNDBUF";
        case SO_TIMESTAMP:
            return "SO_TIMESTAMP";
        case SO_TIMESTAMPNS:
            return "SO_TIMESTAMPNS";
        case SO_TYPE:
            return "SO_TYPE";
        default:
            return "UNKNOWN";
        }
    } else if (level == IPPROTO_IP) {
        switch (optname) {
        case IP_BIND_ADDRESS_NO_PORT:
            return "IP_BIND_ADDRESS_NO_PORT";
        case IP_FREEBIND:
            return "IP_FREEBIND";
        case IP_LOCAL_PORT_RANGE:
            return "IP_LOCAL_PORT_RANGE";
        case IP_MTU:
            return "IP_MTU";
        case IP_MTU_DISCOVER:
            return "IP_MTU_DISCOVER";
        case IP_OPTIONS:
            return "IP_OPTIONS";
        case IP_PKTINFO:
            return "IP_PKTINFO";
        case IP_RECVERR:
            return "IP_RECVERR";
        case IP_RECVTTL:
            return "IP_RECVTTL";
        case IP_RECVOPTS:
            return "IP_RECVOPTS";
        case IP_ROUTER_ALERT:
            return "IP_ROUTER_ALERT";
        case IP_TOS:
            return "IP_TOS";
        case IP_TRANSPARENT:
            return "IP_TRANSPARENT";
        default:
            return "UNKNOWN";
        }
    } else if (level == IPPROTO_IPV6) {
        switch (optname) {
        case IPV6_ADDRFORM:
            return "IPV6_ADDRFORM";
        case IPV6_MTU:
            return "IPV6_MTU";
        case IPV6_MTU_DISCOVER:
            return "IPV6_MTU_DISCOVER";
        case IPV6_RECVPKTINFO:
            return "IPV6_RECVPKTINFO";
        case IPV6_RTHDR:
            return "IPV6_RTHDR";
        case IPV6_AUTHHDR:
            return "IPV6_AUTHHDR";
        case IPV6_DSTOPTS:
            return "IPV6_DSTOPTS";
        case IPV6_HOPOPTS:
            return "IPV6_HOPOPTS";
        case IPV6_HOPLIMIT:
            return "IPV6_HOPLIMIT";
        case IPV6_RECVERR:
            return "IPV6_RECVERR";
        case IPV6_ROUTER_ALERT:
            return "IPV6_ROUTER_ALERT";
        case IPV6_UNICAST_HOPS:
            return "IPV6_UNICAST_HOPS";
        case IPV6_V6ONLY:
            return "IPV6_V6ONLY";
        default:
            return "UNKNOWN";
        }
    } else if (level == IPPROTO_TCP) {
        switch (optname) {
        case TCP_CONGESTION:
            return "TCP_CONGESTION";
        case TCP_CORK:
            return "TCP_CORK";
        case TCP_DEFER_ACCEPT:
            return "TCP_DEFER_ACCEPT";
        case TCP_INFO:
            return "TCP_INFO";
        case TCP_KEEPCNT:
            return "TCP_KEEPCNT";
        case TCP_KEEPIDLE:
            return "TCP_KEEPIDLE";
        case TCP_KEEPINTVL:
            return "TCP_KEEPINTVL";
        case TCP_LINGER2:
            return "TCP_LINGER2";
        case TCP_MAXSEG:
            return "TCP_MAXSEG";
        case TCP_NODELAY:
            return "TCP_NODELAY";
        case TCP_QUICKACK:
            return "TCP_QUICKACK";
        case TCP_SYNCNT:
            return "TCP_SYNCNT";
        case TCP_USER_TIMEOUT:
            return "TCP_USER_TIMEOUT";
        case TCP_WINDOW_CLAMP:
            return "TCP_WINDOW_CLAMP";
        case TCP_FASTOPEN:
            return "TCP_FASTOPEN";
        case TCP_FASTOPEN_CONNECT:
            return "TCP_FASTOPEN_CONNECT";
        case TCP_ULP:
            return "TCP_ULP";
        default:
            return "UNKNOWN";
        }
    } else if (level == IPPROTO_UDP) {
        switch (optname) {
        case UDP_CORK:
            return "UDP_CORK";
        case UDP_SEGMENT:
            return "UDP_SEGMENT";
        case UDP_GRO:
            return "UDP_GRO";
        default:
            return "UNKNOWN";
        }
    } else {
        return "UNKNOWN";
    }
}
#endif

int getaddrinfo(const char* restrict node,
    const char* restrict service,
    const struct addrinfo* restrict hints,
    struct addrinfo** restrict res)
{
    initialize();
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_getaddrinfo(node, service, hints, res);
    } else {
        tl_recursive = true;
        result = interposer_getaddrinfo(node, service, hints, res);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "getaddrinfo('%s', '%s', %p, %p) = %d",
        node, service, (void*)hints, (void*)res, result);
#endif
    return result;
}

void freeaddrinfo(struct addrinfo* res)
{
    initialize();
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        libc_freeaddrinfo(res);
    } else {
        tl_recursive = true;
        interposer_freeaddrinfo(res);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "freeaddrinfo(%p)", (void*)res);
#endif
}

int getnameinfo(
    const struct sockaddr* restrict addr, socklen_t addrlen,
    char* restrict host, socklen_t hostlen,
    char* restrict serv, socklen_t servlen, int flags)
{
    initialize();
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
    } else {
        tl_recursive = true;
        result = interposer_getnameinfo(addr, addrlen, host, hostlen, serv, servlen, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "getnameinfo(%p, %u, %p, %u, %p, %u, %d) = %d",
        (void*)addr, addrlen, (void*)host, hostlen, (void*)serv, servlen, flags, result);
#endif
    return result;
}

int inet_pton(int af, const char* restrict src, void* restrict dst)
{
    initialize();
    int result = 0;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_inet_pton(af, src, dst);
    } else {
        tl_recursive = true;
        result = interposer_inet_pton(af, src, dst);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "inet_pton(%d, '%s', %p) = %d", af, src, (void*)dst, result);
#endif
    return result;
}

const char* inet_ntop(int af, const void* restrict src,
    char* restrict dst, socklen_t size)
{
    initialize();
    const char* result = NULL;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_inet_ntop(af, src, dst, size);
    } else {
        tl_recursive = true;
        result = interposer_inet_ntop(af, src, dst, size);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "inet_ntop(%d, %p, '%s', %u) = %p",
        af, (void*)src, dst, size, (void*)result);
#endif
    return result;
}

int socket(int domain, int type, int protocol)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_socket(domain, type, protocol);
    } else {
        tl_recursive = true;
        result = interposer_socket(domain, type, protocol);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "socket(%s:%d, %s:%d, %s:%d) = %d [%s]",
        str_domain(domain), domain, str_socket_type(type), type, str_protocol(protocol), protocol,
        result, strerror(errno));
#endif
    return result;
}

int getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* restrict optLen)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_getsockopt(sockfd, level, optname, optval, optLen);
    } else {
        tl_recursive = true;
        result = interposer_getsockopt(sockfd, level, optname, optval, optLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "getsockopt(%d, %s:%d, %s:%d) = %d [%s]",
        sockfd, str_sockopt_level(level), level, str_sockoptname(level, optname), optname,
        result, strerror(errno));
#endif
    return result;
}

int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optLen)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_setsockopt(sockfd, level, optname, optval, optLen);
    } else {
        tl_recursive = true;
        result = interposer_setsockopt(sockfd, level, optname, optval, optLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "setsockopt(%d, %s:%d, %s:%d) = %d [%s]",
        sockfd, str_sockopt_level(level), level, str_sockoptname(level, optname), optname,
        result, strerror(errno));
#endif
    return result;
}

int accept(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrLen)
{
    initialize();
    errno = 0;
    int result = libc_accept(sockfd, addr, addrLen);
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "accept(%d, %p, %u) = %d [%s]",
        sockfd, (void*)addr, *addrLen, result, strerror(errno));
#endif
    return result;
}

int accept4(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrLen, int flags)
{
    initialize();
    errno = 0;
    int result = libc_accept4(sockfd, addr, addrLen, flags);
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "accept4(%d, %p, %d, %d) = %d [%s]",
        sockfd, (void*)addr, *addrLen, flags, result, strerror(errno));
#endif
    return result;
}

int bind(int sockfd, const struct sockaddr* addr, socklen_t addrLen)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_bind(sockfd, addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_bind(sockfd, addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "bind(%d, %p, %u) = %d [%s]",
        sockfd, (void*)addr, addrLen, result, strerror(errno));
#endif
    return result;
}

int connect(int sockfd, const struct sockaddr* addr, socklen_t addrLen)
{
    initialize();
    errno = 0;
    int result = 1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_connect(sockfd, addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_connect(sockfd, addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "connect(%d, %p, %u) = %d [%s]",
        sockfd, (void*)addr, addrLen, result, strerror(errno));
#endif
    return result;
}

int getpeername(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrLen)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_getpeername(sockfd, addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_getpeername(sockfd, addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "getpeername(%d, %p, %u) = %d [%s]",
        sockfd, (void*)addr, *addrLen, result, strerror(errno));
#endif
    return result;
}

int getsockname(int sockfd, struct sockaddr* restrict addr, socklen_t* restrict addrLen)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_getsockname(sockfd, addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_getsockname(sockfd, addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "getsockname(%d, %p, %u) = %d [%s]",
        sockfd, (void*)addr, *addrLen, result, strerror(errno));
#endif
    return result;
}

int listen(int sockfd, int backlog)
{
    initialize();
    errno = 0;
    int result = libc_listen(sockfd, backlog);
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "listen(%d, %d) = %d [%s]",
        sockfd, backlog, result, strerror(errno));
#endif
    return result;
}

int shutdown(int sockfd, int how)
{
    initialize();
    errno = 0;
    int result = libc_shutdown(sockfd, how);
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "shutdown(%d, %d) = %d [%s]",
        sockfd, how, result, strerror(errno));
#endif
    return result;
}

ssize_t recv(int sockfd, void* buf, size_t size, int flags)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_recv(sockfd, buf, size, flags);
    } else {
        tl_recursive = true;
        result = interposer_recv(sockfd, buf, size, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "recv(%d, %p, %zu, %d) = %zd [%s]",
        sockfd, buf, size, flags, result, strerror(errno));
#endif
    return result;
}

ssize_t recvfrom(int sockfd, void* restrict buf, size_t size, int flags,
    struct sockaddr* restrict src_addr, socklen_t* restrict addrLen)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_recvfrom(sockfd, buf, size, flags, src_addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_recvfrom(sockfd, buf, size, flags, src_addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "recvfrom(%d, %p, %zu, %d, %p, %d) = %zd [%s]",
        sockfd, buf, size, flags, (void*)src_addr, *addrLen, result, strerror(errno));
#endif
    return result;
}

ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_recvmsg(sockfd, msg, flags);
    } else {
        tl_recursive = true;
        result = interposer_recvmsg(sockfd, msg, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "recvmsg(%d, %p, %d) = %zd [%s]",
        sockfd, (void*)msg, flags, result, strerror(errno));
#endif
    return result;
}

ssize_t send(int sockfd, const void* buf, size_t size, int flags)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_send(sockfd, buf, size, flags);
    } else {
        tl_recursive = true;
        result = interposer_send(sockfd, buf, size, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "send(%d, %p, %zu, %d) = %zd [%s]",
        sockfd, buf, size, flags, result, strerror(errno));
#endif
    return result;
}

ssize_t sendto(int sockfd, const void* buf, size_t size, int flags,
    const struct sockaddr* dst_addr, socklen_t addrLen)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_sendto(sockfd, buf, size, flags, dst_addr, addrLen);
    } else {
        tl_recursive = true;
        result = interposer_sendto(sockfd, buf, size, flags, dst_addr, addrLen);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "sendto(%d, %p, %zu, %d, %p, %d) = %zd [%s]",
        sockfd, buf, size, flags, (void*)dst_addr, addrLen, result, strerror(errno));
#endif
    return result;
}

ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_sendmsg(sockfd, msg, flags);
    } else {
        tl_recursive = true;
        result = interposer_sendmsg(sockfd, msg, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "sendmsg(%d, %p, %d) = %zd [%s]",
        sockfd, (void*)msg, flags, result, strerror(errno));
#endif
    return result;
}

ssize_t read(int fd, void* buf, size_t count)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_read(fd, buf, count);
    } else {
        tl_recursive = true;
        result = interposer_read(fd, buf, count);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "read(%d, %p, %zu) = %zd [%s]",
        fd, buf, count, result, strerror(errno));
#endif
    return result;
}

ssize_t write(int fd, const void* buf, size_t count)
{
    initialize();
    errno = 0;
    ssize_t result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_write(fd, buf, count);
    } else {
        tl_recursive = true;
        result = interposer_write(fd, buf, count);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "write(%d, %p, %zu) = %zd [%s]",
        fd, buf, count, result, strerror(errno));
#endif
    return result;
}

int fcntl(int fd, int op, ...)
{
    initialize();
    errno = 0;
    int result = -1;
    va_list args;
    va_start(args, op);

    switch (op) {
    case F_GETFD:
    case F_GETFL:
    case 9 /*F_GETOWN*/:
    case 11 /*F_GETSIG*/:
    case 1025 /*F_GETLEASE*/:
    case 1032 /*F_GETPIPE_SZ*/:
    case 1034 /*F_GET_SEALS*/:
        result = libc_fcntl(fd, op);
        break;

    case F_DUPFD:
    case 1030 /*F_DUPFD_CLOEXEC*/:
    case F_SETFD:
    case F_SETFL:
    case 8 /*F_SETOWN*/:
    case 10 /*F_SETSIG*/:
    case 1024 /*F_SETLEASE*/:
    case 1026 /*F_NOTIFY*/:
    case 1031 /*F_SETPIPE_SZ*/:
    case 1033 /*F_ADD_SEALS*/:
        result = libc_fcntl(fd, op, va_arg(args, int));
        break;

    case F_SETLK:
    case F_SETLKW:
    case F_GETLK:
    case 37 /*F_OFD_SETLK*/:
    case 38 /*F_OFD_SETLKW*/:
    case 36 /*F_OFD_GETLK*/:
    case 16 /*F_GETOWN_EX*/:
    case 15 /*F_SETOWN_EX*/:
    case 1035 /*F_GET_RW_HINT*/:
    case 1036 /*F_SET_RW_HINT*/:
    case 1037 /*F_GET_FILE_RW_HINT*/:
    case 1038 /*F_SET_FILE_RW_HINT*/:
        result = libc_fcntl(fd, op, va_arg(args, void*));
        break;
    }

#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "fcntl(%d, %d, ...) = %d [%s]",
        fd, op, result, strerror(errno));
#endif

    va_end(args);
    return result;
}

int close(int fd)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_close(fd);
    } else {
        tl_recursive = true;
        result = interposer_close(fd);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "close(%d) = %d [%s]", fd, result, strerror(errno));
#endif
    return result;
}

#if _GNU_SOURCE

int recvmmsg(int sockfd, struct mmsghdr* msgvec,
    unsigned int vlen, int flags, struct timespec* timeout)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
    } else {
        tl_recursive = true;
        result = interposer_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "recvmmsg(%d, %p, %u, %u, %p) = %d [%s]",
        sockfd, (void*)msgvec, vlen, flags, timeout, result, strerror(errno));
#endif
    return result;
}

int sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags)
{
    initialize();
    errno = 0;
    int result = -1;
    if (tl_recursive || __atomic_load_n(&g_disable, __ATOMIC_SEQ_CST)) {
        result = libc_sendmmsg(sockfd, msgvec, vlen, flags);
    } else {
        tl_recursive = true;
        result = interposer_sendmmsg(sockfd, msgvec, vlen, flags);
        tl_recursive = false;
    }
#if LOG_CALLS
    interposer_log(LEVEL_TRACE, "sendmmsg(%d, %p, %u, %u) = %d [%s]",
        sockfd, (void*)msgvec, vlen, flags, result, strerror(errno));
#endif
    return result;
}

#endif // _GNU_SOURCE
#pragma GCC diagnostic pop
