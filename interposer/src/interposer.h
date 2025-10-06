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

#pragma once

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>


// Address family for native SCION addresses.
#define AF_SCION 64

// Additional values for `ai_flags` in `addrinfo` structure
#define AI_SCION_NATIVE 0x7000 /* Return SCION addresses as AF_SCION. */

// Maximum size of a numerical SCION address string.
#define SCION_ADDRSTRLEN 80

#if _WIN32
typedef SOCKET NativeSocket;
#else
typedef int NativeSocket;
#endif

#if __cplusplus
extern "C" {
#endif

typedef int (*LIBC_GETADDRINFO)(const char* restrict, const char* __restrict,
    const struct addrinfo* __restrict, struct addrinfo** __restrict);
typedef void (*LIBC_FREEADDRINFO)(struct addrinfo*);
typedef int (*LIBC_GETNAMEINFO)(const struct sockaddr* __restrict, socklen_t,
    char* __restrict, socklen_t, char* __restrict, socklen_t, int);
typedef int (*LIBC_INET_PTON)(int, const char* __restrict, void* __restrict);
typedef const char* (*LIBC_INET_NTOP)(int, const void* __restrict, char* __restrict, socklen_t);
typedef int (*LIBC_SOCKET)(int, int, int);
typedef int (*LIBC_GETSOCKOPT)(int, int, int, void*, socklen_t*);
typedef int (*LIBC_SETSOCKOPT)(int, int, int, const void*, socklen_t);
typedef int (*LIBC_ACCEPT)(int, struct sockaddr*, socklen_t*);
typedef int (*LIBC_ACCEPT4)(int, struct sockaddr*, socklen_t*, int);
typedef int (*LIBC_BIND)(int, const struct sockaddr*, socklen_t);
typedef int (*LIBC_CONNECT)(int sockfd, const struct sockaddr* addr, socklen_t addrLen);
typedef int (*LIBC_GETPEERNAME)(int, struct sockaddr*, socklen_t*);
typedef int (*LIBC_GETSOCKNAME)(int, struct sockaddr* __restrict, socklen_t*);
typedef int (*LIBC_LISTEN)(int, int);
typedef int (*LIBC_SHUTDOWN)(int sockfd, int how);
typedef ssize_t (*LIBC_RECV)(int, void*, size_t, int);
typedef ssize_t (*LIBC_RECVFROM)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef ssize_t (*LIBC_RECVMSG)(int, struct msghdr*, int);
typedef ssize_t (*LIBC_SEND)(int, const void*, size_t, int);
typedef ssize_t (*LIBC_SENDTO)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*LIBC_SENDMSG)(int, const struct msghdr*, int);
typedef ssize_t (*LIBC_READ)(int fd, void* buf, size_t count);
typedef ssize_t (*LIBC_WRITE)(int, const void*, size_t);
typedef int (*LIBC_FCNTL)(int, int, ...);
typedef int (*LIBC_CLOSE)(int);
#if _GNU_SOURCE
typedef int (*LIBC_RECVMMSG)(int, struct mmsghdr*, unsigned int, int, struct timespec*);
typedef int (*LIBC_SENDMMSG)(int, struct mmsghdr*, unsigned int, int);
#endif

// original functions from libc
extern LIBC_BIND libc_bind;
extern LIBC_GETADDRINFO libc_getaddrinfo;
extern LIBC_FREEADDRINFO libc_freeaddrinfo;
extern LIBC_GETNAMEINFO libc_getnameinfo;
extern LIBC_INET_PTON libc_inet_pton;
extern LIBC_INET_NTOP libc_inet_ntop;
extern LIBC_SOCKET libc_socket;
extern LIBC_GETSOCKOPT libc_getsockopt;
extern LIBC_SETSOCKOPT libc_setsockopt;
extern LIBC_ACCEPT libc_accept;
extern LIBC_ACCEPT4 libc_accept4;
extern LIBC_CONNECT libc_connect;
extern LIBC_GETPEERNAME libc_getpeername;
extern LIBC_GETSOCKNAME libc_getsockname;
extern LIBC_LISTEN libc_listen;
extern LIBC_SHUTDOWN libc_shutdown;
extern LIBC_RECV libc_recv;
extern LIBC_RECVFROM libc_recvfrom;
extern LIBC_RECVMSG libc_recvmsg;
extern LIBC_SEND libc_send;
extern LIBC_SENDTO libc_sendto;
extern LIBC_SENDMSG libc_sendmsg;
extern LIBC_READ libc_read;
extern LIBC_WRITE libc_write;
extern LIBC_FCNTL libc_fcntl;
extern LIBC_CLOSE libc_close;
#if _GNU_SOURCE
extern LIBC_RECVMMSG libc_recvmmsg;
extern LIBC_SENDMMSG libc_sendmmsg;
#endif

int interposer_getaddrinfo(const char* __restrict name,
    const char* __restrict service,
    const struct addrinfo* __restrict hints,
    struct addrinfo** __restrict res);
void interposer_freeaddrinfo(struct addrinfo* res);
int interposer_getnameinfo(
    const struct sockaddr* __restrict addr, socklen_t addrlen,
    char* __restrict host, socklen_t hostlen,
    char* __restrict serv, socklen_t servlen, int flags);
int interposer_inet_pton(int af, const char* __restrict src, void* __restrict dst);
const char* interposer_inet_ntop(int af, const void* __restrict src,
    char* __restrict dst, socklen_t size);

NativeSocket interposer_socket(int domain, int type, int protocol);
int interposer_bind(NativeSocket sockfd, const struct sockaddr* addr, socklen_t addrLen);
int interposer_connect(NativeSocket sockfd, const struct sockaddr* addr, socklen_t addrLen);
int interposer_close(NativeSocket sockfd);

int interposer_getsockopt(NativeSocket sockfd, int level, int optname,
    void* optval, socklen_t* __restrict optLen);
int interposer_setsockopt(NativeSocket sockfd, int level, int optname,
    const void* optval, socklen_t optLen);
int interposer_getpeername(NativeSocket sockfd,
    struct sockaddr* __restrict addr, socklen_t* __restrict addrLen);
int interposer_getsockname(NativeSocket sockfd,
    struct sockaddr* __restrict addr, socklen_t* __restrict addrLen);

ssize_t interposer_read(NativeSocket fd, void* buf, size_t count);
ssize_t interposer_recv(NativeSocket sockfd, void* buf, size_t size, int flags);
ssize_t interposer_recvfrom(NativeSocket sockfd, void* buf, size_t size, int flags,
    struct sockaddr* __restrict src_addr, socklen_t* __restrict addrlen);
ssize_t interposer_recvmsg(NativeSocket sockfd, struct msghdr* msg, int flags);

ssize_t interposer_write(NativeSocket fd, const void* buf, size_t count);
ssize_t interposer_send(NativeSocket sockfd, const void* buf, size_t size, int flags);
ssize_t interposer_sendto(NativeSocket fd, const void* buf, size_t size, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen);
ssize_t interposer_sendmsg(NativeSocket sockfd, const struct msghdr* msg, int flags);

#if _GNU_SOURCE
int interposer_recvmmsg(NativeSocket sockfd, struct mmsghdr* msgvec,
    unsigned int vlen, int flags, struct timespec* timeout);
int interposer_sendmmsg(NativeSocket sockfd, struct mmsghdr* msgvec,
    unsigned int vlen, int flags);
#endif

#if __cplusplus
} // extern "C"
#endif
