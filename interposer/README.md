SCION Interposer
================

The SCION Interposer is a library that overrides socket I/O syscall wrappers and other
socket-related functions in libc with wrappers that support the pseudo address-family AF_SCION.
Additionally, the interposer can encode SCION-addresses as AF_INET6 IPv6 addresses.

The interposer is applied to a target application by loading it using the LD_PRELOAD environment
configuration variable of the dynamic linker. As such the interposer is only suitable for
applications that dynamically link against libc. The interposer is configured using a configuration
file and a set of environment variables with the prefix `SCION_*`.

### Addressing Modes ###

SCION addresses may be presented to client code in different ways depending on the interposer's
configuration and parameters supplied to the intercepted function calls. The addressing modes are:

1. **Native SCION** (`NATIVE_SCION`): SCION addresses are represented using `struct scion_addr` and
    `struct sockaddr_scion`. `struct sockaddr_scion` is a valid as instance of sockaddr(3type) in
    all intercepted functions. sockaddr_scion contains the full SCION ISD-ASN and IPv4 or IPv6 host
    address.
2. **Mapped to IPv6** (`ADDRESS_MAPPING`): In this mode, SCION addresses are represented by
    `struct in6_addr` and `struct sockaddr_in6` as IPv6 addresses. Depending on the kind of SCION
    address used, there are two sub-modes:
    * **SCION-mapped IPv6 addresses**: If possible SCION addresses are represented using the same
    static global mapping as used by scitra-tun(8) and scion2ip(1).
    * **Local Surrogate addresses**: If a static mapping is not possible, a surrogate address is
    allocated from a local pool. Surrogate addresses do not make sense outside of the application
    using the interposer, but can represent SCION addresses that have no SCION-mapped IPv6
    equivalent.

## Intercepted Functions ##

The interposer intercepts to following functions:

* int getaddrinfo(const char* restrict name,
    const char* restrict service,
    const struct addrinfo* restrict hints,
    struct addrinfo** restrict res)

* void freeaddrinfo(struct addrinfo* res)

* int getnameinfo(const sockaddr* restrict addr, socklen_t addrlen,
    char* restrict host, socklen_t hostlen,
    char* restrict serv, socklen_t servlen, int flags)

* int inet_pton(int af, const char* restrict src, void* restrict dst)

* const char* inet_ntop(int af, const void* restrict src,
    char* restrict dst, socklen_t size)

* int socket(int domain, int type, int protocol)

* int bind(int sockfd, const struct sockaddr* addr, socklen_t addrLen)

* int connect(int sockfd, const struct sockaddr* addr, socklen_t addrLen)

* int close(int sockfd)

* int getsockopt(int sockfd, int level, int optname,
    void* optval, socklen_t* restrict optLen)

* int setsockopt(int sockfd, int level, int optname,
    const void* optval, socklen_t optLen)

* int getpeername(int sockfd,
    struct sockaddr* restrict addr, socklen_t* restrict addrLen)

* int getsockname(int sockfd,
    struct sockaddr* restrict addr, socklen_t* restrict addrLen)

* ssize_t read(int fd, void* buf, size_t count)

* ssize_t recv(int sockfd, void* buf, size_t size, int flags)

* ssize_t recvfrom(int sockfd, void* buf, size_t size, int flags,
    struct sockaddr* restrict src_addr, socklen_t* restrict addrlen)

* ssize_t recvmsg(int sockfd, struct msghdr* msg, int flags)

* ssize_t write(int fd, const void* buf, size_t count)

* ssize_t send(int sockfd, const void* buf, size_t size, int flags)

* ssize_t sendto(int sockfd, const void* buf, size_t size, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen)

* ssize_t sendmsg(int sockfd, const struct msghdr* msg, int flags)

* int recvmmsg(int sockfd, struct mmsghdr* msgvec,
    unsigned int vlen, int flags, struct timespec* timeout)

* int sendmmsg(int sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags)
