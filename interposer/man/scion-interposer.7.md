% scion-interposer(7) Version 0.0.1 | SCION++ Manual

## NAME ##

scion-interposer.so - emulates OS-native SCION support by intercepting socket I/O calls

## SYNOPSIS ##

LD_PRELOAD=/usr/lib/scion-interposer.so \[application\]

## DESCRIPTION ##

The SCION Interposer is a library that overrides socket I/O syscall wrappers and other
socket-related functions in libc with wrappers that support the pseudo address-family AF_SCION.
Additionally, the interposer can encode SCION-addresses as AF_INET6 IPv6 addresses similar to
scitra-tun(8) or with local surrogate addresses.

The interposer is applied to a target application by loading it using the LD_PRELOAD environment
configuration variable of the dynamic linker. As such the interposer is only suitable for
applications that dynamically link against libc. The interposer is configured using a configuration
file and a set of environment variables with the prefix `SCION_*`.

**Addressing Modes**

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

## CONFIGURATION ##

The interposer reads configuration files in TOML format. System-wide configuration is expected in
/etc/scion/interposer.toml, with an instance-specific configuration file given by the environment
variable SCION_CONFIG. Settings from the instance-specific configuration file override the
system-wide defaults.

The configuration file is organized in sections that apply to different applications. Additionally,
there is a **default** section that contains default options that may or may not be overridden by
an application-specific section.

Default and applications-specific sections may contain the following options:

* `log_level` Verbosity of logs. One of TRACE, INFO, WARN, ERROR, FATAL. Default: WARN

* `address_mode` Preferred addressing mode. One of NATIVE_SCION and ADDRESS_MAPPING.
    Default: ADDRESS_MAPPING

* `extendedAddressMapping` Boolean. Enable support for SCION-mapped IPv6 addresses and surrogate
    addresses in getnameinfo(3), inet_pton(3), and inet_ntop(3). Default: false

* `allowPromoteOnSendTo` Boolean. Promote unconnected UDP sockets when sending to a SCION address
    for the first time. UDP sockets connecting or binding to a SCION address are always promoted.
    Default: false

* `default_ipv4`, `default_ipv6` Default IP address to be used with SCION if the socket is bound to
    a wildcard IP.

* `addresses` Predefined surrogate addresses. A mapping between SCION addresses and surrogate IPv6
    addresses. By convention surrogate IP addresses should be from fc00::/64. The interposer can
    still add additional surrogate addresses if necessary. Predefining an address is useful for
    binding to a SCION address that cannot be expressed as SCION-mapped IPv6.

* `selector` Path to a dynamically loaded path selector.

* `selector_args` Argument string that is passed to the path selector on initialization. The syntax
    and semantics of the string are defined by the path selector.

Default and applications-specific sections may contain the following subsections:

* `scion` SCION end host options.

    * `connect_to_daemon` Boolean. Whether to connect to an external SCION daemon. Default: true

    * `daemon_address` String. Address string of the SCION daemon passed to gRPC.
        Default: 127.0.0.1:30255

Applications-specific sections must contain a `match` attribute in order to be useful. `match` is a
regular expression that is matched against the full path of the binary the interposer has been
loaded in, e.g., "/usr/bin/iperf3".

**Example**

```
[default]
log_level = "INFO"
address_mode = "ADDRESS_MAPPING"
default_ipv4 = "127.0.0.1"
default_ipv6 = "::1"
addresses = [
    { address = "0-0,127.0.0.1", surrogate = "fc00::" }
]
selector = ""
selector_args = ""

[default.scion]
connect_to_daemon = true
daemon_address = "127.0.0.1:30255"

[nc]
match = "/usr/bin/nc\\..*"
log_level = "TRACE"
```

## ENVIRONMENT ##

The SCION Interposer uses to following environment variables:

* `SCION_CONFIG` Path to an additional configuration file.

* `SCION_ASSUME_APPLICATION` String that the **match** attribute of application-specific
    configurations must match. By default this is the full path of the application binary.

Settings from the configuration file(s) can be overridden with environment variables:

* `SCION_DAEMON_ADDRESS` Overrides `daemon_address`.
* `SCION_LOG_LEVEL` Overrides `log_level`.
* `SCION_ADDRESS_MODE` Overrides `address_mode`.
* `SCION_EXTENDED_ADDRESS_MAPPING` Overrides `extendedAddressMapping`.
* `SCION_PROMOTE_ON_SENDTO` Overrides `allowPromoteOnSendTo`.
* `SCION_DEFAULT_IPV4`, `SCION_DEFAULT_IPV6` Override `default_ipv4` and `default_ipv6`.
* `SCION_SELECTOR` Overrides `selector`.
* `SCION_SELECTOR_ARGS` Overrides `selector_args`.

## INTERCEPTED FUNCTIONS ##

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

## AUTHOR ##

Lars-Christian Schulz <lschulz@ovgu.de>

## SEE ALSO ##

libc(7), ld.so(8), getaddrinfo(3), sockaddr(3type), scitra-tun(8), socket(7), ip(7), ipv6(7)
