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
#include "interposer.hpp"
#include "builtin_selector.h"

#include <ares.h>

#include <netinet/ip.h>
#include <netinet/udp.h>


#if TESTING
#define SYS_GETADDRINFO getaddrinfo
#define SYS_FREEADDRINFO freeaddrinfo
#define SYS_GETNAMEINFO getnameinfo
#define SYS_INET_PTON inet_pton
#define SYS_INET_NTOP inet_ntop
#define SYS_SOCKET socket
#define SYS_BIND bind
#define SYS_CONNECT connect
#define SYS_CLOSE close
#define SYS_GETSOCKOPT getsockopt
#define SYS_SETSOCKOPT setsockopt
#define SYS_GETPEERNAME getpeername
#define SYS_GETSOCKNAME getsockname
#define SYS_RECV recv
#define SYS_RECVFROM recvfrom
#define SYS_RECVMSG recvmsg
#define SYS_READ read
#define SYS_WRITE write
#define SYS_SEND send
#define SYS_SENDTO sendto
#define SYS_SENDMSG sendmsg
#if _GNU_SOURCE
#define SYS_RECVMMSG recvmmsg
#define SYS_SENDMMSG sendmmsg
#endif
#else
#define SYS_GETADDRINFO libc_getaddrinfo
#define SYS_FREEADDRINFO libc_freeaddrinfo
#define SYS_GETNAMEINFO libc_getnameinfo
#define SYS_INET_PTON libc_inet_pton
#define SYS_INET_NTOP libc_inet_ntop
#define SYS_SOCKET libc_socket
#define SYS_BIND libc_bind
#define SYS_CONNECT libc_connect
#define SYS_CLOSE libc_close
#define SYS_GETSOCKOPT libc_getsockopt
#define SYS_SETSOCKOPT libc_setsockopt
#define SYS_GETPEERNAME libc_getpeername
#define SYS_GETSOCKNAME libc_getsockname
#define SYS_RECV libc_recv
#define SYS_RECVFROM libc_recvfrom
#define SYS_RECVMSG libc_recvmsg
#define SYS_READ libc_read
#define SYS_WRITE libc_write
#define SYS_SEND libc_send
#define SYS_SENDTO libc_sendto
#define SYS_SENDMSG libc_sendmsg
#if _GNU_SOURCE
#define SYS_RECVMMSG libc_recvmmsg
#define SYS_SENDMMSG libc_sendmmsg
#endif
#endif

// Size of packet buffers for receiveing and in some cases sending SCION
// packets. 9000 bytes matches the buffer size of the Go border router.
static constexpr size_t SCION_BUFFER_SIZE = 9000;

/////////////
// Helpers //
/////////////

static void* copy_c_struct(void* src, size_t size)
{
    assert(src);
    void* copy = std::malloc(size);
    if (!copy) return nullptr;
    std::memcpy(copy, src, size);
    return copy;
};

static char* copy_c_string(char* src)
{
    assert(src);
    char* copy = reinterpret_cast<char*>(std::malloc(std::strlen(src)));
    if (!copy) return nullptr;
    std::strcpy(copy, src);
    return copy;
}

////////////////
// Interposer //
////////////////

extern "C" void stop_interposer();

Interposer::Interposer(const Options& opts)
    : mode(opts.addressMode)
    , extendedAddressMapping(opts.extendedAddressMapping)
    , allowPromoteOnSendTo(opts.allowPromoteOnSendTo)
    , defaultIPv4(opts.defaultIPv4)
    , defaultIPv6(opts.defaultIPv6)
    , connectToDaemon(opts.connectToDaemon)
    , daemonAddress(opts.daemonAddress)
{
    for (auto& [surrogate, address] : opts.surrogates) {
        surrogates.addOrReplace(surrogate, address);
    }
    if (!initializeSelector(selector, opts)) {
        std::exit(EXIT_FAILURE);
    }
}

Interposer::~Interposer()
{
    // Stop intercepting calls before destroying the interposer state.
    // Without this call the interposer deadlocks.
    stop_interposer();
}

ControlPlane* Interposer::cp()
{
    using namespace scion;
    std::lock_guard guard(cpMutex);
    if (controlPlane) return controlPlane.get();

#if TESTING
    controlPlane = std::make_unique<TestCP>();
#else
    controlPlane = std::make_unique<DaemonConn>();
    reinterpret_cast<DaemonConn*>(controlPlane.get())->connect(daemonAddress);
#endif

    if (controlPlane->isConnected()) {
        // Set default MTU
        pmtu.setFirstHopMtu((std::uint16_t)std::min<size_t>(
            controlPlane->asInfo().mtu, SCION_BUFFER_SIZE));
        // Set localhost address in resolver
        if (auto addrFamily = controlPlane->internalAddrFamily(); addrFamily== AF_INET) {
            resolver.setLocalhost(Resolver::AddressSet{
                ScIPAddress(controlPlane->asInfo().isdAsn,
                    generic::IPAddress::MakeIPv4(0x7f000001))
            });
        } else if (addrFamily == AF_INET6) {
            resolver.setLocalhost(Resolver::AddressSet{
                ScIPAddress(controlPlane->asInfo().isdAsn,
                    generic::IPAddress::MakeIPv6(0, 1))
            });
        }
    }
    return controlPlane.get();
}

static std::unique_ptr<Interposer> initialize_interposer()
{
    Options opts;
    loadOptions(opts);
    interposer_set_log_level(opts.logLevel);
    auto tmp = std::make_unique<Interposer>(opts);
    if (tmp->resolver.initialize()) return nullptr;
    return tmp;
};

// Get the global interposer initializing it if necessary.
Interposer* get_interposer()
{
    static std::unique_ptr<Interposer> instance;
    static std::mutex mutex;
    std::lock_guard guard(mutex);
    if (instance) return instance.get();
    if (!(instance = initialize_interposer())) abort();
    return instance.get();
}

// Tries to interpret the given sockaddr as a SCION address by all available
// methods. Returns nullopt if the address can not be interpreted as SCION.
static std::optional<scion::ScIPEndpoint> sockaddr_to_scion(const sockaddr* addr, socklen_t addrLen)
{
    using namespace scion;
    if (addr->sa_family == AF_SCION && addrLen >= sizeof(sockaddr_scion)) {
        return details::endpoint_cast(reinterpret_cast<const sockaddr_scion*>(addr));
    } else if (addr->sa_family == AF_INET6 && addrLen >= sizeof(sockaddr_in6)) {
        auto ep = generic::toGenericEp(*reinterpret_cast<const sockaddr_in6*>(addr));
        if (auto host = get_interposer()->surrogates.getAddress(ep.host()); host.has_value()) {
            return ScIPEndpoint(*host, ep.port());
        } else if (auto host = unmapFromIPv6(ep.host()); host.has_value()) {
            return ScIPEndpoint(*host, ep.port());
        }
    }
    return std::nullopt;
}

// Tries to interpret an IPv6 address as a SCION address by all available
// methods.
static std::optional<scion::ScIPAddress> in6_to_scion(const in6_addr* addr)
{
    using namespace scion;
    auto ip = generic::toGenericAddr(*addr).unmap4in6();
    if (auto host = get_interposer()->surrogates.getAddress(ip); host.has_value()) {
        return *host;
    } else if (auto host = unmapFromIPv6(ip); host.has_value()) {
        return *host;
    }
    return std::nullopt;
}

// Returns an IPv6 address that locally represents a SCION-IP address.
static scion::generic::IPAddress map_scion_to_ipv6(const scion::ScIPAddress& addr)
{
    if (auto mapped = mapToIPv6(addr); mapped.has_value()) {
        return *mapped;
    } else {
        // FIXME: Creating a new surrogate addresses for received packets
        // enables resource exhaustion attacks against unconnected sockets.
        return get_interposer()->surrogates.makeSurrogate(addr).map4in6();
    }
}

// Helper for returning SCION-mapped IPv6 endpoints as sockaddr structs.
static sockaddr_in6 map_scion_to_sockaddr_in6(const scion::ScIPEndpoint& ep)
{
    using namespace scion;
    sockaddr_in6 sa = {};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = details::byteswapBE(ep.port());
    map_scion_to_ipv6(ep.address()).toBytes16(std::span<std::byte, 16>(
        reinterpret_cast<std::byte*>(&sa.sin6_addr), 16));
    return sa;
}

////////////////////////
// Address Resolution //
////////////////////////

// Resolve a service name (e.g., "https" or "443").
int resolve_service(const char* service, const addrinfo* hints, std::uint16_t* res)
{
    addrinfo serviceHints = {};
    if (hints && hints->ai_flags & AI_NUMERICSERV) {
        serviceHints.ai_flags = AI_NUMERICSERV;
    }
    addrinfo* info = nullptr;
    if (int err = SYS_GETADDRINFO(nullptr, service, &serviceHints, &info); err)
        return err;
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(info, SYS_FREEADDRINFO);

    for (auto* node = info; node; node = node->ai_next) {
        if (node->ai_family == AF_INET && node->ai_addrlen == sizeof(sockaddr_in)) {
            if (res) *res = reinterpret_cast<sockaddr_in*>(node->ai_addr)->sin_port;
            return 0;
        } else if (node->ai_family == AF_INET6 && node->ai_addrlen == sizeof(sockaddr_in6)) {
            if (res) *res = reinterpret_cast<sockaddr_in6*>(node->ai_addr)->sin6_port;
            return 0;
        }
    }
    return EAI_NONAME;
}

// Copy the result of getaddrinfo into new structs on the heap that we can free
// with free() instead of freeaddrinfo().
int copy_addrinfo(addrinfo* src, addrinfo** dst, addrinfo** lastAddr)
{
    for (auto* node = src; node; node = node->ai_next) {
        // create new node in output list
        auto* copy = reinterpret_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
        if (!copy) return EAI_MEMORY;
        if (*dst == nullptr) *dst = copy; // initialize head of result list
        // link entries in result list
        if (*lastAddr) (*lastAddr)->ai_next = copy;
        *lastAddr = copy;

        // copy node
        copy->ai_flags = node->ai_flags;
        copy->ai_family = node->ai_family;
        copy->ai_socktype = node->ai_socktype;
        copy->ai_protocol = node->ai_protocol;
        copy->ai_addrlen = node->ai_addrlen;
        copy->ai_addr = reinterpret_cast<sockaddr*>(copy_c_struct(node->ai_addr, node->ai_addrlen));
        if (!copy->ai_addr) return EAI_MEMORY;
        if (node->ai_canonname) {
            copy->ai_canonname = copy_c_string(node->ai_canonname);
            if (!copy->ai_canonname) return EAI_MEMORY;
        }
    }
    return 0;
}

int scion_to_addrinfo(scion::Resolver::AddressSet& addresses, const char* service,
    const addrinfo* hints, AddressMode mode, addrinfo** res, addrinfo** lastAddr)
{
    std::uint16_t port = 0;
    if (service) {
        int err = resolve_service(service, hints, &port);
        if (err) return err;
    }

    for (auto&& addr : addresses) {
        auto* out = reinterpret_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
        if (!out) return EAI_MEMORY;
        if (*res == nullptr) *res = out; // initialize head of result list
        // link entries in result list
        if (*lastAddr) (*lastAddr)->ai_next = out;
        *lastAddr = out;

        if (hints) {
            out->ai_socktype = SOCK_DGRAM; // only DGRAM is supported for now
            out->ai_protocol = hints->ai_protocol;
        }

        if (mode == AddressMode::NATIVE_SCION) {
            out->ai_family = AF_SCION;
            out->ai_addrlen = sizeof(sockaddr_scion);
            out->ai_addr = reinterpret_cast<sockaddr*>(std::calloc(1, sizeof(sockaddr_scion)));
            if (!out->ai_addr) return EAI_MEMORY;
            auto* sa = reinterpret_cast<sockaddr_scion*>(out->ai_addr);
            sa->sscion_family = AF_SCION;
            sa->sscion_addr = scion::details::addr_cast(addr);
            sa->sscion_port = port;
        } else if (mode == AddressMode::ADDRESS_MAPPING) {
            auto mapped = mapToIPv6(addr);
            if (mapped.has_value()) {
                out->ai_family = AF_INET6;
                out->ai_addrlen = sizeof(sockaddr_in6);
                out->ai_addr = reinterpret_cast<sockaddr*>(std::calloc(1, sizeof(sockaddr_in6)));
                if (!out->ai_addr) return EAI_MEMORY;
                auto* sa = reinterpret_cast<sockaddr_in6*>(out->ai_addr);
                sa->sin6_family = AF_INET6;
                auto in6 = scion::generic::toUnderlay<in6_addr>(*mapped);
                assert(in6.has_value());
                sa->sin6_addr = *in6;
                sa->sin6_port = port;
            } else {
                out->ai_family = AF_INET6;
                out->ai_addrlen = sizeof(sockaddr_in6);
                out->ai_addr = reinterpret_cast<sockaddr*>(std::calloc(1, sizeof(sockaddr_in6)));
                if (!out->ai_addr) return EAI_MEMORY;
                auto* sa = reinterpret_cast<sockaddr_in6*>(out->ai_addr);
                sa->sin6_family = AF_INET6;
                auto surrogate = get_interposer()->surrogates.makeSurrogate(addr);
                auto in6 = scion::generic::toUnderlay<in6_addr>(surrogate);
                assert(in6.has_value());
                sa->sin6_addr = *in6;
                sa->sin6_port = port;
            }
        }
    }
    return 0;
}

int ares_to_addrinfo(const ares_addrinfo* info, addrinfo** res, addrinfo** lastAddr)
{
    for (auto* node = info->nodes; node; node = node->ai_next) {
        auto* out = reinterpret_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
        if (!out) return EAI_MEMORY;
        if (*res == nullptr) *res = out; // initialize head of result list

        // link entries in result list
        if (*lastAddr) (*lastAddr)->ai_next = out;
        *lastAddr = out;

        out->ai_flags = node->ai_flags;
        out->ai_family = node->ai_family;
        out->ai_socktype = node->ai_socktype;
        out->ai_protocol = node->ai_protocol;
        out->ai_addrlen = node->ai_addrlen;
        out->ai_addr = reinterpret_cast<sockaddr*>(
            copy_c_struct(node->ai_addr, node->ai_addrlen));
        if (!out->ai_addr) return EAI_MEMORY;
    }
    return 0;
}

// Return address suitable for listening on as requested by getaddrinfo's
// AI_PASSIVE flag.
int get_wildcard_addresses(const char* __restrict name,
    const char* __restrict service,
    const struct addrinfo* __restrict hints,
    struct addrinfo** __restrict res)
{
    using namespace scion;
    auto interposer = get_interposer();
    auto cp = interposer->cp();
    addrinfo* lastAddr = nullptr; // pointer to last addrinfo in result list

    // Preferred SCION bind address
    if ((hints->ai_family == AF_UNSPEC || hints->ai_family == AF_SCION)
        && (hints->ai_socktype == 0 || hints->ai_socktype == SOCK_DGRAM)) {

        std::optional<generic::IPAddress> defaultAddr;
        if (int addrFamily = cp->internalAddrFamily(); addrFamily == AF_INET) {
            if (interposer->defaultIPv4) defaultAddr = interposer->defaultIPv4;
            defaultAddr = posix::details::getDefaultInterfaceAddr4();
        } else if (addrFamily == AF_INET6) {
            if (interposer->defaultIPv6) defaultAddr = interposer->defaultIPv6;
            defaultAddr = posix::details::getDefaultInterfaceAddr6();
        }
        if (!defaultAddr) return EAI_NODATA;

        std::uint16_t port = 0;
        if (service) {
            int err = resolve_service(service, hints, &port);
            if (err) return err;
        }

        *res = reinterpret_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
        if (!res) return EAI_MEMORY;
        (*res)->ai_family = AF_SCION;
        (*res)->ai_socktype = SOCK_DGRAM;
        (*res)->ai_protocol = hints->ai_protocol;
        (*res)->ai_addrlen = sizeof(sockaddr_scion);
        (*res)->ai_addr = reinterpret_cast<sockaddr*>(std::calloc(1, sizeof(sockaddr_scion)));
        if (!(*res)->ai_addr) {
            interposer_freeaddrinfo(*res);
            *res = nullptr;
            return EAI_MEMORY;
        }
        *reinterpret_cast<sockaddr_scion*>((*res)->ai_addr) = details::endpoint_cast(
            ScIPEndpoint(cp->asInfo().isdAsn, generic::IPEndpoint(*defaultAddr, ntohs(port))));
        lastAddr = *res;
    }

    // non-SCION addresses
    if (hints->ai_family != AF_SCION) {
        addrinfo* info = nullptr;
        if (int err = SYS_GETADDRINFO(name, service, hints, &info); err)
            return err;
        std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(info, SYS_FREEADDRINFO);
        if (int err = copy_addrinfo(info, res, &lastAddr); err) {
            interposer_freeaddrinfo(*res);
            *res = nullptr;
            return err;
        }
    }
    return 0;
}

extern "C"
int interposer_getaddrinfo(const char* __restrict name,
    const char* __restrict service,
    const struct addrinfo* __restrict hints,
    struct addrinfo** __restrict res)
{
    using namespace scion;
    auto interposer = get_interposer();

    *res = nullptr;
    auto mode = interposer->mode;

    // if AI_PASSIVE is set getaddrinfo returns addresses for listening on
    if (hints && hints->ai_flags & AI_PASSIVE && !name) {
        return get_wildcard_addresses(name, service, hints, res);
    }

    // prepare c-ares query
    auto channel = reinterpret_cast<ares_channel_t*>(
        details::resolverGetChannel(interposer->resolver));
    bool queryAres = true;
    bool queryScion = true;
    ares_addrinfo_hints aresHints = {};
    if (hints) {
        if (hints->ai_family == AF_SCION)
            queryAres = false;
        else if (hints->ai_family != AF_UNSPEC && hints->ai_family != AF_INET6)
            queryScion = false;
        if (hints->ai_socktype != 0 && hints->ai_socktype != SOCK_DGRAM)
            queryScion = false; // only DGRAM sockets supported so far

        aresHints.ai_family = hints->ai_family & ~AF_SCION;
        aresHints.ai_socktype = hints->ai_socktype;
        aresHints.ai_protocol = hints->ai_protocol;
        if (hints->ai_flags & AI_NUMERICHOST)
            aresHints.ai_flags |= ARES_AI_NUMERICHOST;
        if (hints->ai_flags & AI_NUMERICSERV)
            aresHints.ai_flags |= ARES_AI_NUMERICSERV;
        if (hints->ai_flags & AI_CANONNAME)
            aresHints.ai_flags |= ARES_AI_CANONNAME;
        if ((hints->ai_family & AF_SCION) || (hints->ai_flags & AI_SCION_NATIVE))
            mode = AddressMode::NATIVE_SCION;

        const int ALL_FLAGS = AI_NUMERICHOST | AI_NUMERICSERV | AI_CANONNAME
            | AI_PASSIVE | AI_SCION_NATIVE;
        if (hints->ai_flags & ~ALL_FLAGS) {
            interposer_log(LEVEL_WARN, "Unsupported flag in getaddrinfo (0x%x)",
                hints->ai_flags);
        }
    }

    if (queryScion && !interposer->cp()->isConnected()) {
        queryScion = false; // SCION connection is not available
    }

    // query ares_getaddrinfo and SCION TXT record in parallel
    Maybe<Resolver::AddressSet> scionRes;
    struct QueryResult
    {
        int status;
        std::unique_ptr<ares_addrinfo, void(*)(ares_addrinfo*)> result;
    };
    QueryResult aresRes{ares_status_t::ARES_EOF, {nullptr, &ares_freeaddrinfo}};
    std::promise<QueryResult> promise;
    auto cb = [] (void* arg, int status, int timeouts, ares_addrinfo* result)
    {
        auto promise = reinterpret_cast<std::promise<QueryResult>*>(arg);
        promise->set_value(QueryResult{status, {result, &ares_freeaddrinfo}});
    };
    if (queryAres) ares_getaddrinfo(channel, name, service, &aresHints, cb, &promise);
    if (queryScion) {
        std::string str;
        if (name) str = name;
        scionRes = interposer->resolver.resolveHost(str);
    }
    if (queryAres) aresRes = promise.get_future().get();

    // put SCION addresses at the start of the result list
    addrinfo* lastAddr = nullptr; // pointer to last addrinfo in result list
    if (scionRes.has_value() && !scionRes->empty()) {
        for (auto&& addr : *scionRes) {
            interposer_log(LEVEL_INFO, "Found SCION address for %s (%s): %s",
                name, service, std::format("{}", addr).c_str());
        }
        int err = scion_to_addrinfo(*scionRes, service, hints, mode, res, &lastAddr);
        if (err) {
            interposer_freeaddrinfo(*res);
            *res = nullptr;
        }
    }

    // followed by regular results
    if (aresRes.status == ares_status_t::ARES_SUCCESS) {
        int err = ares_to_addrinfo(aresRes.result.get(), res, &lastAddr);
        if (err != 0 && err != EAI_AGAIN && err != EAI_FAIL && err != EAI_NODATA && err != EAI_NONAME) {
            interposer_freeaddrinfo(*res);
            *res = nullptr;
            return err;
        }
    } else if (*res == nullptr) {
        if (aresRes.status == ARES_ENOTIMP)
            return EAI_FAMILY;
        else if (aresRes.status == ARES_ENOTFOUND)
            return EAI_NONAME;
        else if (aresRes.status == ARES_ESERVICE)
            return EAI_SERVICE;
        else
            return EAI_AGAIN;
    }

    // set cnames
    if (aresRes.result) {
        if (auto* cname = aresRes.result->cnames) {
            for (auto* node = *res; node; node = node->ai_next) {
                node->ai_canonname = copy_c_string(cname->name);
                if (!node->ai_canonname) {
                    interposer_freeaddrinfo(*res);
                    *res = nullptr;
                    return EAI_MEMORY;
                }
            }
        }
    }

    return 0;
}

extern "C"
void interposer_freeaddrinfo(struct addrinfo* res)
{
    addrinfo* node = res;
    addrinfo* next = nullptr;
    while (node) {
        std::free(node->ai_addr);
        std::free(node->ai_canonname);
        next = node->ai_next;
        std::free(node);
        node = next;
    }
}

extern "C"
int interposer_getnameinfo(const sockaddr* __restrict addr, socklen_t addrlen,
    char* __restrict host, socklen_t hostlen,
    char* __restrict serv, socklen_t servlen, int flags)
{
    using namespace scion;
    std::optional<ScIPAddress> scionAddr;
    std::uint16_t portBE = 0;
    if (!addr) {
        errno = EFAULT;
        return EAI_SYSTEM;
    }
    if (addr->sa_family == AF_SCION) {
        if (addrlen < sizeof(sockaddr_scion)) return EAI_FAIL;
        scionAddr = details::addr_cast(&reinterpret_cast<const sockaddr_scion*>(addr)->sscion_addr);
        portBE = reinterpret_cast<const sockaddr_scion*>(addr)->sscion_port;
    } else if (addr->sa_family == AF_INET6 && get_interposer()->extendedAddressMapping) {
        if (addrlen < sizeof(sockaddr_in6)) return EAI_FAIL;
        scionAddr = in6_to_scion(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr);
        portBE = reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port;
        if (scionAddr && hostlen >= INET6_ADDRSTRLEN && hostlen < SCION_ADDRSTRLEN) {
            interposer_log(LEVEL_WARN,
                "Application called getnameinfo with a SCION-mapped IPv6, but the output buffer is"
                " too small. If the application is not behaving as expected try disabling"
                " extendedAddressMapping.");
        }
    }
    if (scionAddr) {
        if (!host && !serv) return EAI_NONAME;
        if (flags & NI_NAMEREQD) {
            return EAI_NONAME; // we can't get hostnames from SCION addresses
        }
        if (host) {
            auto res = std::format_to_n(host, hostlen - 1, "{}", *scionAddr);
            *res.out = '\0';
            if (res.size > (hostlen - 1)) {
                return EAI_OVERFLOW;
            }
        }
        if (serv) {
            sockaddr_in6 portOnly = {};
            portOnly.sin6_family = AF_INET6;
            portOnly.sin6_port = portBE;
            int err = SYS_GETNAMEINFO(reinterpret_cast<sockaddr*>(&portOnly), sizeof(portOnly),
                nullptr, 0, serv, servlen, flags);
            if (err) return err;
        }
        return 0;
    }
    return SYS_GETNAMEINFO(addr, addrlen, host, hostlen, serv, servlen, flags);
}

extern "C"
int interposer_inet_pton(int af, const char* __restrict src, void* __restrict dst)
{
    using namespace scion;
    if (af == AF_SCION) {
        if (auto addr = ScIPAddress::Parse(std::string_view(src, std::strlen(src))); addr) {
            *reinterpret_cast<scion_addr*>(dst) = details::addr_cast(*addr);
            return 1;
        } else {
            return 0;
        }
    } else if (af == AF_INET6 && get_interposer()->extendedAddressMapping) {
        if (auto addr = ScIPAddress::Parse(std::string_view(src, std::strlen(src))); addr) {
            map_scion_to_ipv6(*addr).toBytes16(std::span<std::byte, 16>(
                reinterpret_cast<std::byte*>(dst), 16));
            return 1;
        }
    }
    return SYS_INET_PTON(af, src, dst);
}

extern "C"
const char* interposer_inet_ntop(int af, const void* __restrict src,
    char* __restrict dst, socklen_t size)
{
    using namespace scion;
    std::optional<ScIPAddress> scionAddr;
    if (af == AF_SCION) {
        if (!src) {
            errno = EFAULT;
            return NULL;
        }
        scionAddr = details::addr_cast(reinterpret_cast<const scion_addr*>(src));
    } else if (af == AF_INET6 && get_interposer()->extendedAddressMapping) {
        if (!src) {
            errno = EFAULT;
            return NULL;
        }
        scionAddr = in6_to_scion(reinterpret_cast<const in6_addr*>(src));
        if (scionAddr && size >= INET6_ADDRSTRLEN && size < SCION_ADDRSTRLEN) {
            interposer_log(LEVEL_WARN,
                "Application called inet_ntop with a SCION-mapped IPv6, but the output buffer is"
                " too small. If the application is not behaving as expected try disabling"
                " extendedAddressMapping.");
        }
    }
    if (scionAddr) {
        if (!dst) {
            errno = EFAULT;
            return NULL;
        }
        auto res = std::format_to_n(dst, size - 1, "{}", *scionAddr);
        *res.out = '\0';
        if (res.size > (size - 1)) {
            errno = ENOSPC;
            return NULL;
        }
        return dst;
    } else {
        return SYS_INET_NTOP(af, src, dst, size);
    }
}

//////////////////////
// Socket Lifecycle //
//////////////////////

static int _getsockopt(NativeSocket sockfd, int level, int optname, void* optval, socklen_t* optlen)
{
    #if _WIN32
        auto optvalChar = reinterpret_cast<const char*>(optval);
        if (SYS_GETSOCKOPT(sockfd, level, optname, optvalChar, optlen) == SOCKET_ERROR) {
            return WSAGetLastError();
        }
    #else
        if (SYS_GETSOCKOPT(sockfd, level, optname, optval, optlen) == -1) {
            return errno;
        }
    #endif
        return 0;
}

// Get the domain / address family of the socket. Returns 0 if there is an error.
static int get_socket_family(NativeSocket sockfd)
{
    int domain = 0;
    socklen_t optlen = sizeof(domain);
    if (_getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &domain, &optlen))
        return 0;
    return domain;
}

// Get the type of the socket. Returns 0 if there is an error.
static int get_socket_type(NativeSocket sockfd)
{
    int type = 0;
    socklen_t optlen = sizeof(type);
    if (_getsockopt(sockfd, SOL_SOCKET, SO_TYPE, &type, &optlen))
        return 0;
    return type;
}

// Get the protocol of the socket. Returns 0 if there is an error.
static int get_socket_protocol(NativeSocket sockfd)
{
    int protocol = 0;
    socklen_t optlen = sizeof(protocol);
    if (_getsockopt(sockfd, SOL_SOCKET, SO_PROTOCOL, &protocol, &optlen))
        return 0;
    return protocol;
}

// Get the address the socket is currently bound to (the socket name).
static scion::Maybe<scion::generic::IPEndpoint> get_bound_addr(NativeSocket sockfd)
{
    using namespace scion;
    sockaddr_storage boundAddr;
    socklen_t boundAddrLen = sizeof(boundAddr);
    if (SYS_GETSOCKNAME(sockfd, reinterpret_cast<sockaddr*>(&boundAddr), &boundAddrLen)) {
        return Error(posix::details::getLastError());
    }
    if (boundAddr.ss_family == AF_INET) {
        return generic::toGenericEp(*reinterpret_cast<sockaddr_in*>(&boundAddr));
    } else if (boundAddr.ss_family == AF_INET6) {
        return generic::toGenericEp(*reinterpret_cast<sockaddr_in6*>(&boundAddr));
    } else  {
        return Error(std::error_code(ENOTSUP, std::system_category()));
    }
}

// Enable IPv4-mapped addresses in an IPv6 socket.
static int enable_ipv4in6(NativeSocket sockfd)
{
#if _WIN32
    DWORD v6only = 0;
    auto ptr = reinterpret_cast<const char*>(&v6only);
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, ptr, sizeof(v6only)) == SOCKET_ERROR) {
        return -1;
    }
#else
    int v6only = 0;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == -1) {
        return -1;
    }
#endif
    return 0;
}

// Creates a new SCION socket wrapping a native socket. Returns the native
// socket.
static NativeSocket make_scion_socket(int type, int protocol)
{
    using namespace scion::posix;
    auto interposer = get_interposer();

#if __linux__
    // In Linux, the type argument can contain additional flags
    int realType = type & 0x3fff;
#else
    int realType = type;
#endif

    // Currently only implements UDP/SCION
    if (realType != SOCK_DGRAM || (protocol != 0 && protocol != IPPROTO_UDP)) {
        errno = EINVAL;
        return INVALID_SOCKET_VALUE;
    }

    auto socket = std::make_unique<Socket>(AF_SCION, protocol, IpUdpSocket());
    NativeSocket sockfd = ::socket(AF_INET6, type, protocol);
    auto udp = IpUdpSocket(PosixSocket<>(sockfd));
    if (enable_ipv4in6(sockfd)) {
        return INVALID_SOCKET_VALUE;
    }
    udp.setNextScmpHandler(&interposer->pathCache)->setNextScmpHandler(&interposer->pmtu);
    socket->s = std::move(udp);
    socket->selectorCtx = interposer->selector.notify_created(sockfd, realType, protocol);
    interposer->sockets.emplace(sockfd, std::move(socket));

    interposer_log(LEVEL_INFO, "Created SCION socket %d", sockfd);
    return sockfd;
}

// Wrap a native socket in a SCION socket.
static auto promote_to_scion(NativeSocket sockfd, int family)
{
    using namespace scion;
    auto interposer = get_interposer();

    if (sockfd == scion::posix::INVALID_SOCKET_VALUE) {
        errno = ENOTSOCK;
        return interposer->sockets.end();
    }
    int type = get_socket_type(sockfd);
    if (type != SOCK_DGRAM) {
        errno = EINVAL;
        return interposer->sockets.end();
    }
    int protocol = get_socket_protocol(sockfd);
    if (protocol != 0 && protocol != IPPROTO_UDP) {
        errno = EINVAL;
        return interposer->sockets.end();
    }
    sockaddr_storage boundAddr = {};
    socklen_t boundAddrLen = sizeof(boundAddr);
    if (SYS_GETSOCKNAME(sockfd, reinterpret_cast<sockaddr*>(&boundAddr), &boundAddrLen)) {
        return interposer->sockets.end();
    }

    if (boundAddr.ss_family == AF_INET6) {
        // Ensure that we can use an IPv4 underlay with a v6 socket.
        // Skip this step if the socket is already bound.
        auto sa6 = reinterpret_cast<sockaddr_in6*>(&boundAddr);
        if (IN6_IS_ADDR_UNSPECIFIED(&sa6->sin6_addr) && sa6->sin6_port == 0) {
            if (enable_ipv4in6(sockfd)) {
                interposer_log(LEVEL_ERROR, "Enabling IPv4in6 on socket %d failed", sockfd);
                return interposer->sockets.end();
            }
        }
    }

    interposer_log(LEVEL_INFO, "Promoting socket %d", sockfd);
    auto udp = posix::IpUdpSocket(posix::PosixSocket<>(sockfd));
    auto socket = std::make_unique<Socket>(family, protocol, std::move(udp));
    udp.setNextScmpHandler(&interposer->pathCache)->setNextScmpHandler(&interposer->pmtu);
    socket->selectorCtx = interposer->selector.notify_created(sockfd, type, protocol);

    return interposer->sockets.insert({sockfd, std::move(socket)}).first;
}

static int bind_default_scion(Socket& socket)
{
    using namespace scion;
    auto interposer = get_interposer();
    auto cp = interposer->cp();
    NativeSocket sockfd = std::get<posix::IpUdpSocket>(socket.s).underlaySocket();

    auto bound = get_bound_addr(sockfd);
    if (isError(bound)) {
        errno = bound.error().value();
        return -1;
    }

    auto localIsdAsn = cp->asInfo().isdAsn;
    auto [firstPort, lastPort] = cp->dispatchedPorts();
    if (!bound->host().isUnspecified() || bound->port() != 0) {
        // The socket is bound to an IP address already and is now being
        // promoted to SCION. Combine the local ISD-ASN with the bound address
        // and store in SCION socket.
        if (bound->port() < firstPort || bound->port() > lastPort) {
            interposer_log(LEVEL_WARN, "Socket %d bound outside of dispatched port range", sockfd);
        }
        scion::ScIPEndpoint bindTo(localIsdAsn, *bound);

        if (auto ec = std::get<posix::IpUdpSocket>(socket.s).setLocalEp(bindTo); !ec) {
            interposer_log(LEVEL_INFO, "%s", std::format("Binding socket {} to {}",
                sockfd, bindTo).c_str());
            auto tmp = details::endpoint_cast(bindTo);
            interposer->selector.notify_bind(socket.selectorCtx, sockfd, &tmp);
        } else {
            interposer_log(LEVEL_ERROR, "%s", std::format("Binding socket {} to {} failed: {}",
                sockfd, bindTo, fmtError(ec)).c_str());
            errno = EINVAL;
            return -1;
        }
    } else {
        // Socket has not been bound yet, bind to default SCION address
        generic::IPAddress bindAddr;
        if (get_socket_family(sockfd) == AF_INET) {
            bindAddr = interposer->defaultIPv4.value_or(generic::IPAddress::UnspecifiedIPv4());
        } else {
            if (cp->internalAddrFamily() == AF_INET) {
                bindAddr = interposer->defaultIPv4.value_or(
                    generic::IPAddress::UnspecifiedIPv4()).map4in6();
            } else {
                bindAddr = interposer->defaultIPv6.value_or(generic::IPAddress::UnspecifiedIPv6());
            }
        }
        ScIPEndpoint bindTo(localIsdAsn, bindAddr, 0);

        auto& udp = std::get<posix::IpUdpSocket>(socket.s);
        if (auto ec = udp.bind(bindTo, firstPort, lastPort); !ec) {
            interposer_log(LEVEL_INFO, "%s", std::format("Binding socket {} to {}",
                sockfd, bindTo).c_str());
            if (bound = get_bound_addr(sockfd); bound.has_value()) {
                interposer_log(LEVEL_INFO, "%s",
                    std::format("Socket {} bound to {} (underlay {})",
                        sockfd, std::get<posix::IpUdpSocket>(socket.s).localEp(), *bound).c_str());
                auto tmp = details::endpoint_cast(ScIPEndpoint(localIsdAsn, *bound));
                interposer->selector.notify_bind(socket.selectorCtx, sockfd, &tmp);
            } else {
                interposer_log(LEVEL_ERROR, "%s",
                    std::format("Getting bound address of socket {} failed: {}",
                    sockfd, bindTo, fmtError(ec)).c_str());
                errno = bound.error().value();
                return -1;
            }
        } else {
            interposer_log(LEVEL_ERROR, "%s", std::format("Binding socket {} to {} failed: {}",
                sockfd, bindTo, fmtError(ec)).c_str());
            errno = EADDRNOTAVAIL;
            return -1;
        }
    }

    return 0;
}

extern "C"
NativeSocket interposer_socket(int domain, int type, int protocol)
{
    if (domain == AF_SCION) {
        std::unique_lock guard(get_interposer()->mutex);
        return make_scion_socket(type, protocol);
    }
    return SYS_SOCKET(domain, type, protocol);
}

extern "C"
int interposer_bind(NativeSocket sockfd, const struct sockaddr* addr, socklen_t addrLen)
{
    using namespace scion;
    auto interposer = get_interposer();
    auto cp = interposer->cp();
    std::optional<ScIPEndpoint> bindAddr;

    if (!cp->isConnected()) {
        // SCION not available
        return SYS_BIND(sockfd, addr, addrLen);
    }
    int family = get_socket_family(sockfd);
    if ((family != AF_INET && family != AF_INET6) || get_socket_type(sockfd) != SOCK_DGRAM) {
        return SYS_BIND(sockfd, addr, addrLen);
    }

    std::unique_lock guard(interposer->mutex);
    auto iter = interposer->sockets.find(sockfd);
    if (iter != interposer->sockets.end()) {
        // already a SCION socket, bind address must be AF_SCION
        if (addr->sa_family != AF_SCION || addrLen < sizeof(sockaddr_scion)) {
            errno = EINVAL;
            return -1;
        }
        bindAddr = details::endpoint_cast(reinterpret_cast<const sockaddr_scion*>(addr));
    } else {
        // if the bind addr is interpreted as SCION, try promoting the socket
        bindAddr = sockaddr_to_scion(addr, addrLen);
        if (bindAddr.has_value()) {
            iter = promote_to_scion(sockfd, family);
            if (iter == interposer->sockets.end()) return -1;
        }
    }

    if (iter != interposer->sockets.end()) {
        auto& socket = iter->second;
        auto [firstPort, lastPort] = cp->dispatchedPorts();
        if (!bindAddr->isdAsn().isUnspecified() && bindAddr->isdAsn() != cp->asInfo().isdAsn) {
            errno = EADDRNOTAVAIL;
            return -1;
        }
        if (bindAddr->host().is4() && family == AF_INET6) {
            // bind the IPv6 socket to a v4-mapped IPv6 address
            std::get<posix::IpUdpSocket>(socket->s).underlaySocket();
            bindAddr = ScIPEndpoint(
                bindAddr->isdAsn(),
                bindAddr->host().map4in6(),
                bindAddr->port());
        }
        interposer_log(LEVEL_INFO, "%s",
            std::format("Binding socket {} to {}", sockfd, *bindAddr).c_str());
        std::unique_lock<std::mutex> socketGuard(socket->mutex);
        auto ec = std::get<posix::IpUdpSocket>(socket->s).bind(*bindAddr, firstPort, lastPort);
        if (ec) {
            if (ec.category() == std::system_category())
                errno = ec.value();
            else
                errno = EADDRNOTAVAIL;
            return -1;
        }
        socket->lastDest.reset();
        if (auto bound = get_bound_addr(sockfd); bound.has_value()) {
            interposer_log(LEVEL_INFO, "%s",
                std::format("Socket {} bound to {} (underlay {})",
                    sockfd, std::get<posix::IpUdpSocket>(socket->s).localEp(), *bound).c_str());
            auto tmp = details::endpoint_cast(ScIPEndpoint(bindAddr->isdAsn(), *bound));
            interposer->selector.notify_bind(socket->selectorCtx, sockfd, &tmp);
        } else {
            interposer_log(LEVEL_ERROR, "%s",
                std::format("Getting bound address of socket {} failed: {}",
                sockfd, *bindAddr, fmtError(ec)).c_str());
            errno = bound.error().value();
            return -1;
        }
        return 0;
    } else {
        guard.unlock();
        return SYS_BIND(sockfd, addr, addrLen);
    }
}

extern "C"
int interposer_connect(NativeSocket sockfd, const struct sockaddr* addr, socklen_t addrLen)
{
    using namespace scion;
    auto interposer = get_interposer();
    auto cp = interposer->cp();

    if (!cp->isConnected()) {
        // SCION not available
        return SYS_CONNECT(sockfd, addr, addrLen);
    }
    int family = get_socket_family(sockfd);
    if ((family != AF_INET && family != AF_INET6) || get_socket_type(sockfd) != SOCK_DGRAM) {
        return SYS_CONNECT(sockfd, addr, addrLen);
    }

    std::unique_lock guard(interposer->mutex);
    auto iter = interposer->sockets.find(sockfd);
    auto to = sockaddr_to_scion(addr, addrLen);
    if (iter != interposer->sockets.end()) {
        // already a SCION socket, remote address must be convertible to SCION
        if (!to.has_value()) {
            errno = EINVAL;
            return -1;
        }
        // bind address and port suitable for SCION if not bound already
        if (!std::get<posix::IpUdpSocket>(iter->second->s).localEp().localEp().isFullySpecified()) {
            if (bind_default_scion(*iter->second)) return -1;
        }
    } else if (to.has_value()) {
        // if the remote addr is convertible to SCION, try promoting the socket
        iter = promote_to_scion(sockfd, family);
        if (iter == interposer->sockets.end()) return -1;
        if (bind_default_scion(*iter->second)) return -1;
    }

    if (iter != interposer->sockets.end()) {
        std::unique_lock<std::mutex> socketGuard(iter->second->mutex);
        interposer_log(LEVEL_INFO, "%s",
            std::format("Connecting socket {} to {}", sockfd, *to).c_str());
        if (auto ec = std::get<posix::IpUdpSocket>(iter->second->s).connect(*to); ec) {
            if (ec.category() == std::system_category())
                errno = ec.value();
            else
                errno = EBADF;
            return -1;
        }
        iter->second->lastDest.reset();
        auto tmp = details::endpoint_cast(*to);
        interposer->selector.notify_connect(iter->second->selectorCtx, sockfd, &tmp);
        return 0;
    } else {
        guard.unlock();
        return SYS_CONNECT(sockfd, addr, addrLen);
    }
}

extern "C"
int interposer_close(NativeSocket sockfd)
{
    auto interposer = get_interposer();
    std::unique_lock guard(interposer->mutex);
    auto iter = interposer->sockets.find(sockfd);
    if (iter != interposer->sockets.end()) {
        interposer->selector.notify_close(iter->second->selectorCtx, iter->first);
        interposer->sockets.erase(iter);
        return 0;
    } else {
        guard.unlock();
        return SYS_CLOSE(sockfd);
    }
}

///////////////////////////////
// Socket Getters and Setter //
///////////////////////////////

extern "C"
int interposer_getsockopt(NativeSocket sockfd, int level, int optname,
    void* optval, socklen_t* __restrict optLen)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        std::unique_lock<std::mutex> socketGuard(iter->second->mutex);
        if (level == IPPROTO_IP) {
            if (optname == IP_MTU) {
                if (*optLen != sizeof(int)) {
                    errno = EINVAL;
                    return -1;
                }
                int mtu = 1280;
                if (const auto& lastDest = iter->second->lastDest) {
                    mtu = (int)interposer->pmtu.getMtu(lastDest->dst.host(), *lastDest->path);
                } else {
                    mtu = (int)interposer->cp()->asInfo().mtu;
                }
                *reinterpret_cast<int*>(optval) = mtu;
                return 0;
            }
        } else if (level == IPPROTO_IPV6) {
            if (optname == IPV6_MTU) {
                if (*optLen != sizeof(int)) {
                    errno = EINVAL;
                    return -1;
                }
                int mtu = 1280;
                if (const auto& lastDest = iter->second->lastDest) {
                    mtu = (int)interposer->pmtu.getMtu(lastDest->dst.host(), *lastDest->path);
                } else {
                    mtu = (int)interposer->cp()->asInfo().mtu;
                }
                *reinterpret_cast<int*>(optval) = mtu;
                return 0;
            }
        } else if (level == IPPROTO_UDP) {
    #if __linux__
            if (optname == UDP_CORK || optname == UDP_SEGMENT || optname == UDP_GRO) {
                errno = ENOPROTOOPT;
                return -1;
            }
    #endif
        }
    }
    return SYS_GETSOCKOPT(sockfd, level, optname, optval, optLen);
}

extern "C"
int interposer_setsockopt(NativeSocket sockfd, int level, int optname,
    const void* optval, socklen_t optLen)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        std::unique_lock<std::mutex> socketGuard(iter->second->mutex);
        if (level == IPPROTO_IP) {
            // TODO
        } else if (level == IPPROTO_IPV6) {
            if (optname == IPV6_MTU) {
                // TODO: Set per-socket maximum MTU
                errno = EINVAL;
                return -1;
            }
        } else if (level == IPPROTO_UDP) {
    #if __linux__
            if (optname == UDP_CORK || optname == UDP_SEGMENT || optname == UDP_GRO) {
                errno = ENOPROTOOPT;
                return -1;
            }
    #endif
        }
    }
    return SYS_SETSOCKOPT(sockfd, level, optname, optval, optLen);
}

extern "C"
int interposer_getpeername(NativeSocket sockfd,
    struct sockaddr* __restrict addr, socklen_t* __restrict addrLen)
{
    using namespace scion;
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        std::unique_lock<std::mutex> socketGuard(iter->second->mutex);
        auto remote = std::get<posix::IpUdpSocket>(iter->second->s).remoteEp();
        socketGuard.unlock();
        if (!remote.isFullySpecified()) {
            errno = ENOTCONN;
            return -1;
        }
        if (iter->second->family == AF_SCION) {
            // Return native SCION address
            auto sa = details::endpoint_cast(remote);
            std::memcpy(addr, &sa, std::min(*addrLen, (socklen_t)sizeof(sa)));
            *addrLen = (socklen_t)sizeof(sa);
            return 0;
        } else {
            // Return IPv6-mapped SCION address
            sockaddr_in6 a = map_scion_to_sockaddr_in6(remote);
            std::memcpy(addr, &a, std::min(*addrLen, (socklen_t)sizeof(a)));
            *addrLen = (socklen_t)sizeof(a);
            return 0;
        }
    } else {
        return SYS_GETPEERNAME(sockfd, addr, addrLen);
    }
}

extern "C"
int interposer_getsockname(NativeSocket sockfd,
    struct sockaddr* __restrict addr, socklen_t* __restrict addrLen)
{
    using namespace scion;
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        std::unique_lock<std::mutex> socketGuard(iter->second->mutex);
        auto local = std::get<posix::IpUdpSocket>(iter->second->s).localEp();
        socketGuard.unlock();
        if (iter->second->family == AF_SCION) {
            // Return native SCION address
            auto sa = details::endpoint_cast(local);
            std::memcpy(addr, &sa, std::min(*addrLen, (socklen_t)sizeof(sa)));
            *addrLen = (socklen_t)sizeof(sa);
            return 0;
        } else {
            // Return IPv6-mapped SCION address
            sockaddr_in6 a = map_scion_to_sockaddr_in6(local);
            std::memcpy(addr, &a, std::min(*addrLen, (socklen_t)sizeof(a)));
            *addrLen = (socklen_t)sizeof(a);
            return 0;
        }
    } else {
        return SYS_GETSOCKNAME(sockfd, addr, addrLen);
    }
}

////////////////
// Socket I/O //
////////////////

static scion::PathPtr get_path(Socket& socket, NativeSocket fd,
    const sockaddr_scion* to, const uint8_t* payload, size_t payload_len)
{
    using namespace scion;
    auto interposer = get_interposer();

    auto queryPaths = [interposer] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        using namespace daemon;
        auto cp = interposer->cp();

        std::vector<PathPtr> paths;
        if (auto ec = cp->queryPaths(src, dst, paths); ec) {
            return ec;
        }

        if (interposer->selector.filter_paths) {
            // apply the global path policy
            std::vector<scion_path*> cPaths;
            cPaths.reserve(paths.size());
            for (auto&& path : paths) {
                cPaths.push_back(reinterpret_cast<scion_path*>(path.get()));
            }

            auto newSize = interposer->selector.filter_paths(dst, cPaths.data(), cPaths.size());
            if (newSize > cPaths.size()) {
                interposer_log(LEVEL_FATAL, "Path selector broke contract");
                std::abort();
            }
            cPaths.resize(newSize);

            std::vector<PathPtr> selected;
            selected.reserve(newSize);
            for (scion_path* path : cPaths) {
                selected.push_back(PathPtr(reinterpret_cast<Path*>(path)));
            }
            cache.store(src, dst, selected);
        } else {
            cache.store(src, dst, paths);
        }
        return ErrorCode::Ok;
    };

    IsdAsn dst(details::byteswapBE(to->sscion_addr.sscion_isd_asn));
    auto paths = interposer->pathCache.lookup(interposer->cp()->asInfo().isdAsn, dst, queryPaths);
    if (isError(paths)) {
        interposer_log(LEVEL_WARN, "Path query failed: %s",
            fmtError(paths.error()).c_str());
        return nullptr;
    }
    if (paths->empty()) return nullptr;

    // call path selector
    // TODO: we might be able to get away with reinterpreting PathPtr as scion_path*
    std::vector<scion_path*> cPaths;
    cPaths.reserve(paths->size());
    for (auto&& path : *paths) cPaths.push_back(reinterpret_cast<scion_path*>(path.get()));
    scion_path* path = interposer->selector.select_path(socket.selectorCtx,
        fd, to, cPaths.data(), cPaths.size(), payload, payload_len);
    if (!path) {
        interposer_log(LEVEL_WARN, "%s", std::format("No paths to {}", dst).c_str());
    }
    return PathPtr(reinterpret_cast<Path*>(path));
};

static scion::Maybe<std::span<std::byte>> recv_dgram_impl(
    Socket& socket, std::span<std::byte> pktBuffer, scion::MsgFlags flags,
    struct sockaddr* __restrict src_addr, socklen_t* __restrict addrlen)
{
    using namespace scion;
    auto interposer = get_interposer();
    int sockfd = std::get<posix::IpUdpSocket>(socket.s).underlaySocket();

    ScIPEndpoint from;
    RawPath rp;
    posix::IPEndpoint ulSource;
    auto recvd = std::get<posix::IpUdpSocket>(socket.s).recvFromVia(
        pktBuffer, from, rp, ulSource, flags);
    if (recvd) {
        auto source = details::endpoint_cast(from);
        scion_sel_packet_info info = {
            .from = &source,
            .path = reinterpret_cast<scion_raw_path*>(&rp),
            .underlay = &ulSource.data.generic,
            .underlay_len = sizeof(ulSource.data),
            .payload = reinterpret_cast<const uint8_t*>(recvd->data()),
            .payload_len = recvd->size(),
        };
        interposer->selector.notify_received(socket.selectorCtx, sockfd, &info);
        if (src_addr && addrlen) {
            if (socket.family == AF_SCION) {
                std::memcpy(src_addr, &source, std::min((size_t)*addrlen, sizeof(source)));
                *addrlen = (socklen_t)sizeof(source);
            } else {
                sockaddr_in6 a = map_scion_to_sockaddr_in6(from);
                std::memcpy(src_addr, &a, std::min((size_t)*addrlen, sizeof(a)));
                *addrlen = (socklen_t)sizeof(a);
            }
        }
    }
    return recvd;
}

ssize_t interposer_recvfrom_impl(Socket& socket, void* buf, size_t size, int flags,
    struct sockaddr* __restrict src_addr, socklen_t* __restrict addrlen)
{
    using namespace scion;

    // Temporary buffer receiving tha packet with headers and payload.
    // The payload is later copied into buf, as clients expect to receive just
    // the payload without headers.
    std::array<std::byte, SCION_BUFFER_SIZE> pktBuffer;

    // Fail if unsupported flags are present
    const int SUPPORTED_FLAGS = MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | MSG_WAITALL;
    if (flags & ~SUPPORTED_FLAGS) {
        interposer_log(LEVEL_WARN, "Unsupported flags passed to recv: 0x%x", flags);
        errno = EOPNOTSUPP;
        return -1;
    }

    std::unique_lock<std::mutex> socketGuard(socket.mutex);
    auto recvd = recv_dgram_impl(socket, pktBuffer, static_cast<MsgFlags>(flags & ~MSG_TRUNC),
        src_addr, addrlen);
    if (recvd.has_value()) {
        auto ret = std::min(size, recvd->size());
        std::memcpy(buf, recvd->data(), ret);
        if (flags & MSG_TRUNC)
            return (ssize_t)recvd->size();
        else
            return (ssize_t) ret;
    } else {
        auto ec = recvd.error();
        if (ec.category() == std::system_category()) {
            errno = recvd.error().value();
        } else if (ec.category() == scion_error_category()) {
            if (static_cast<ErrorCode>(ec.value()) == ErrorCode::Timeout) {
                errno = EWOULDBLOCK;
            } else {
                errno = EIO;
            }
        } else {
            errno = EIO;
        }
        return -1;
    }
}

extern "C"
ssize_t interposer_read(NativeSocket fd, void* buf, size_t count)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(fd); iter != interposer->sockets.end()) {
        return interposer_recvfrom_impl(*iter->second, buf, count, 0, nullptr, nullptr);
    } else {
        guard.unlock();
        return SYS_READ(fd, buf, count);
    }
}

extern "C"
ssize_t interposer_recv(NativeSocket sockfd, void* buf, size_t size, int flags)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_recvfrom_impl(*iter->second, buf, size, flags, nullptr, nullptr);
    } else {
        guard.unlock();
        return SYS_RECV(sockfd, buf, size, flags);
    }
}

extern "C"
ssize_t interposer_recvfrom(NativeSocket sockfd, void* buf, size_t size, int flags,
    struct sockaddr* __restrict src_addr, socklen_t* __restrict addrlen)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_recvfrom_impl(*iter->second, buf, size, flags, src_addr, addrlen);
    } else {
        guard.unlock();
        return SYS_RECVFROM(sockfd, buf, size, flags, src_addr, addrlen);
    }
}

static ssize_t interposer_recvmsg_impl(Socket& socket, struct msghdr* msg, int flags)
{
    using namespace scion;
    std::array<std::byte, SCION_BUFFER_SIZE> pktBuffer;

    if (!msg) {
        errno = EFAULT;
        return -1;
    }

    // Fail if unsupported flags are present
    const int SUPPORTED_FLAGS = MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | MSG_WAITALL;
    if (flags & ~SUPPORTED_FLAGS) {
        interposer_log(LEVEL_WARN, "Unsupported flags passed to recv: 0x%x", flags);
        errno = EOPNOTSUPP;
        return -1;
    }

    std::unique_lock<std::mutex> socketGuard(socket.mutex);

    socklen_t addrlen = msg->msg_namelen;
    auto recvd = recv_dgram_impl(socket, pktBuffer, static_cast<MsgFlags>(flags & ~MSG_TRUNC),
        reinterpret_cast<sockaddr*>(msg->msg_name), &addrlen);
    if (recvd) {
        // Copy payload out into scatter output buffers
        std::byte* payload = recvd->data();
        size_t remaining = recvd->size();
        for (size_t i = 0; remaining > 0 && i < msg->msg_iovlen; ++i) {
            size_t n = std::min(msg->msg_iov[i].iov_len, remaining);
            std::memcpy(msg->msg_iov[i].iov_base, payload, n);
            payload += n;
            remaining -= n;
        }

        // Ancillary data not supported
        if (msg->msg_control) {
            msg->msg_control = 0;
        }
        msg->msg_flags = 0;

        if (flags & MSG_TRUNC)
            return (ssize_t)recvd->size();
        else
            return (ssize_t)(recvd->size() - remaining);
    } else {
        auto ec = recvd.error();
        if (ec.category() == std::system_category()) {
            errno = recvd.error().value();
        } else if (ec.category() == scion_error_category()) {
            if (static_cast<ErrorCode>(ec.value()) == ErrorCode::Timeout) {
                errno = EWOULDBLOCK;
            } else {
                errno = EIO;
            }
        } else {
            errno = EIO;
        }
        return -1;
    }
}

extern "C"
ssize_t interposer_recvmsg(NativeSocket sockfd, struct msghdr* msg, int flags)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_recvmsg_impl(*iter->second, msg, flags);
    } else {
        guard.unlock();
        return SYS_RECVMSG(sockfd, msg, flags);
    }
}

// Determine destination address for a UDP datagram.
static ssize_t send_dgram_get_dest(Socket& socket,
    const struct sockaddr* dest_addr, socklen_t addrlen,
    scion::ScIPEndpoint& ep, sockaddr_scion& sa)
{
    using namespace scion;
    if (dest_addr) {
        if (dest_addr->sa_family == AF_SCION && addrlen >= sizeof(sockaddr_scion)) {
            // Full SCION address given
            std::memcpy(&sa, dest_addr, sizeof(sockaddr_scion));
            ep = details::endpoint_cast(&sa);
        } else if (dest_addr->sa_family == AF_INET6 && addrlen >= sizeof(sockaddr_in6)) {
            // Expect SCION-mapped or surrogate IPv6
            if (auto dest = sockaddr_to_scion(dest_addr, addrlen); dest.has_value()) {
                ep = *dest;
                sa = details::endpoint_cast(*dest);
            } else {
                errno = EINVAL;
                return -1;
            }
        } else {
            errno = EINVAL;
            return -1;
        }
    } else {
        // Expect a connected socket
        ep = std::get<posix::IpUdpSocket>(socket.s).remoteEp();
        if (!ep.isFullySpecified()) {
            errno = EDESTADDRREQ;
            return -1;
        }
        sa = details::endpoint_cast(ep);
    }
    return 0;
}

// Select a path and send a single datagram.
static ssize_t send_dgram_impl(Socket& socket, const void* buf, size_t size, scion::MsgFlags flags,
    const scion::ScIPEndpoint& ep, const sockaddr_scion& sa)
{
    using namespace scion;
    auto interposer = get_interposer();
    auto& udp = std::get<posix::IpUdpSocket>(socket.s);
    int sockfd = udp.underlaySocket();

    // Use cached headers when possible and path selector agrees
    bool useCache = false;
    if (socket.lastDest && socket.lastDest->dst == ep) {
        useCache = interposer->selector.select_cached(
            socket.selectorCtx, sockfd, &sa,
            reinterpret_cast<scion_path*>(socket.lastDest->path.get()),
            reinterpret_cast<const uint8_t*>(buf), size);
    }

    Maybe<std::span<const std::byte>> sent;
    if (useCache) {
        size_t mtu = interposer->pmtu.getMtu(
            socket.lastDest->dst.host(), *socket.lastDest->path);
        if (mtu < (socket.headerCache.size() + size)) {
            errno = EMSGSIZE;
            return -1;
        }
        sent = udp.sendToCached(socket.headerCache, ep, socket.lastDest->nh,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), size), flags);
    } else {
        PathPtr path = get_path(socket, sockfd, &sa, reinterpret_cast<const uint8_t*>(buf), size);
        if (!path) {
            errno = EIO;
            return -1;
        }
        size_t mtu = interposer->pmtu.getMtu(ep.host(), *path);
        auto hdrSize = std::get<posix::IpUdpSocket>(socket.s).measureTo(ep, *path);
        if (isError(hdrSize)) {
            errno = EIO;
            return -1;
        }
        if (mtu < (*hdrSize + size)) {
            errno = EMSGSIZE;
            return -1;
        }
        auto nh = *generic::toUnderlay<posix::IPEndpoint>(path->nextHop(ep.localEp()));
        sent = std::get<posix::IpUdpSocket>(socket.s).sendTo(
            socket.headerCache, ep, *path, nh,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), size), flags);
        if (sent) {
            socket.lastDest = CachedDestination{
                .dst = ep,
                .nh = nh,
                .path = path,
            };
        } else {
            socket.lastDest.reset();
        }
    }

    if (sent) {
        return (ssize_t)sent->size();
    } else {
        auto ec = sent.error();
        interposer_log(LEVEL_WARN, "Sending failed: %s", fmtError(ec).c_str());
        if (ec.category() == std::system_category()) {
            errno = ec.value();
        } else if (ec.category() == scion_error_category()) {
            if (static_cast<ErrorCode>(ec.value()) == ErrorCode::Timeout) {
                errno = EWOULDBLOCK;
            } else if (static_cast<ErrorCode>(ec.value()) == ErrorCode::PacketTooBig) {
                errno = EMSGSIZE;
            } else {
                errno = EIO;
            }
        } else {
            errno = EIO;
        }
        return -1;
    }
}

static ssize_t interposer_sendto_impl(Socket& socket, const void* buf, size_t size, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen)
{
    using namespace scion;

    // Fail if unsupported flags are present
    const int SUPPORTED_FLAGS = MSG_CONFIRM | MSG_DONTWAIT | MSG_NOSIGNAL;
    if (flags & ~SUPPORTED_FLAGS) {
        interposer_log(LEVEL_WARN, "Unsupported flags passed to send: 0x%x", flags);
        errno = EOPNOTSUPP;
        return -1;
    }

    std::unique_lock<std::mutex> socketGuard(socket.mutex);
    ScIPEndpoint ep;
    sockaddr_scion sa;
    if (auto err = send_dgram_get_dest(socket, dest_addr, addrlen, ep, sa); err) {
        return err;
    }
    return send_dgram_impl(socket, buf, size, static_cast<MsgFlags>(flags), ep, sa);
}

static int promote_on_sendto(Interposer* interposer, NativeSocket sockfd, int family)
{
    std::unique_lock exclusive(interposer->mutex);
    auto iter = interposer->sockets.find(sockfd);
    if (iter == interposer->sockets.end()) {
        iter = promote_to_scion(sockfd, family);
        if (iter == interposer->sockets.end() || bind_default_scion(*iter->second)) {
            interposer_log(LEVEL_ERROR, "Promoting socket %d in sendto failed", sockfd);
            return -1;
        }
    }
    return 0;
}

extern "C"
ssize_t interposer_write(NativeSocket fd, const void* buf, size_t count)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(fd); iter != interposer->sockets.end()) {
        return interposer_sendto_impl(*iter->second, buf, count, 0, nullptr, 0);
    } else {
        guard.unlock();
        return SYS_WRITE(fd, buf, count);
    }
}

extern "C"
ssize_t interposer_send(NativeSocket sockfd, const void* buf, size_t size, int flags)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_sendto_impl(*iter->second, buf, size, flags, nullptr, 0);
    } else {
        guard.unlock();
        return SYS_SEND(sockfd, buf, size, flags);
    }
}

extern "C"
ssize_t interposer_sendto(NativeSocket sockfd, const void* buf, size_t size, int flags,
    const struct sockaddr* dest_addr, socklen_t addrlen)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_sendto_impl(*iter->second, buf, size, flags, dest_addr, addrlen);
    } else {
        if (interposer->allowPromoteOnSendTo && interposer->cp()->isConnected()) {
            int family = get_socket_family(sockfd);
            if ((family == AF_INET || family == AF_INET6) && get_socket_type(sockfd) == SOCK_DGRAM
                && sockaddr_to_scion(dest_addr, addrlen).has_value()) {
                guard.unlock();
                if (promote_on_sendto(interposer, sockfd, family)) {
                    errno = EAFNOSUPPORT;
                    return -1;
                }
                return interposer_sendto(sockfd, buf, size, flags, dest_addr, addrlen);
            }
        }
        return SYS_SENDTO(sockfd, buf, size, flags, dest_addr, addrlen);
    }
}

static ssize_t interposer_sendmsg_impl(Socket& socket, const struct msghdr* msg, int flags)
{
    using namespace scion;

    // Fail if unsupported flags are present
    const int SUPPORTED_FLAGS = MSG_CONFIRM | MSG_DONTWAIT | MSG_NOSIGNAL;
    if (flags & ~SUPPORTED_FLAGS) {
        interposer_log(LEVEL_WARN, "Unsupported flags passed to send: 0x%x", flags);
        errno = EOPNOTSUPP;
        return -1;
    }

    std::unique_lock<std::mutex> socketGuard(socket.mutex);

    ScIPEndpoint ep;
    sockaddr_scion sa;
    auto err = send_dgram_get_dest(socket,
        reinterpret_cast<const sockaddr*>(msg->msg_name), msg->msg_namelen, ep, sa);
    if (err) return err;

    // Gather payload from all buffers
    size_t size = 0;
    std::array<std::byte, SCION_BUFFER_SIZE> pktBuffer;
    for (size_t i = 0; i < msg->msg_iovlen; ++i) {
        auto n = std::min(msg->msg_iov[i].iov_len, pktBuffer.size() - size);
        if (n < msg->msg_iov[i].iov_len) {
            errno = EMSGSIZE;
            return -1;
        }
        std::memcpy(pktBuffer.data() + size, msg->msg_iov[i].iov_base, n);
        size += n;
    }

    return send_dgram_impl(socket, pktBuffer.data(), size, static_cast<MsgFlags>(flags), ep, sa);
}

extern "C"
ssize_t interposer_sendmsg(NativeSocket sockfd, const struct msghdr* msg, int flags)
{
    using namespace scion;
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);

    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        return interposer_sendmsg_impl(*iter->second, msg, flags);
    } else {
        if (interposer->allowPromoteOnSendTo && interposer->cp()->isConnected()) {
            int family = get_socket_family(sockfd);
            auto dest_addr = reinterpret_cast<const sockaddr*>(msg->msg_name);
            if ((family == AF_INET || family == AF_INET6) && get_socket_type(sockfd) == SOCK_DGRAM
                && sockaddr_to_scion(dest_addr, msg->msg_namelen).has_value()) {
                guard.unlock();
                if (promote_on_sendto(interposer, sockfd, family)) {
                    errno = EAFNOSUPPORT;
                    return -1;
                }
                return interposer_sendmsg(sockfd, msg, flags);
            }
        }
        return SYS_SENDMSG(sockfd, msg, flags);
    }
}


#if _GNU_SOURCE

extern "C"
int interposer_recvmmsg(NativeSocket sockfd, struct mmsghdr* msgvec,
    unsigned int vlen, int flags, struct timespec* timeout)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        if (flags & MSG_WAITFORONE) {
            interposer_log(LEVEL_WARN, "Unsupported flags passed to recvmmsg: 0x%x", flags);
            errno = EOPNOTSUPP;
            return -1;
        }
        for (unsigned int i = 0; i < vlen; ++i) msgvec[i].msg_len = 0;
        for (unsigned int i = 0; i < vlen; ++i) {
            auto recvd = interposer_recvmsg_impl(*iter->second, &msgvec[i].msg_hdr, flags);
            if (recvd >= 0) {
                msgvec[i].msg_len = (unsigned int)recvd;
            } else {
                if (i == 0) return (int)recvd;
                else return (int)i;
            }
        }
        return vlen;
    } else {
        guard.unlock();
        return SYS_RECVMMSG(sockfd, msgvec, vlen, flags, timeout);
    }
}

extern "C"
int interposer_sendmmsg(NativeSocket sockfd, struct mmsghdr* msgvec, unsigned int vlen, int flags)
{
    auto interposer = get_interposer();
    std::shared_lock guard(interposer->mutex);
    if (auto iter = interposer->sockets.find(sockfd); iter != interposer->sockets.end()) {
        for (unsigned int i = 0; i < vlen; ++i) msgvec[i].msg_len = 0;
        for (unsigned int i = 0; i < vlen; ++i) {
            auto sent = interposer_sendmsg_impl(*iter->second, &msgvec[i].msg_hdr, flags);
            if (sent >= 0) {
                msgvec[i].msg_len = (unsigned int)sent;
            } else {
                if (i == 0) return (int)sent;
                else return (int)i;
            }
        }
        return vlen;
    } else {
        guard.unlock();
        return SYS_SENDMMSG(sockfd, msgvec, vlen, flags);
    }
}

#endif // _GNU_SOURCE
