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

#include "scion/scion.h"
#include "scion/details/c_interface.hpp"

#include "scion/addr/address.hpp"
#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/addr/isd_asn.hpp"
#include "scion/asio/udp_socket.hpp"
#include "scion/daemon/client.hpp"
#include "scion/details/bit.hpp"
#include "scion/error_codes.hpp"
#include "scion/path/raw.hpp"
#include "scion/path/shared_cache.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scion/resolver.hpp"
#include "scion/scmp/path_mtu.hpp"

#include <ares.h>
#include <boost/asio.hpp>

#if _WIN32
#include <Iphlpapi.h>
#else
#include <net/if.h>
#endif

#include <chrono>
#include <cstring>
#include <format>
#include <memory>
#include <type_traits>


//////////////////////
// Helper functions //
//////////////////////

static scion_error translate_error(const std::error_code& ec)
{
    using namespace scion;

    if (!ec) return SCION_OK;

    if (ec.category() == scion_error_category()) {
        return static_cast<scion_error>(ec.value());
    } else if (ec.category() == std::system_category()) {
        auto value = ec.value();
        if (value == ECANCELED) {
            return SCION_CANCELLED;
        } else if (value == ECANCELED || value == ENOTSOCK) {
            return SCION_INVALID_SOCKET;
        } else if (value == EDESTADDRREQ) {
            return SCION_NO_LOCAL_HOST_ADDR;
        } else if (value == EAGAIN || value == EWOULDBLOCK) {
            return SCION_WOULD_BLOCK;
        } else {
            return SCION_ERROR;
        }
    } else if (ec.category() == grpc_error_category()) {
        return  SCION_CONTROL_PLANE_RPC_ERROR;
    } else if (ec.category() == cares_error_category()) {
        switch (ec.value()) {
        case ARES_SUCCESS:
            return SCION_OK;
        case ARES_EDESTRUCTION:
        case ARES_ECANCELLED:
            return SCION_CANCELLED;
        case ARES_ETIMEOUT:
            return SCION_TIMEOUT;
        case ARES_ENOTINITIALIZED:
            return SCION_LOGIC_ERROR;
        case ARES_EBADNAME:
            return SCION_INVALID_ARGUMENT;
        case ARES_ENOTFOUND:
            return SCION_NAME_NOT_FOUND;
        case ARES_ENODATA:
        case ARES_EFORMERR:
        case ARES_ESERVFAIL:
        case ARES_ENOTIMP:
        case ARES_EREFUSED:
            return SCION_REMOTE_ERROR;
        default:
            return SCION_ERROR;
        }
    } else {
        return SCION_ERROR;
    }
};

// Copy up to `*dst_len` bytes from `src`to `dst` and set `dst_len` to the
// number of bytes actually copied. Returns SCION_BUFFER_TOO_SMALL if not all
// bytes could be copied.
static scion_error copy_out(void* dst, size_t* dst_len, void* src, size_t src_len)
{
    auto n = std::min(*dst_len, src_len);
    std::memcpy(dst, src, n);
    *dst_len = src_len;
    if (n < src_len) return SCION_BUFFER_TOO_SMALL;
    return SCION_OK;
}

///////////////////////////////////
// scion_addr and sockaddr_scion //
///////////////////////////////////

namespace scion {
namespace details {

scion_addr addr_cast(const scion::ScIPAddress& addr)
{
    using namespace scion;
    scion_addr saddr = {};
    saddr.sscion_host_type = static_cast<scion_host_addr_type>(
        AddressTraits<ScIPAddress::HostAddr>::type(addr.host()));
    if (addr.host().hasZone()) {
        saddr.sscion_scope_id = details::byteswapBE(addr.host().zoneId());
    }
    saddr.sscion_isd_asn = details::byteswapBE((uint64_t)addr.isdAsn());
    if (addr.host().is4()) {
        addr.host().toBytes4(std::span<std::byte, 4>(
            reinterpret_cast<std::byte*>(saddr.u.sscion_addr), 4));
    } else {
        addr.host().toBytes16(std::span<std::byte, 16>(
            reinterpret_cast<std::byte*>(saddr.u.sscion_addr), 16));
    }
    return saddr;
}

scion::ScIPAddress addr_cast(const scion_addr* saddr)
{
    using namespace scion;

    generic::IPAddress host;
    if (saddr->sscion_host_type == SCION_IPv4) {
        host = generic::IPAddress::MakeIPv4(std::span<const std::byte, 4>(
            reinterpret_cast<const std::byte*>(saddr->u.sscion_addr), 4));
    } else if (saddr->sscion_host_type == SCION_IPv6) {
        std::string_view zone;
        if (saddr->sscion_scope_id) {
            char name[IF_NAMESIZE] = {};
            if (if_indextoname(saddr->sscion_scope_id, name)) {
                zone = std::string_view(name, std::strlen(name));
            }
        }
        host = generic::IPAddress::MakeIPv6(std::span<const std::byte, 16>(
            reinterpret_cast<const std::byte*>(saddr->u.sscion_addr), 16), zone);
    } else {
        assert(false);
    }

    return ScIPAddress{
        IsdAsn(details::byteswapBE(saddr->sscion_isd_asn)),
        host
    };
}

sockaddr_scion endpoint_cast(const scion::ScIPEndpoint& ep)
{
    using namespace scion;
    sockaddr_scion sa = {AF_SCION, 0, 0, {}};
    sa.sscion_port = details::byteswapBE(ep.port());
    sa.sscion_addr = addr_cast(ep.address());
    return sa;
}

scion::ScIPEndpoint endpoint_cast(const sockaddr_scion* sa)
{
    using namespace scion;
    return ScIPEndpoint{
        addr_cast(&sa->sscion_addr), details::byteswapBE(sa->sscion_port)
    };
}

} // namespace details
} // namespace scion

////////////
// Errors //
////////////

extern "C" DLLEXPORT
const char* scion_error_string(scion_error err)
{
    switch (err) {
        case SCION_OK:
            return "ok";
        case SCION_CANCELLED:
            return "operation cancelled";
        case SCION_PENDING:
            return "operation pending";
        case SCION_TIMEOUT:
            return "operation timed out";
        case SCION_SCMP_RECEIVED:
            return "received an SCMP packet";
        case SCION_NO_METADATA:
            return "no metadata available";
        case SCION_LOGIC_ERROR:
            return "expected precondition failed";
        case SCION_NOT_IMPLEMENTED:
            return "not implemented";
        case SCION_INVALID_ARGUMENT:
            return "invalid argument";
        case SCION_SYNTAX_ERROR:
            return "syntax error in input";
        case SCION_BUFFER_TOO_SMALL:
            return "provided buffer too small to hold output";
        case SCION_PACKET_TOO_BIG:
            return "packet or payload too big";
        case SCION_REQUIRES_ZONE:
            return "IPv6 address requires zone identifier";
        case SCION_NO_LOCAL_HOST_ADDR:
            return "no suitable underlay host address found";
        case SCION_NAME_NOT_FOUND:
            return "name not found";
        case SCION_REMOTE_ERROR:
            return "remote machine returned an error";
        case SCION_INVALID_PACKET:
            return "received an invalid packet";
        case SCION_CHECKSUM_ERROR:
            return "packet checksum incorrect";
        case SCION_DST_ADDR_MISMATCH:
            return "packet rejected because of unexpected destination address";
        case SCION_SRC_ADDR_MISMATCH:
            return "packet rejected because of unexpected source address";
        case SCION_WOULD_BLOCK:
            return "nonblocking operation would block";
        case SCION_CONTROL_PLANE_RPC_ERROR:
            return "error in communication with control plane services";
        case SCION_ERROR:
            return "operation failed";
        default:
            return "unexpected error code";
    }
}

///////////
// Clock //
///////////

extern "C" DLLEXPORT
uint64_t scion_time_utc()
{
    using namespace std::chrono;
    return std::uint64_t(duration_cast<nanoseconds>(
        utc_clock::now().time_since_epoch()).count());
}

extern "C" DLLEXPORT
uint64_t scion_time_steady()
{
    using namespace std::chrono;
    return std::uint64_t(duration_cast<nanoseconds>(
        steady_clock::now().time_since_epoch()).count());
}

//////////
// SCMP //
//////////

class CScmpHandler : public scion::ScmpHandlerImpl
{
public:
    scion_scmp_handler callback = nullptr;
    void* user_ptr = nullptr;

    virtual bool handleScmpCallback(
        const scion::ScIPAddress& from,
        const scion::RawPath& path,
        const scion::hdr::ScmpMessage& msg,
        std::span<const std::byte> payload)
    {
        using namespace scion;

        scion_scmp_message message = {
            .type = SCION_SCMP_UNKNOWN,
            .params = {},
            .from = details::addr_cast(from),
            .path = reinterpret_cast<const scion_raw_path*>(&path),
            .payload = reinterpret_cast<const uint8_t*>(payload.data()),
            .payload_len = payload.size(),
        };

        std::visit([&] (auto&& msg) {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, hdr::ScmpUnknownError>) {
                message.type = SCION_SCMP_UNKNOWN;
                message.params.unknown = scion_scmp_unknown{
                    .code = msg.code,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpDstUnreach>) {
                message.type = SCION_SCMP_DST_UNREACH;
                message.params.dst_unreach = scion_scmp_dst_unreach{
                    .code = msg.code,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpPacketTooBig>) {
                message.type = SCION_SCMP_PACKET_TOO_BIG;
                message.params.packet_too_big = scion_scmp_packet_too_big{
                    .code = msg.code,
                    .mtu = msg.mtu,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpParamProblem>) {
                message.type = SCION_SCMP_PARAM_PROBLEM;
                message.params.param_problem = scion_scmp_param_problem{
                    .code = msg.code,
                    .pointer = msg.pointer,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpExtIfDown>) {
                message.type = SCION_SCMP_EXT_IF_DOWN;
                message.params.ext_if_down = scion_scmp_ext_if_down{
                    .code = msg.code,
                    .sender = msg.sender,
                    .iface = msg.iface,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpIntConnDown>) {
                message.type = SCION_SCMP_INT_CONN_DOWN;
                message.params.int_conn_down = scion_scmp_int_conn_down{
                    .code = msg.code,
                    .sender = msg.sender,
                    .ingress = msg.ingress,
                    .egress = msg.egress,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpEchoRequest>) {
                message.type = SCION_SCMP_ECHO_REQUEST;
                message.params.echo = scion_scmp_echo{
                    .code = msg.code,
                    .id = msg.id,
                    .seq = msg.seq,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpEchoReply>) {
                message.type = SCION_SCMP_ECHO_REPLY;
                message.params.echo = scion_scmp_echo{
                    .code = msg.code,
                    .id = msg.id,
                    .seq = msg.seq,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpTraceRequest>) {
                message.type = SCION_SCMP_TRACE_REQUEST;
                message.params.traceroute = scion_scmp_traceroute{
                    .code = msg.code,
                    .id = msg.id,
                    .seq = msg.seq,
                };
            } else if constexpr (std::is_same_v<T, hdr::ScmpTraceReply>) {
                message.type = SCION_SCMP_TRACE_REPLY;
                message.params.traceroute = scion_scmp_traceroute{
                    .code = msg.code,
                    .id = msg.id,
                    .seq = msg.seq,
                };
            }
        }, msg);

        callback(&message, user_ptr);
        return true;
    }
};

//////////////////
// Host Context //
//////////////////

struct scion_context_t
{
    boost::asio::io_context ioCtx;
    std::unique_ptr<scion::daemon::GrpcDaemonClient> daemonClient;
    scion::daemon::AsInfo localAS;
    scion::daemon::PortRange scionPorts;
    scion::Resolver resolver;
    scion::SharedPathCache pathCache;
    std::unique_ptr<scion::PathMtuDiscoverer<>> pmtu;
    CScmpHandler scmpHandler;
};

extern "C" DLLEXPORT
scion_error scion_create_host_context(scion_context** pctx, const scion_context_opts* opts)
{
    using namespace scion;
    auto ctx = std::make_unique<scion_context>();

    if (opts->daemon_address) {
        ctx->daemonClient = std::make_unique<scion::daemon::GrpcDaemonClient>(
            grpc::string(opts->daemon_address));
        auto asInfo = ctx->daemonClient->rpcAsInfo(IsdAsn());
        if (isError(asInfo)) {
            return translate_error(getError(asInfo));
        }
        ctx->localAS = *asInfo;
        if (opts->default_isd_asn) {
            ctx->localAS.isdAsn = IsdAsn(opts->default_isd_asn);
        }
        if (opts->ports_begin == 0 && opts->ports_end == 0) {
            auto ports = ctx->daemonClient->rpcPortRange();
            if (isError(ports)) {
                return translate_error(getError(ports));
            }
            ctx->scionPorts = *ports;
        } else {
            ctx->scionPorts = std::make_pair(opts->ports_begin, opts->ports_end);
        }
    } else {
        ctx->localAS = {
            IsdAsn(opts->default_isd_asn), false, 1280
        };
        ctx->scionPorts = std::make_pair(opts->ports_begin, opts->ports_end);
    }

    if (auto ec = ctx->resolver.initialize(); ec) {
        return translate_error(ec);
    }
    ctx->resolver.setLocalhost({
        ScIPAddress(ctx->localAS.isdAsn, generic::IPAddress::MakeIPv4(0x7f000001)),
        ScIPAddress(ctx->localAS.isdAsn, generic::IPAddress::MakeIPv6(0, 1))
    });
    ctx->scmpHandler.setNextScmpHandler(&ctx->pathCache);

    if (opts->flags & SCION_HOST_CTX_MTU_DISCOVER) {
        ctx->pmtu = std::make_unique<scion::PathMtuDiscoverer<>>(ctx->localAS.mtu);
        ctx->pathCache.setNextScmpHandler(ctx->pmtu.get());
    }

    *pctx = ctx.release();
    return SCION_OK;
}

extern "C" DLLEXPORT
void scion_delete_host_context(scion_context* ctx)
{
    if (ctx) delete ctx;
}

extern "C" DLLEXPORT
void* scion_set_scmp_handler(
    scion_context* ctx, scion_scmp_handler handler, void* user_ptr)
{
    auto prev = ctx->scmpHandler.user_ptr;
    ctx->scmpHandler.callback = handler;
    ctx->scmpHandler.user_ptr = user_ptr;
    return prev;
}

extern "C" DLLEXPORT
size_t scion_poll(scion_context* ctx)
{
    return ctx->ioCtx.poll();
}

extern "C" DLLEXPORT
size_t scion_run(scion_context* ctx)
{
    return ctx->ioCtx.run();
}

extern "C" DLLEXPORT
size_t scion_run_for(scion_context* ctx, uint32_t timeout)
{
    return ctx->ioCtx.run_for(std::chrono::milliseconds(timeout));
}

extern "C" DLLEXPORT
void scion_stop(scion_context* ctx)
{
    ctx->ioCtx.stop();
}

extern "C" DLLEXPORT
void scion_restart(scion_context* ctx)
{
    ctx->ioCtx.restart();
}

extern "C" DLLEXPORT
uint16_t scion_discovered_pmtu(scion_context* ctx, scion_path* path, const struct scion_addr* dest)
{
    using namespace scion::generic;
    if (ctx->pmtu) {
        if (dest->sscion_host_type == SCION_IPv4) {
            auto ip = IPAddress::MakeIPv4(std::span<const std::byte, 4>(
                reinterpret_cast<const std::byte*>(&dest->u.sscion_addr), 4));
            return ctx->pmtu->getMtu(ip, *reinterpret_cast<scion::Path*>(path));
        } else if (dest->sscion_host_type == SCION_IPv6) {
            auto ip = IPAddress::MakeIPv6(std::span<const std::byte, 16>(
                reinterpret_cast<const std::byte*>(&dest->u.sscion_addr), 16));
            return ctx->pmtu->getMtu(ip, *reinterpret_cast<scion::Path*>(path));
        } else {
            return 0;
        }
    } else {
        return reinterpret_cast<scion::Path*>(path)->mtu();
    }
}

extern "C" DLLEXPORT
uint16_t scion_discovered_pmtu_raw(
    scion_context* ctx, scion_raw_path* path, const struct scion_addr* dest)
{
    using namespace scion::generic;
    if (ctx->pmtu) {
        if (dest->sscion_host_type == SCION_IPv4) {
            auto ip = IPAddress::MakeIPv4(std::span<const std::byte, 4>(
                reinterpret_cast<const std::byte*>(&dest->u.sscion_addr), 4));
            return ctx->pmtu->getMtu(ip, *reinterpret_cast<scion::RawPath*>(path));
        } else if (dest->sscion_host_type == SCION_IPv6) {
            auto ip = IPAddress::MakeIPv6(std::span<const std::byte, 16>(
                reinterpret_cast<const std::byte*>(&dest->u.sscion_addr), 16));
            return ctx->pmtu->getMtu(ip, *reinterpret_cast<scion::RawPath*>(path));
        }
    }
    return 0;
}

///////////////
// Addresses //
///////////////

extern "C" DLLEXPORT
bool scion_addr_are_equal(const scion_addr* a, const scion_addr* b)
{
    return a->sscion_host_type == b->sscion_host_type
        && a->sscion_isd_asn == b->sscion_isd_asn
        && a->sscion_scope_id == b->sscion_scope_id
        && std::memcmp(a->u.sscion_addr, b->u.sscion_addr, 16) == 0;
}

extern "C" DLLEXPORT
bool scion_sockaddr_are_equal(const sockaddr_scion* a, const sockaddr_scion* b)
{
    return a->sscion_family == b->sscion_family
        && a->sscion_port == b->sscion_port
        && a->sscion_flowinfo == b->sscion_flowinfo
        && scion_addr_are_equal(&a->sscion_addr, &b->sscion_addr);
}

extern "C" DLLEXPORT
scion_error scion_sockaddr_get_host(
    const struct sockaddr_scion* saddr, struct sockaddr* host, socklen_t host_len)
{
    std::memset(host, 0, host_len);
    if (saddr->sscion_addr.sscion_host_type == SCION_IPv4) {
        if (host_len < sizeof(sockaddr_in)) return SCION_BUFFER_TOO_SMALL;
        host->sa_family = AF_INET;
        auto in4 = reinterpret_cast<sockaddr_in*>(host);
        std::memcpy(&in4->sin_addr, saddr->sscion_addr.u.sscion_addr, 4);
        in4->sin_port = saddr->sscion_port;
        return SCION_OK;
    } else if (saddr->sscion_addr.sscion_host_type == SCION_IPv6) {
        if (host_len < sizeof(sockaddr_in6)) return SCION_BUFFER_TOO_SMALL;
        host->sa_family = AF_INET6;
        auto in6 = reinterpret_cast<sockaddr_in6*>(host);
        std::memcpy(&in6->sin6_addr, saddr->sscion_addr.u.sscion_addr, 16);
        in6->sin6_flowinfo = saddr->sscion_flowinfo;
        in6->sin6_scope_id = saddr->sscion_addr.sscion_scope_id;
        in6->sin6_port = saddr->sscion_port;
        return SCION_OK;
    } else {
        return SCION_INVALID_ARGUMENT;
    }
}

extern "C" DLLEXPORT
scion_error scion_split_host_port(
    const char* addr, const char** host, size_t* host_len, uint16_t* port)
{
    auto res = scion::details::splitHostPort(std::string_view(addr, std::strlen(addr)));
    if (res.has_value()) {
        *host = res->first.data();
        *host_len = res->first.size();
        *port = res->second;
        return SCION_OK;
    } else {
        return translate_error(scion::getError(res));
    }
}

extern "C" DLLEXPORT
scion_error scion_parse_host(const char* host, scion_addr* addr)
{
    auto res = scion::ScIPAddress::Parse(std::string_view(host, std::strlen(host)));
    if (res.has_value()) {
        *addr = scion::details::addr_cast(*res);
        return SCION_OK;
    } else {
        return SCION_SYNTAX_ERROR;
    }
}

extern "C" DLLEXPORT
scion_error scion_parse_ep(const char* endpoint, sockaddr_scion* sockaddr)
{
    auto res = scion::ScIPEndpoint::Parse(std::string_view(endpoint, std::strlen(endpoint)));
    if (res.has_value()) {
        *sockaddr = scion::details::endpoint_cast(*res);
        return SCION_OK;
    } else {
        return SCION_SYNTAX_ERROR;
    }
}

extern "C" DLLEXPORT
scion_error scion_print_host(const scion_addr* addr, char* buffer, size_t* buffer_len)
{
    using namespace scion::details;
    if (*buffer_len == 0) {
        *buffer_len = std::formatted_size("{}", addr_cast(addr)) + 1;
        return SCION_BUFFER_TOO_SMALL;
    }
    auto res = std::format_to_n(buffer, *buffer_len - 1, "{}", addr_cast(addr));
    *res.out = '\0';
    scion_error err = SCION_OK;
    if (*buffer_len < (size_t)(res.size + 1)) {
        err = SCION_BUFFER_TOO_SMALL;
    }
    *buffer_len = res.size + 1;
    return err;
}

extern "C" DLLEXPORT
scion_error scion_print_ep(const sockaddr_scion* addr, char* buffer, size_t* buffer_len)
{
    using namespace scion::details;
    if (*buffer_len == 0) {
        *buffer_len = std::formatted_size("{}", endpoint_cast(addr)) + 1;
        return SCION_BUFFER_TOO_SMALL;
    }
    auto res = std::format_to_n(buffer, *buffer_len - 1, "{}", endpoint_cast(addr));
    *res.out = '\0';
    scion_error err = SCION_OK;
    if (*buffer_len < (size_t)(res.size + 1)) {
        err = SCION_BUFFER_TOO_SMALL;
    }
    *buffer_len = res.size + 1;
    return err;
}

/////////////////////
// Name Resolution //
/////////////////////

extern "C" DLLEXPORT
scion_error scion_resolve_name(scion_context* ctx,
    const char* name, struct sockaddr_scion* res, size_t* res_len)
{
    auto addresses = ctx->resolver.resolveService(std::string_view(name, std::strlen(name)));
    if (isError(addresses)) return SCION_NAME_NOT_FOUND;

    size_t i = 0;
    for (auto& ep : *addresses) {
        if (i >= *res_len) break;
        res[i++] = scion::details::endpoint_cast(ep);
    }
    *res_len = addresses->size();
    if (i < *res_len) return SCION_BUFFER_TOO_SMALL;
    return SCION_OK;
}

extern "C" DLLEXPORT
void scion_resolve_name_async(scion_context* ctx,
    const char* name, struct sockaddr_scion* res, size_t* res_len,
    scion_async_resolve_handler handler)
{
    using namespace scion;

    auto split = ctx->resolver.splitHostPort(name);
    if (isError(split)) {
        handler.callback(translate_error(split.error()), handler.user_ptr);
        return;
    }
    auto [host, port] = *split;

    ctx->resolver.resolveHostAsync(std::string(name), ctx->ioCtx, [=] (auto addresses) {
        if (isError(addresses)) {
            handler.callback(translate_error(addresses.error()), handler.user_ptr);
            return;
        }
        size_t i = 0;
        for (auto&& host : *addresses) {
            if (i >= *res_len) break;
            res[i++] = sockaddr_scion{
                .sscion_family = AF_SCION,
                .sscion_port = port,
                .sscion_flowinfo = 0,
                .sscion_addr = details::addr_cast(host)
            };
        }
        *res_len = addresses->size();
        scion_error status = SCION_OK;
        if (i < *res_len) status = SCION_BUFFER_TOO_SMALL;
        handler.callback(status, handler.user_ptr);
    });
}

///////////
// Paths //
///////////

extern "C" DLLEXPORT
scion_error scion_query_paths(
    scion_context* ctx, uint64_t dst, scion_path** paths, size_t* paths_len)
{
    using namespace scion;

    auto queryPaths = [ctx] (SharedPathCache& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        using namespace daemon;
        std::vector<PathPtr> paths;
        auto flags = PathReqFlags::Refresh | PathReqFlags::AllMetadata;
        ctx->daemonClient->rpcPaths(src, dst, flags, std::back_inserter(paths));
        cache.store(src, dst, std::move(paths));
        return ErrorCode::Ok;
    };
    auto res = ctx->pathCache.lookup(ctx->localAS.isdAsn, IsdAsn(dst), queryPaths);
    if (isError(res)) {
        return translate_error(getError(res));
    }

    size_t i = 0;
    for (auto&& path : *res) {
        if (i >= *paths_len) break;
        paths[i++] = reinterpret_cast<scion_path*>(path.detach());
    }
    *paths_len = res->size();
    if (i < *paths_len) return SCION_BUFFER_TOO_SMALL;
    return SCION_OK;
}

extern "C" DLLEXPORT
void scion_release_paths(scion_path** paths, size_t paths_len)
{
    using namespace scion;
    for (size_t i = 0; i < paths_len; ++i) {
        if (paths[i]) {
            intrusive_ptr_release(reinterpret_cast<Path*>(paths[i]));
            paths[i] = nullptr;
        }
    }
}

extern "C" DLLEXPORT
uint64_t scion_path_first_as(scion_path* path)
{
    return reinterpret_cast<scion::Path*>(path)->firstAS();
}

extern "C" DLLEXPORT
uint64_t scion_path_last_as(scion_path* path)
{
    return reinterpret_cast<scion::Path*>(path)->lastAS();
}

extern "C" DLLEXPORT
scion_ptype scion_path_type(scion_path* path)
{
    return static_cast<scion_ptype>(reinterpret_cast<scion::Path*>(path)->type());
}

extern "C" DLLEXPORT
uint64_t scion_path_expiry(scion_path* path)
{
    using namespace std::chrono;
    auto expiry = reinterpret_cast<scion::Path*>(path)->expiry().time_since_epoch();
    return duration_cast<nanoseconds>(expiry).count();
}

extern "C" DLLEXPORT
uint16_t scion_path_mtu(scion_path* path)
{
    return reinterpret_cast<scion::Path*>(path)->mtu();
}

extern "C" DLLEXPORT
uint64_t scion_path_broken(scion_path* path)
{
    return reinterpret_cast<scion::Path*>(path)->broken();
}

extern "C" DLLEXPORT
void scion_path_set_broken(scion_path* path, uint64_t broken)
{
    reinterpret_cast<scion::Path*>(path)->setBroken(broken);
}

extern "C" DLLEXPORT
scion_error scion_path_meta_hops(scion_path* path, scion_hop* hops, size_t* hops_len)
{
    using namespace scion;
    auto ifaces = reinterpret_cast<Path*>(path)->getAttribute<path_meta::Interfaces>(
        PATH_ATTRIBUTE_INTERFACES);
    if (!ifaces) return SCION_NO_METADATA;
    size_t i = 0;
    for (auto&& hop : ifaces->data) {
        if (i >= *hops_len) break;
        hops[i++] = scion_hop {
            .isd_asn = hop.isdAsn,
            .ingress = hop.ingress,
            .egress = hop.egress,
        };
    }
    *hops_len = ifaces->data.size();
    if (i < *hops_len) return SCION_BUFFER_TOO_SMALL;
    return SCION_OK;
}

extern "C" DLLEXPORT
uint32_t scion_path_hop_count(scion_path* path)
{
    return reinterpret_cast<scion::Path*>(path)->hopCount();
}

extern "C" DLLEXPORT
void scion_path_digest(scion_path* path, scion_digest* digest)
{
    auto d = reinterpret_cast<scion::Path*>(path)->digest();
    std::memcpy(digest->value, d.value(), sizeof(digest->value));
}

extern "C" DLLEXPORT
scion_error scion_path_next_hop(scion_path* path, sockaddr* next_hop, socklen_t* next_hop_len)
{
    using namespace scion;

    if (reinterpret_cast<Path*>(path)->empty()) return SCION_PATH_IS_EMPTY;
    auto nh = reinterpret_cast<Path*>(path)->nextHop();
    if (nh.host().is4()) {
        if (auto underlay = toUnderlay<sockaddr_in>(nh); isError(underlay)) {
            return SCION_LOGIC_ERROR;
        } else {
            size_t out_len =* next_hop_len;
            scion_error status = copy_out(next_hop, &out_len, &(*underlay), sizeof(*underlay));
            *next_hop_len = (socklen_t)out_len;
            return status;
        }
    } else {
        if (auto underlay = toUnderlay<sockaddr_in6>(nh); isError(underlay)) {
            return SCION_LOGIC_ERROR;
        } else {
            size_t out_len =* next_hop_len;
            scion_error status = copy_out(next_hop, &out_len, &(*underlay), sizeof(*underlay));
            *next_hop_len = (socklen_t)out_len;
            return status;
        }
    }
}

extern "C" DLLEXPORT
void scion_path_encoded(scion_path* path, const uint8_t** encoded, size_t* encoded_len)
{
    auto raw = reinterpret_cast<scion::Path*>(path)->encoded();
    *encoded = reinterpret_cast<const uint8_t*>(raw.data());
    *encoded_len = raw.size();
}

extern "C" DLLEXPORT
scion_error scion_path_print(scion_path* path, char* buffer, size_t* buffer_len)
{
    using namespace scion;
    if (*buffer_len == 0) {
        *buffer_len = std::formatted_size("{}", *reinterpret_cast<Path*>(path)) + 1;
        return SCION_BUFFER_TOO_SMALL;
    }
    auto res = std::format_to_n(buffer, *buffer_len - 1, "{}", *reinterpret_cast<Path*>(path));
    *res.out = '\0';
    scion_error err = SCION_OK;
    if (*buffer_len < (size_t)(res.size + 1)) {
        err = SCION_BUFFER_TOO_SMALL;
    }
    *buffer_len = res.size + 1;
    return err;
}

///////////////
// Raw Paths //
///////////////

extern "C" DLLEXPORT
scion_raw_path* scion_raw_path_allocate()
{
    return reinterpret_cast<scion_raw_path*>(new scion::RawPath);
}

extern "C" DLLEXPORT
void scion_raw_path_free(scion_raw_path* path)
{
    if (path) delete reinterpret_cast<scion::RawPath*>(path);
}

extern "C" DLLEXPORT
void scion_raw_path_encoded(scion_raw_path* path, const uint8_t** encoded, size_t* encoded_len)
{
    auto raw = reinterpret_cast<scion::RawPath*>(path)->encoded();
    *encoded = reinterpret_cast<const uint8_t*>(raw.data());
    *encoded_len = raw.size();
}

extern "C" DLLEXPORT
uint64_t scion_raw_path_first_as(scion_raw_path* path)
{
    return reinterpret_cast<scion::RawPath*>(path)->firstAS();
}

extern "C" DLLEXPORT
uint64_t scion_raw_path_last_as(scion_raw_path* path)
{
    return reinterpret_cast<scion::RawPath*>(path)->lastAS();
}

extern "C" DLLEXPORT
scion_ptype scion_raw_path_type(scion_raw_path* path)
{
    return static_cast<scion_ptype>(reinterpret_cast<scion::RawPath*>(path)->type());
}

extern "C" DLLEXPORT
void scion_raw_path_digest(scion_raw_path* path, scion_digest* digest)
{
    auto d = reinterpret_cast<scion::RawPath*>(path)->digest();
    std::memcpy(digest->value, d.value(), sizeof(digest->value));
}

extern "C" DLLEXPORT
scion_error scion_raw_path_reverse(scion_raw_path* path)
{
    return translate_error(reinterpret_cast<scion::RawPath*>(path)->reverseInPlace());
}

extern "C" DLLEXPORT
scion_error scion_raw_path_print(scion_raw_path* path, char* buffer, size_t* buffer_len)
{
    using namespace scion;
    if (*buffer_len == 0) {
        *buffer_len = std::formatted_size("{}", *reinterpret_cast<RawPath*>(path)) + 1;
        return SCION_BUFFER_TOO_SMALL;
    }
    auto res = std::format_to_n(buffer, *buffer_len - 1, "{}", *reinterpret_cast<RawPath*>(path));
    *res.out = '\0';
    scion_error err = SCION_OK;
    if (*buffer_len < (size_t)(res.size + 1)) {
        err = SCION_BUFFER_TOO_SMALL;
    }
    *buffer_len = res.size + 1;
    return err;
}

//////////////////
// Header Cache //
//////////////////

extern "C" DLLEXPORT
scion_hdr_cache* scion_hdr_cache_allocate()
{
    return reinterpret_cast<scion_hdr_cache*>(new scion::HeaderCache<>);
}

extern "C" DLLEXPORT
void scion_hdr_cache_free(scion_hdr_cache* headers)
{
    if (headers) delete reinterpret_cast<scion::HeaderCache<>*>(headers);
}

/////////////
// Sockets //
/////////////

// Helper for initializing an Asio UDP/IP endpoint from a sockaddr.
static scion_error sockaddr_to_asio(
    const sockaddr* addr, socklen_t addr_len, boost::asio::ip::udp::endpoint& out)
{
    using namespace boost::asio::ip;
    if (addr->sa_family == AF_INET) {
        if (addr_len < sizeof(sockaddr_in)) return SCION_INVALID_ARGUMENT;
        auto in4 = reinterpret_cast<const sockaddr_in*>(addr);
        out = udp::endpoint(
            make_address_v4(reinterpret_cast<const address_v4::bytes_type&>(in4->sin_addr.s_addr)),
            ntohs(in4->sin_port)
        );
        return SCION_OK;
    } else if (addr->sa_family == AF_INET6) {
        if (addr_len < sizeof(sockaddr_in6)) return SCION_INVALID_ARGUMENT;
        auto in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        out = udp::endpoint(
            make_address_v6(reinterpret_cast<const address_v6::bytes_type&>(in6->sin6_addr),
                in6->sin6_scope_id),
            ntohs(in6->sin6_port)
        );
        return SCION_OK;
    } else {
        return SCION_INVALID_ARGUMENT;
    }
}

// Helper for initializing a sockaddr from an ASIO UDP/IP endpoint.
static scion_error asio_to_sockaddr(
    boost::asio::ip::udp::endpoint& ep, sockaddr* out, socklen_t out_len)
{
    using namespace boost::asio::ip;
    std::memset(out, 0, out_len);
    if (ep.address().is_v4()) {
        if (out_len < sizeof(sockaddr_in)) return SCION_INVALID_ARGUMENT;
        out->sa_family = AF_INET;
        auto in4 = reinterpret_cast<sockaddr_in*>(out);
        std::ranges::copy(ep.address().to_v4().to_bytes(),
            reinterpret_cast<unsigned char*>(&in4->sin_addr));
        in4->sin_port = htons(ep.port());
    } else {
        if (out_len < sizeof(sockaddr_in6)) return SCION_INVALID_ARGUMENT;
        out->sa_family = AF_INET6;
        auto in6 = reinterpret_cast<sockaddr_in6*>(out);
        std::ranges::copy(ep.address().to_v6().to_bytes(),
            reinterpret_cast<unsigned char*>(&in6->sin6_addr));
        in6->sin6_scope_id = ep.address().to_v6().scope_id();
        in6->sin6_port = htons(ep.port());
    }
    return SCION_OK;
}

struct scion_socket_t
{
    scion_context* ctx;
    std::variant<scion::asio::UdpSocket> v;
};

extern "C" DLLEXPORT
scion_error scion_socket_create(scion_context* ctx, scion_socket** socket, int socket_type)
{
    if (socket_type != SOCK_DGRAM) return SCION_NOT_IMPLEMENTED;
    *socket = new scion_socket_t{
        .ctx = ctx,
        .v = scion::asio::UdpSocket(ctx->ioCtx)
    };
    auto s = &std::get<scion::asio::UdpSocket>((*socket)->v);
    s->setNextScmpHandler(&ctx->scmpHandler);
    return SCION_OK;
}

extern "C" DLLEXPORT
void scion_close(scion_socket* socket)
{
    if (socket) delete socket;
}

extern "C" DLLEXPORT
scion_error scion_bind(scion_socket* socket, const struct sockaddr* addr, socklen_t addr_len)
{
    using namespace scion;

    ScIPEndpoint bind;
    if (addr->sa_family == AF_SCION) {
        if (addr_len < sizeof(sockaddr_scion))
            return SCION_INVALID_ARGUMENT;
        bind = details::endpoint_cast(reinterpret_cast<const sockaddr_scion*>(addr));
    } else if (addr->sa_family == AF_INET) {
        if (addr_len < sizeof(sockaddr_in))
            return SCION_INVALID_ARGUMENT;
        auto in4 = reinterpret_cast<const sockaddr_in*>(addr);
        bind = ScIPEndpoint(
            socket->ctx->localAS.isdAsn,
            generic::IPAddress::MakeIPv4(std::span<const std::byte, 4>(
                reinterpret_cast<const std::byte*>(&in4->sin_addr.s_addr), 4)),
            in4->sin_port
        );
    } else if (addr->sa_family == AF_INET6) {
        if (addr_len < sizeof(sockaddr_in6))
            return SCION_INVALID_ARGUMENT;
        auto in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        bind = ScIPEndpoint(
            socket->ctx->localAS.isdAsn,
            generic::IPAddress::MakeIPv6(std::span<const std::byte, 16>(
                reinterpret_cast<const std::byte*>(&in6->sin6_addr), 16)),
            in6->sin6_port
        );
    } else {
        return SCION_NOT_IMPLEMENTED;
    }

    return std::visit([&](auto&& s) -> scion_error {
        return translate_error(s.bind(bind));
    }, socket->v);
}

extern "C" DLLEXPORT
scion_error scion_connect(scion_socket* socket, const struct sockaddr_scion* addr)
{
    return std::visit([&](auto&& s) -> scion_error {
        return translate_error(s.connect(scion::details::endpoint_cast(addr)));
    }, socket->v);
}

extern "C" DLLEXPORT
bool scion_is_open(scion_socket* socket)
{
    return std::visit([&](auto&& s) -> bool {
        return s.isOpen();
    }, socket->v);
}

extern "C" DLLEXPORT
scion_native_handle scion_underlay_handle(scion_socket* socket)
{
    return std::visit([&](auto&& s) {
        return s.underlaySocket();
    }, socket->v);
}

extern "C" DLLEXPORT
scion_error scion_set_nonblocking(scion_socket* socket, bool nonblocking)
{
    return std::visit([&](auto&& s) {
        return translate_error(s.setNonblocking(nonblocking));
    }, socket->v);
}

extern "C" DLLEXPORT
void scion_getsockname(scion_socket* socket, struct sockaddr_scion* addr)
{
    using namespace scion;
    auto local = std::visit([&](auto&& s) -> ScIPEndpoint {
        return s.localEp();
    }, socket->v);
    *addr = details::endpoint_cast(local);
}

extern "C" DLLEXPORT
void scion_getmapped(scion_socket* socket, struct sockaddr_scion* addr)
{
    using namespace scion;
    auto local = std::visit([&](auto&& s) -> ScIPEndpoint {
        return s.mappedEp();
    }, socket->v);
    *addr = details::endpoint_cast(local);
}

extern "C" DLLEXPORT
void scion_getpeername(scion_socket* socket, struct sockaddr_scion* addr)
{
    using namespace scion;
    auto local = std::visit([&](auto&& s) -> ScIPEndpoint {
        return s.remoteEp();
    }, socket->v);
    *addr = details::endpoint_cast(local);
}

extern "C" DLLEXPORT
scion_error scion_measure(scion_socket* socket, const scion_packet* args, size_t* hdr_size)
{
    using namespace scion;

    if (!args->_path || (args->_path_type != 1 && args->_path_type != 2)) {
        return SCION_INVALID_ARGUMENT;
    }

    auto size = std::visit([&](auto&& s) -> Maybe<std::size_t> {
        if (args->addr) {
            if (args->_path_type == 1) {
                return s.measureTo(
                    details::endpoint_cast(args->addr),
                    *reinterpret_cast<Path*>(args->_path)
                );
            } else {
                return s.measureTo(
                    details::endpoint_cast(args->addr),
                    *reinterpret_cast<RawPath*>(args->_path)
                );
            }
        } else {
            if (args->_path_type == 1) {
                return s.measure(*reinterpret_cast<Path*>(args->_path));
            } else {
                return s.measure(*reinterpret_cast<RawPath*>(args->_path));
            }
        }
    }, socket->v);
    if (isError(size)) {
        return translate_error(getError(size));
    } else {
        *hdr_size = *size;
        return SCION_OK;
    }
}

extern "C" DLLEXPORT
scion_error scion_request_stun_mapping(scion_socket* socket, struct sockaddr* router,
    socklen_t router_len)
{
    using namespace scion;

    if (!router) {
        return SCION_INVALID_ARGUMENT;
    }

    boost::asio::ip::udp::endpoint addr;
    auto err = sockaddr_to_asio(router, router_len, addr);
    if (err) return err;

    auto ec = std::visit([&](auto&& s) -> std::error_code {
        return s.requestStunMapping(addr);
    }, socket->v);
    return translate_error(ec);
}

extern "C" DLLEXPORT
scion_error scion_send(scion_socket* socket, scion_hdr_cache* headers,
    const void* buf, size_t* n, const struct scion_packet* args)
{
    using namespace scion;

    if (!args->_path || (args->_path_type != 1 && args->_path_type != 2)) {
        return SCION_INVALID_ARGUMENT;
    }

    boost::asio::ip::udp::endpoint nh;
    auto err = sockaddr_to_asio(args->underlay, args->underlay_len, nh);
    if (err) return err;

    auto sent = std::visit([&](auto&& s) -> Maybe<std::span<const std::byte>> {
        if (args->addr) {
            if (args->_path_type == 1) {
                return s.sendTo(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    details::endpoint_cast(args->addr),
                    *reinterpret_cast<Path*>(args->_path),
                    nh,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), *n)
                );
            } else {
                return s.sendTo(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    details::endpoint_cast(args->addr),
                    *reinterpret_cast<RawPath*>(args->_path),
                    nh,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), *n)
                );
            }
        } else {
            if (args->_path_type == 1) {
                return s.send(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *reinterpret_cast<Path*>(args->_path),
                    nh,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), *n)
                );
            } else {
                return s.send(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *reinterpret_cast<RawPath*>(args->_path),
                    nh,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), *n)
                );
            }
        }
    }, socket->v);
    if (isError(sent)) {
        return translate_error(getError(sent));
    } else {
        *n = sent->size();
        return SCION_OK;
    }
}

extern "C" DLLEXPORT
scion_error scion_send_cached(scion_socket* socket, scion_hdr_cache* headers,
    const void* buf, size_t* n, struct scion_packet* args)
{
    using namespace scion;

    boost::asio::ip::udp::endpoint nh;
    auto err = sockaddr_to_asio(args->underlay, args->underlay_len, nh);
    if (err) return err;

    auto sent = std::visit([&] (auto&& s) -> Maybe<std::span<const std::byte>> {
        return s.sendCached(
            *reinterpret_cast<HeaderCache<>*>(headers),
            nh,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), *n)
        );
    }, socket->v);
    if (isError(sent)) {
        return translate_error(getError(sent));
    } else {
        *n = sent->size();
        return SCION_OK;
    }
}

extern "C" DLLEXPORT
scion_error scion_recv_stun_response(scion_socket* socket)
{
    using namespace scion;
    auto ec = std::visit([&] (auto&& s) -> std::error_code {
        return s.recvStunResponse();
    }, socket->v);
    return translate_error(ec);
}

extern "C" DLLEXPORT
void* scion_recv(scion_socket* socket,
    void* buf, size_t* n, struct scion_packet* args, scion_error* err)
{
    using namespace scion;

    if (args->_path && args->_path_type != 2) {
        *err = SCION_INVALID_ARGUMENT;
        return NULL;
    }

    ScIPEndpoint from;
    boost::asio::ip::udp::endpoint underlay;
    auto recvd = std::visit([&] (auto&& s) -> Maybe<std::span<std::byte>> {
        return s.recvFromVia(
            std::span<std::byte>(reinterpret_cast<std::byte*>(buf), *n),
            from,
            *reinterpret_cast<RawPath*>(args->_path),
            underlay
        );
    }, socket->v);
    if (isError(recvd)) {
        *err =  translate_error(getError(recvd));
        return NULL;
    }

    if (args->addr) *args->addr = details::endpoint_cast(from);
    if (args->underlay) {
        if (auto e = asio_to_sockaddr(underlay, args->underlay, args->underlay_len)) {
            *err = e;
            return NULL;
        }
    }

    *n = recvd->size();
    return recvd->data();
}

extern "C" DLLEXPORT
void scion_request_stun_mapping_async(scion_socket* socket, struct sockaddr* router,
    socklen_t router_len, struct scion_async_send_handler handler)
{
    using namespace scion;

    if (!router) {
        handler.callback(SCION_INVALID_ARGUMENT, 0, handler.user_ptr);
        return;
    }

    auto addr = std::make_unique<boost::asio::ip::udp::endpoint>();
    auto err = sockaddr_to_asio(router, router_len, *addr);
    if (err) {
        handler.callback(err, 0, handler.user_ptr);
        return;
    }

    struct send_stun_impl {
        scion_async_send_handler m_handler;
        const scion_packet* m_args;
        std::unique_ptr<boost::asio::ip::udp::endpoint> m_addr;

        send_stun_impl(scion_async_send_handler handler,
            std::unique_ptr<boost::asio::ip::udp::endpoint>&& underlay)
            : m_handler(handler), m_addr(std::move(underlay))
        {}

        void operator()(std::error_code ec)
        {
            m_addr.reset();
            // all memory must have been released before calling the completion handler
            if (ec) {
                m_handler.callback(translate_error(ec), 0, m_handler.user_ptr);
            } else {
                m_handler.callback(SCION_OK, 0, m_handler.user_ptr);
            }
        }
    };

    std::visit([&] (auto&& s) {
        send_stun_impl token(handler, std::move(addr));
        s.requestStunMappingAsync(*token.m_addr, std::move(token));
    }, socket->v);
}

extern "C" DLLEXPORT
void scion_send_async(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t n,
    const struct scion_packet* args, struct scion_async_send_handler handler)
{
    using namespace scion;

    if (!args->_path || (args->_path_type != 1 && args->_path_type != 2)) {
        handler.callback(SCION_INVALID_ARGUMENT, 0, handler.user_ptr);
        return;
    }

    auto nh = std::make_unique<boost::asio::ip::udp::endpoint>();
    auto err = sockaddr_to_asio(args->underlay, args->underlay_len, *nh);
    if (err) {
        handler.callback(err, 0, handler.user_ptr);
        return;
    }

    struct async_send_impl {
        scion_async_send_handler m_handler;
        const scion_packet* m_args;
        std::unique_ptr<ScIPEndpoint> m_to;
        std::unique_ptr<boost::asio::ip::udp::endpoint> m_underlay;

        async_send_impl(scion_async_send_handler handler, const scion_packet* args,
            std::unique_ptr<boost::asio::ip::udp::endpoint>&& underlay)
            : m_handler(handler), m_args(args), m_underlay(std::move(underlay))
        {
            if (args->addr) {
                m_to = std::make_unique<ScIPEndpoint>(details::endpoint_cast(args->addr));
            }
        }

        void operator()(Maybe<std::span<const std::byte>> sent)
        {
            m_to.reset();
            m_underlay.reset();
            // all memory must have been released before calling the completion handler
            if (isError(sent)) {
                m_handler.callback(translate_error(getError(sent)), 0, m_handler.user_ptr);
            } else {
                m_handler.callback(SCION_OK, sent->size(), m_handler.user_ptr);
            }
        }
    };

    std::visit([&] (auto&& s) {
        async_send_impl token(handler, args, std::move(nh));
        if (args->addr) {
            if (args->_path_type == 1) {
                s.sendToAsync(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *token.m_to,
                    *reinterpret_cast<Path*>(args->_path),
                    *token.m_underlay,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
                    std::move(token)
                );
            } else {
                s.sendToAsync(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *token.m_to,
                    *reinterpret_cast<RawPath*>(args->_path),
                    *token.m_underlay,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
                    std::move(token)
                );
            }
        } else {
            if (args->_path_type == 1) {
                s.sendAsync(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *reinterpret_cast<Path*>(args->_path),
                    *token.m_underlay,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
                    std::move(token)
                );
            } else {
                s.sendAsync(
                    *reinterpret_cast<HeaderCache<>*>(headers),
                    *reinterpret_cast<RawPath*>(args->_path),
                    *token.m_underlay,
                    std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
                    std::move(token)
                );
            }
        }
    }, socket->v);
}

extern "C" DLLEXPORT
void scion_send_cached_async(
    scion_socket* socket, scion_hdr_cache* headers, const void* buf, size_t n,
    struct scion_packet* args, struct scion_async_send_handler handler)
{
    using namespace scion;

    auto nh = std::make_unique<boost::asio::ip::udp::endpoint>();
    auto err = sockaddr_to_asio(args->underlay, args->underlay_len, *nh);
    if (err) {
        handler.callback(err, 0, handler.user_ptr);
        return;
    }

    struct async_send_cached_impl {
        scion_async_send_handler m_handler;
        std::unique_ptr<boost::asio::ip::udp::endpoint> m_underlay;

        async_send_cached_impl(scion_async_send_handler handler,
            std::unique_ptr<boost::asio::ip::udp::endpoint>&& underlay)
            : m_handler(handler), m_underlay(std::move(underlay))
        {}

        void operator()(Maybe<std::span<const std::byte>> sent)
        {
            m_underlay.reset();
            // all memory must have been released before calling the completion handler
            if (isError(sent)) {
                m_handler.callback(translate_error(getError(sent)), 0, m_handler.user_ptr);
            } else {
                m_handler.callback(SCION_OK, sent->size(), m_handler.user_ptr);
            }
        }
    };

    std::visit([&] (auto&& s) {
        async_send_cached_impl token(handler, std::move(nh));
        return s.sendCachedAsync(
            *reinterpret_cast<HeaderCache<>*>(headers),
            *token.m_underlay,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(buf), n),
            std::move(token)
        );
    }, socket->v);
}

extern "C" DLLEXPORT
void scion_recv_stun_response_async(scion_socket* socket,
    struct scion_async_recv_handler handler)
{
    using namespace scion;

    struct recv_stun_impl {
        scion_async_recv_handler m_handler;
        void operator()(std::error_code ec)
        {
            m_handler.callback(translate_error(ec), nullptr, 0, m_handler.user_ptr);
        }
    };
    std::visit([&] (auto&& s) {
        s.recvStunResponseAsync(recv_stun_impl{handler});
    }, socket->v);
}

extern "C" DLLEXPORT
void scion_recv_async(scion_socket* socket, void* buf, size_t n, struct scion_packet* args,
    struct scion_async_recv_handler handler)
{
    using namespace scion;

    if (args->_path && args->_path_type != 2) {
        handler.callback(SCION_INVALID_ARGUMENT, nullptr, 0, handler.user_ptr);
        return;
    }

    struct async_recv_impl {
        scion_async_recv_handler m_handler;
        scion_packet* m_args;
        std::unique_ptr<ScIPEndpoint> m_from;
        std::unique_ptr<boost::asio::ip::udp::endpoint> m_underlay;

        async_recv_impl(scion_async_recv_handler handler, scion_packet* args)
            : m_handler(handler), m_args(args)
        {
            if (args->addr) m_from.reset(new ScIPEndpoint);
            m_underlay.reset(new boost::asio::ip::udp::endpoint);
        }

        void operator()(Maybe<std::span<std::byte>> recvd)
        {
            if (m_from) {
                *m_args->addr = details::endpoint_cast(*m_from);
                m_from.reset();
            }
            if (m_args->underlay) {
                asio_to_sockaddr(*m_underlay, m_args->underlay, m_args->underlay_len);
            }
            m_underlay.reset();
            // all memory must have been released before calling the completion handler
            if (isError(recvd)) {
                m_handler.callback(translate_error(getError(recvd)), nullptr, 0, m_handler.user_ptr);
            } else {
                m_handler.callback(SCION_OK, recvd->data(), recvd->size(), m_handler.user_ptr);
            }
        }
    };

    std::visit([&](auto&& s) {
        async_recv_impl token(handler, args);
        if (args->addr) {
            if (args->_path) {
                s.recvFromViaAsync(
                    std::span<std::byte>(reinterpret_cast<std::byte*>(buf), n),
                    *token.m_from,
                    *reinterpret_cast<RawPath*>(args->_path),
                    *token.m_underlay,
                    std::move(token)
                );
            } else {
                s.recvFromAsync(
                    std::span<std::byte>(reinterpret_cast<std::byte*>(buf), n),
                    *token.m_from,
                    *token.m_underlay,
                    std::move(token)
                );
            }
        } else {
            s.recvAsync(
                std::span<std::byte>(reinterpret_cast<std::byte*>(buf), n),
                *token.m_underlay,
                std::move(token)
            );
        }

    }, socket->v);
}

extern "C" DLLEXPORT
scion_error scion_cancel(scion_socket* socket)
{
    return std::visit([&](auto&& s) {
        return translate_error(s.cancel());
    }, socket->v);
}

////////////
// Timers //
////////////

extern "C" DLLEXPORT
scion_timer* scion_timer_allocate(scion_context* ctx)
{
    return reinterpret_cast<scion_timer*>(new boost::asio::steady_timer(ctx->ioCtx));
}

extern "C" DLLEXPORT
void scion_timer_free(scion_timer* timer)
{
    delete reinterpret_cast<boost::asio::steady_timer*>(timer);
}

extern "C" DLLEXPORT
void scion_timer_set_timeout(scion_timer* timer, uint32_t timeout)
{
    using std::chrono::milliseconds;
    reinterpret_cast<boost::asio::steady_timer*>(timer)->expires_after(milliseconds(timeout));
}

extern "C" DLLEXPORT
size_t scion_timer_cancel(scion_timer* timer)
{
    return reinterpret_cast<boost::asio::steady_timer*>(timer)->cancel();
}

extern "C" DLLEXPORT
scion_error scion_timer_wait(scion_timer* timer)
{
    boost::system::error_code ec;
    reinterpret_cast<boost::asio::steady_timer*>(timer)->wait(ec);
    return translate_error(ec);
}

extern "C" DLLEXPORT
void scion_timer_wait_async(scion_timer* timer, struct scion_wait_handler handler)
{
    auto token = [=] (const boost::system::error_code& error) {
        handler.callback(translate_error(error), handler.user_ptr);
    };
    reinterpret_cast<boost::asio::steady_timer*>(timer)->async_wait(token);
}
