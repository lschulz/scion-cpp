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

#include "scion/error_codes.hpp"
#include "scion/addr/address.hpp"
#include "scion/addr/endpoint.hpp"
#include "scion/details/bit.hpp"

#if _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#include <cstdint>
#include <cstring>
#include <format>
#include <variant>


//////////////////////////////////
// IPv4 in_addr and sockaddr_in //
//////////////////////////////////

template <>
struct scion::AddressTraits<in_addr>
{
    using HostAddr = in_addr;

    static HostAddrType type(const HostAddr&) noexcept
    {
        return HostAddrType::IPv4;
    }

    static std::size_t size(const HostAddr&) noexcept
    {
        return 4;
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        return addr.s_addr == 0;
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte> bytes) noexcept
    {
        if (bytes.size() < 4) return ErrorCode::BufferTooSmall;
        std::memcpy(bytes.data(), &addr.s_addr, 4);
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        if (bytes.size() != 4) return Error(ErrorCode::InvalidArgument);
        HostAddr addr = {};
        std::memcpy(&addr.s_addr, bytes.data(), bytes.size());
        return addr;
    }

    static Maybe<HostAddr> fromString(std::string_view text) noexcept
    {
        // copy to make null-terminated input string
        std::array<char, INET_ADDRSTRLEN> buf = {};
        if (text.size() < buf.size()) {
            std::copy(text.begin(), text.end(), buf.begin());
        } else {
            return Error(ErrorCode::InvalidArgument);
        }
        HostAddr addr = {};
        if (!inet_pton(AF_INET, buf.data(), &addr))
            return Error(ErrorCode::InvalidArgument);
        return addr;
    }
};

template <>
struct scion::EndpointTraits<sockaddr_in>
{
    using LocalEp = sockaddr_in;
    using HostAddr = in_addr;
    using ScionAddr = scion::Address<HostAddr>;

    static LocalEp fromHostPort(HostAddr host, std::uint16_t port) noexcept
    {
        return LocalEp{
            .sin_family = AF_INET,
            .sin_port = details::byteswapBE(port),
            .sin_addr = host,
            .sin_zero = {},
        };
    }

    static HostAddr getHost(const LocalEp& ep) noexcept
    {
        return ep.sin_addr;
    }

    static std::uint16_t getPort(const LocalEp& ep) noexcept
    {
        return details::byteswapBE(ep.sin_port);
    }
};

template <>
struct std::formatter<in_addr>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const in_addr& addr, auto& ctx) const
    {
        auto out = ctx.out();
        std::array<char, INET_ADDRSTRLEN> buffer;
        if (inet_ntop(AF_INET, &addr, buffer.data(), buffer.size())) {
            for (std::size_t i = 0; buffer[i] != 0; ++i) out++ = buffer[i];
        }
        return out;
    }
};

template <>
struct std::formatter<sockaddr_in>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const sockaddr_in& addr, auto& ctx) const
    {
        auto out = ctx.out();
        std::array<char, INET_ADDRSTRLEN> host;
        std::array<char, 8> service;
        int err = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
            host.data(), host.size(),
            service.data(), service.size(),
            NI_NUMERICHOST | NI_NUMERICSERV);
        if (!err) {
            out = std::format_to(out, "{}:{}", host.data(), service.data());
        }
        return out;
    }
};

inline bool operator==(const in_addr& a, const in_addr& b)
{
    return a.s_addr == b.s_addr;
}

inline std::strong_ordering operator<=>(const in_addr& a, const in_addr& b)
{
    return a.s_addr <=> b.s_addr;
}

inline bool operator==(const sockaddr_in& a, const sockaddr_in& b)
{
    return a.sin_family == b.sin_family
        && a.sin_port == b.sin_port
        && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

inline std::strong_ordering operator<=>(const sockaddr_in& a, const sockaddr_in& b)
{
    auto order = a.sin_family <=> b.sin_family;
    if (order != std::strong_ordering::equal) return order;
    order = a.sin_addr <=> b.sin_addr;
    if (order != std::strong_ordering::equal) return order;
    return a.sin_port <=> b.sin_port;
}

template <>
struct std::hash<in_addr>
{
    std::size_t operator()(const in_addr& addr) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&addr, sizeof(addr), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&addr, sizeof(addr), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

template <>
struct std::hash<sockaddr_in>
{
    std::size_t operator()(const sockaddr_in& sockaddr) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&sockaddr, sizeof(sockaddr), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&sockaddr, sizeof(sockaddr), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

////////////////////////////////////
// IPv6 in6_addr and sockaddr_in6 //
////////////////////////////////////

template <>
struct scion::AddressTraits<in6_addr>
{
    using HostAddr = in6_addr;

    static HostAddrType type(const HostAddr&) noexcept
    {
        return HostAddrType::IPv6;
    }

    static std::size_t size(const HostAddr&) noexcept
    {
        return 16;
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        return IN6_IS_ADDR_UNSPECIFIED(&addr);
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte> bytes) noexcept
    {
        if (bytes.size() < 16) return ErrorCode::BufferTooSmall;
        std::memcpy(bytes.data(), &addr.s6_addr, 16);
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        if (bytes.size() != 16) return Error(ErrorCode::InvalidArgument);
        HostAddr addr = {};
        std::memcpy(&addr.s6_addr, bytes.data(), bytes.size());
        return addr;
    }

    static Maybe<HostAddr> fromString(std::string_view text) noexcept
    {
        // copy to make null-terminated input string
        std::array<char, INET6_ADDRSTRLEN> buf = {};
        if (text.size() < buf.size()) {
            std::copy(text.begin(), text.end(), buf.begin());
        } else {
            return Error(ErrorCode::InvalidArgument);
        }
        HostAddr addr = {};
        if (!inet_pton(AF_INET6, buf.data(), &addr))
            return Error(ErrorCode::InvalidArgument);
        return addr;
    }
};

template <>
struct scion::EndpointTraits<sockaddr_in6>
{
    using LocalEp = sockaddr_in6;
    using HostAddr = in6_addr;
    using ScionAddr = scion::Address<HostAddr>;

    static LocalEp fromHostPort(HostAddr host, std::uint16_t port) noexcept
    {
        return LocalEp{
            .sin6_family = AF_INET6,
            .sin6_port = details::byteswapBE(port),
            .sin6_flowinfo = 0,
            .sin6_addr = host,
            .sin6_scope_id = 0,
        };
    }

    static HostAddr getHost(const LocalEp& ep) noexcept
    {
        return ep.sin6_addr;
    }

    static std::uint16_t getPort(const LocalEp& ep) noexcept
    {
        return details::byteswapBE(ep.sin6_port);
    }
};

template <>
struct std::formatter<in6_addr>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const in6_addr& addr, auto& ctx) const
    {
        auto out = ctx.out();
        std::array<char, INET6_ADDRSTRLEN> buffer;
        if (inet_ntop(AF_INET6, &addr, buffer.data(), buffer.size())) {
            for (std::size_t i = 0; buffer[i] != 0; ++i) out++ = buffer[i];
        }
        return out;
    }
};

template <>
struct std::formatter<sockaddr_in6>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const sockaddr_in6& addr, auto& ctx) const
    {
        auto out = ctx.out();
        std::array<char, INET6_ADDRSTRLEN> host;
        std::array<char, 8> service;
        int err = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
            host.data(), static_cast<socklen_t>(host.size()),
            service.data(), static_cast<socklen_t>(service.size()),
            NI_NUMERICHOST | NI_NUMERICSERV);
        if (!err) {
            out = std::format_to(out, "[{}]:{}", host.data(), service.data());
        }
        return out;
    }
};

inline bool operator==(const in6_addr& a, const in6_addr& b)
{
    return std::equal(a.s6_addr, a.s6_addr + sizeof(a.s6_addr), b.s6_addr);
}

inline std::strong_ordering operator<=>(const in6_addr& a, const in6_addr& b)
{
    for (std::size_t i = 0; i < sizeof(a.s6_addr); ++i) {
        if (a.s6_addr[i] != b.s6_addr[i]) {
            return a.s6_addr[i] <=> b.s6_addr[i];
        }
    }
    return std::strong_ordering::equal;
}

inline bool operator==(const sockaddr_in6& a, const sockaddr_in6& b)
{
    if (a.sin6_family != b.sin6_family || a.sin6_port != b.sin6_port)
        return false;
    return a.sin6_addr == b.sin6_addr;
}

inline std::strong_ordering operator<=>(const sockaddr_in6& a, const sockaddr_in6& b)
{
    auto order = a.sin6_family <=> b.sin6_family;
    if (order != std::strong_ordering::equal) return order;
    order = a.sin6_addr <=> b.sin6_addr;
    if (order != std::strong_ordering::equal) return order;
    return a.sin6_port <=> b.sin6_port;
}

template <>
struct std::hash<in6_addr>
{
    std::size_t operator()(const in6_addr& addr) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&addr, sizeof(addr), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&addr, sizeof(addr), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

template <>
struct std::hash<sockaddr_in6>
{
    std::size_t operator()(const sockaddr_in6& sockaddr) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&sockaddr, sizeof(sockaddr), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&sockaddr, sizeof(sockaddr), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

//////////////////////////////////////////////////////
// scion::bsd::IPAddress and scion::bsd::IPEndpoint //
//////////////////////////////////////////////////////

namespace scion {
namespace bsd {

using IPAddress = std::variant<in_addr, in6_addr>;

class IPEndpoint
{
public:
    union
    {
        sockaddr generic;
        sockaddr_in v4;
        sockaddr_in6 v6;
    } data;
};

inline bool operator==(const scion::bsd::IPEndpoint& lhs, const scion::bsd::IPEndpoint& rhs)
{
    if (lhs.data.generic.sa_family != rhs.data.generic.sa_family) return false;
    if (lhs.data.generic.sa_family == AF_INET) {
        return lhs.data.v4 == rhs.data.v4;
    } else if (lhs.data.generic.sa_family == AF_INET6) {
        return lhs.data.v6 == rhs.data.v6;
    } else {
        assert(false && "unexpected address family in scion::bsd::IPEndpoint");
        return true;
    }
}

inline std::strong_ordering operator<=>(
    const scion::bsd::IPEndpoint& lhs, const scion::bsd::IPEndpoint& rhs)
{
    auto order = lhs.data.generic.sa_family <=> rhs.data.generic.sa_family;
    if (order != std::strong_ordering::equal) return order;
    if (lhs.data.generic.sa_family == AF_INET) {
        return lhs.data.v4 <=> rhs.data.v4;
    } else if (lhs.data.generic.sa_family == AF_INET6) {
        return lhs.data.v6 <=> rhs.data.v6;
    } else {
        assert(false && "unexpected address family in scion::bsd::IPEndpoint");
        return std::strong_ordering::equal;
    }
}

} // namespace bsd
} // namespace scion

template <>
struct scion::AddressTraits<scion::bsd::IPAddress>
{
    using HostAddr = scion::bsd::IPAddress;

    static HostAddrType type(const HostAddr& addr) noexcept
    {
        if (std::holds_alternative<in_addr>(addr))
            return HostAddrType::IPv4;
        else
            return HostAddrType::IPv6;
    }

    static std::size_t size(const HostAddr& addr) noexcept
    {
        if (std::holds_alternative<in_addr>(addr))
            return 4;
        else
            return 16;
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        if (std::holds_alternative<in_addr>(addr))
            return scion::AddressTraits<in_addr>::isUnspecified(std::get<in_addr>(addr));
        else
            return scion::AddressTraits<in6_addr>::isUnspecified(std::get<in6_addr>(addr));
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte> bytes) noexcept
    {
        if (std::holds_alternative<in_addr>(addr)) {
            if (bytes.size() < 4) return ErrorCode::BufferTooSmall;
            std::memcpy(bytes.data(), std::get_if<in_addr>(&addr), 4);
        } else {
            if (bytes.size() < 16) return ErrorCode::BufferTooSmall;
            std::memcpy(bytes.data(), std::get_if<in6_addr>(&addr), 16);
        }
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        const auto size = bytes.size();
        if (size == 4) {
            auto addr = AddressTraits<in_addr>::fromBytes(bytes);
            return addr.transform([] (auto&& x) { return HostAddr(x); });
        } else if (size == 16) {
            auto addr = AddressTraits<in6_addr>::fromBytes(bytes);
            return addr.transform([] (auto&& x) { return HostAddr(x); });
        } else {
            return Error(ErrorCode::InvalidArgument);
        }
    }

    static Maybe<HostAddr> fromString(std::string_view text) noexcept
    {
        if (text.contains(':')) {
            // assume IPv6
            auto ip = scion::AddressTraits<in6_addr>::fromString(text);
            if (isError(ip)) return propagateError(ip);
            return get(ip);
        } else {
            // assume IPv4
            auto ip = scion::AddressTraits<in_addr>::fromString(text);
            if (isError(ip)) return propagateError(ip);
            return get(ip);
        }
    }
};

template <>
struct scion::EndpointTraits<scion::bsd::IPEndpoint>
{
    using LocalEp = scion::bsd::IPEndpoint;
    using HostAddr = scion::bsd::IPAddress;
    using ScionAddr = scion::Address<HostAddr>;

    static LocalEp fromHostPort(HostAddr host, std::uint16_t port) noexcept
    {
        if (std::holds_alternative<in_addr>(host)) {
            return LocalEp{.data = {.v4 = {
                .sin_family = AF_INET,
                .sin_port = details::byteswapBE(port),
                .sin_addr = std::get<in_addr>(host),
                .sin_zero = {},
            }}};
        } else {
            return LocalEp{.data = {.v6 = {
                .sin6_family = AF_INET6,
                .sin6_port = details::byteswapBE(port),
                .sin6_flowinfo = 0,
                .sin6_addr = std::get<in6_addr>(host),
                .sin6_scope_id = 0,
            }}};
        }
    }

    static HostAddr getHost(const LocalEp& ep) noexcept
    {
        if (ep.data.generic.sa_family == AF_INET)
            return ep.data.v4.sin_addr;
        else if (ep.data.generic.sa_family == AF_INET6)
            return ep.data.v6.sin6_addr;
        assert(false && "unexpected address family in scion::bsd::IPEndpoint");
        return in_addr{};
    }

    static std::uint16_t getPort(const LocalEp& ep) noexcept
    {
        if (ep.data.generic.sa_family == AF_INET)
            return details::byteswapBE(ep.data.v4.sin_port);
        else if (ep.data.generic.sa_family == AF_INET6)
            return details::byteswapBE(ep.data.v6.sin6_port);
        assert(false && "unexpected address family in scion::bsd::IPEndpoint");
        return 0;
    }
};

template <>
struct std::formatter<scion::bsd::IPAddress>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::bsd::IPAddress& addr, auto& ctx) const
    {
        auto out = ctx.out();
        int family = std::holds_alternative<in_addr>(addr) ? AF_INET : AF_INET6;
        std::array<char, INET6_ADDRSTRLEN> buffer;
        if (inet_ntop(family, &addr, buffer.data(), buffer.size())) {
            for (std::size_t i = 0; buffer[i] != 0; ++i) out++ = buffer[i];
        }
        return out;
    }
};

template <>
struct std::formatter<scion::bsd::IPEndpoint>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::bsd::IPEndpoint& addr, auto& ctx) const
    {
        auto out = ctx.out();
        std::array<char, INET6_ADDRSTRLEN> host;
        std::array<char, 8> service;
        int err = getnameinfo(reinterpret_cast<const sockaddr*>(&addr), sizeof(addr),
            host.data(), static_cast<socklen_t>(host.size()),
            service.data(), static_cast<socklen_t>(service.size()),
            NI_NUMERICHOST | NI_NUMERICSERV);
        if (!err) {
            if (addr.data.generic.sa_family == AF_INET)
                out = std::format_to(out, "{}:{}", host.data(), service.data());
            else
                out = std::format_to(out, "[{}]:{}", host.data(), service.data());
        }
        return out;
    }
};

template <>
struct std::hash<scion::bsd::IPEndpoint>
{
    std::size_t operator()(const scion::bsd::IPEndpoint& ep) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            if (ep.data.generic.sa_family == AF_INET) {
                scion::details::MurmurHash3_x86_32(&ep.data.v4, sizeof(ep.data.v4), seed, &h);
            } else if (ep.data.generic.sa_family == AF_INET6) {
                scion::details::MurmurHash3_x86_32(&ep.data.v6, sizeof(ep.data.v6), seed, &h);
            } else {
                assert(false && "unexpected address family in scion::bsd::IPEndpoint");
            }
            return h;
        } else {
            std::uint64_t h[2] = {};
            if (ep.data.generic.sa_family == AF_INET) {
                scion::details::MurmurHash3_x64_128(&ep.data.v4, sizeof(ep.data.v4), seed, &h);
            } else if (ep.data.generic.sa_family == AF_INET6) {
                scion::details::MurmurHash3_x64_128(&ep.data.v6, sizeof(ep.data.v6), seed, &h);
            } else {
                assert(false && "unexpected address family in scion::bsd::IPEndpoint");
            }
            return h[0] ^ h[1];
        }
    }
};
