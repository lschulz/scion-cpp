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

#include "scion/addr/address.hpp"
#include "scion/addr/endpoint.hpp"
#include "scion/error_codes.hpp"

#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <format>
#include <string_view>
#include <string>
#include <variant>


namespace scion {
namespace generic {

class IPAddress;
class IPEndpoint;

/// \brief API-independent generic IPv4/6 address.
///
/// Represents an IPv4 or IPv6 address. IPv4 addresses and IPv4-mapped IPv6
/// address are considered distinct and con be converted between with the
/// map4in6() and unmap4in6() methods.
///
/// Always represents an address. There is no empty or invalid state.
///
/// ### Formatting
///
/// Supports formatting with `std::format`. The default format adheres to RFC
/// 5952. The following format specifiers are available to modify the output:
/// * `l` Always use the expended form of IPv6 addresses.
/// * `x` Write IPv6 with lower case digits. (the default)
/// * `X` Write IPv6 with upper case digits.
/// Output of IPv4 addresses is not affected by the `lxX` specifiers.
///
class IPAddress
{
public:
    /// \brief Construct the address "::".
    IPAddress()
        : addrInfo(&IPAddress::IPv6NoZone, false)
    {}

    /// \brief Returns the unspecified IPv4 address "0.0.0.0".
    static IPAddress UnspecifiedIPv4()
    {
        return {0, 0, &IPAddress::IPv4};
    }

    /// \brief Returns the unspecified IPv6 address "::",
    static IPAddress UnspecifiedIPv6()
    {
        return {0, 0, &IPAddress::IPv6NoZone};
    }

    /// \brief Make an IPv4 address from four bytes in big-endian order.
    /// \note {a, b, c, d} -> a.b.c.d
    static IPAddress MakeIPv4(std::span<const std::byte, 4> ipv4)
    {
        return IPAddress{
            0,
            ((std::uint64_t)ipv4[0] << 24) | ((std::uint64_t)ipv4[1] << 16)
            | ((std::uint64_t)ipv4[2] << 8) | ((std::uint64_t)ipv4[3]),
            &IPAddress::IPv4
        };
    }

    /// \brief Make an IPv4 address from an integer in host byte order.
    /// \note 0xaabbccdd -> aa.bb.cc.dd
    static IPAddress MakeIPv4(std::uint32_t ipv4)
    {
        return IPAddress{
            0,
            (std::uint64_t)ipv4,
            &IPAddress::IPv4
        };
    }

    /// \brief Make an IPv6 address from 16 bytes in big-endian order.
    static IPAddress MakeIPv6(std::span<const std::byte, 16> ipv6)
    {
        return IPAddress{
            ((std::uint64_t)ipv6[0] << 56) | ((std::uint64_t)ipv6[1] << 48)
            | ((std::uint64_t)ipv6[2] << 40) | ((std::uint64_t)ipv6[3] << 32)
            | ((std::uint64_t)ipv6[4] << 24) | ((std::uint64_t)ipv6[5] << 16)
            | ((std::uint64_t)ipv6[6] << 8) | ((std::uint64_t)ipv6[7]),
            ((std::uint64_t)ipv6[8] << 56) | ((std::uint64_t)ipv6[9] << 48)
            | ((std::uint64_t)ipv6[10] << 40) | ((std::uint64_t)ipv6[11] << 32)
            | ((std::uint64_t)ipv6[12] << 24) | ((std::uint64_t)ipv6[13] << 16)
            | ((std::uint64_t)ipv6[14] << 8) | ((std::uint64_t)ipv6[15]),
            &IPAddress::IPv6NoZone
        };
    }

    /// \brief Make an IPv6 address from 16 bytes in host byte order and a zone
    // identifier.
    static IPAddress MakeIPv6(
        std::span<const std::byte, 16> ipv6, std::string_view zone)
    {
        return IPAddress{
            ((std::uint64_t)ipv6[0] << 56) | ((std::uint64_t)ipv6[1] << 48)
            | ((std::uint64_t)ipv6[2] << 40) | ((std::uint64_t)ipv6[3] << 32)
            | ((std::uint64_t)ipv6[4] << 24) | ((std::uint64_t)ipv6[5] << 16)
            | ((std::uint64_t)ipv6[6] << 8) | ((std::uint64_t)ipv6[7]),
            ((std::uint64_t)ipv6[8] << 56) | ((std::uint64_t)ipv6[9] << 48)
            | ((std::uint64_t)ipv6[10] << 40) | ((std::uint64_t)ipv6[11] << 32)
            | ((std::uint64_t)ipv6[12] << 24) | ((std::uint64_t)ipv6[13] << 16)
            | ((std::uint64_t)ipv6[14] << 8) | ((std::uint64_t)ipv6[15]),
            makeIPv6Zone(zone)
        };
    }

    static IPAddress MakeIPv6(std::uint64_t hi, std::uint64_t lo)
    {
        return IPAddress{hi, lo, &IPAddress::IPv6NoZone};
    }

    static IPAddress MakeIPv6(std::uint64_t hi, std::uint64_t lo, std::string_view zone)
    {
        return IPAddress{hi, lo, makeIPv6Zone(zone)};
    }

    /// \brief Parse an IPv4 or IPv6 address. Recognizes all formats described
    /// in RFC 4291.
    /// \param noZone Fail if the address requires storing a
    /// zone identifier.
    /// \retrun Returns `RequiresZone` if the address specifies a zone, but
    /// `noZone` is true.
    static Maybe<IPAddress> Parse(std::string_view text, bool noZone = false) noexcept;

    bool operator==(const IPAddress& other) const
    {
        return (*this <=> other) == 0;
    }

    std::strong_ordering operator<=>(const IPAddress& other) const
    {
        if (addrInfo->type != other.addrInfo->type) {
            return addrInfo->type <=> other.addrInfo->type;
        }
        if (is4()) {
            return (lo & 0xffff'ffff) <=> (other.lo & 0xffff'ffff);
        } else {
            if (addrInfo->zone != other.addrInfo->zone) {
                return addrInfo->zone <=> other.addrInfo->zone;
            } else {
                auto order = hi <=> other.hi;
                if (order == std::strong_ordering::equal)
                    return lo <=> other.lo;
                else
                    return order;
            }
        }
    }

    /// \brief Compute the sum of 16-bit big endian words in the address.
    std::uint32_t checksum() const
    {
        using scion::details::byteswapBE;
        std::uint32_t sum = 0;
        for (int i = 0; i < 4; ++i) {
            sum += (lo >> (16*i)) & 0xffff;
            sum += (hi >> (16*i)) & 0xffff;
        }
        return sum;
    }

    /// \brief Tell whether the address is the unspecified wildcard.
    bool isUnspecified() const
    {
        return hi == 0 && lo == 0;
    }

    /// \brief Tell whether this is an IPv4 address, but not an IPv4-mapped IPv6.
    bool is4() const { return addrInfo->type == AddrType::IPv4; }

    /// \brief Tell whether this is an IPv4-mapped IPv6 address.
    bool is4in6() const { return is6() && hi == 0 && (lo >> 16) & 0xffffllu; }

    /// \brief Tell whether this is an IPv6 address including IP4 mapped to IPv6.
    bool is6() const { return addrInfo->type == AddrType::IPv6; }

    /// \brief Tell whether this is a SCION-mapped IPv6 address.
    bool isScion() const { return is6() && ((hi >> 56) & 0xff) == 0xfc; }

    /// \brief Tell whether this is a SCION-IPv4-mapped IPv6 address.
    bool isScion4() const { return isScion() && (hi & 0xff'fffful) == 0 && (lo >> 32) & 0xffffllu; }

    /// \brief Tell whether this is a SCION-IPv6-mapped IPv6 address.
    bool isScion6() const { return isScion() && ((hi & 0xff'fffful) != 0 || (lo >> 32) != 0xffffllu); }

    /// \brief Unmaps IPv4-mapped IPv6 addresses to regular IPv4. Returns a copy
    /// of the address if it is not a 4-in-6 address.
    IPAddress unmap4in6() const
    {
        if (is4in6())
            return IPAddress{hi, lo & 0xffff'ffffull, &IPAddress::IPv4};
        else
            return *this;
    }

    /// \brief Encode an IPv4 address as IPv4-mapped IPv6. Returns a copy of the
    /// address if it is not an IPv4.
    IPAddress map4in6() const
    {
        if (is4())
            return IPAddress{0, (0xffffull << 32) | (lo & 0xffff'ffffull), &IPv6NoZone};
        else
            return *this;
    }

    /// \brief Get IPv4 address as big-endian integer.
    std::uint32_t getIPv4() const { assert(is4()); return std::uint32_t(lo); }

    /// \brief Get IPv6 address as two big-endian integers.
    std::pair<std::uint64_t, std::uint64_t> getIPv6() const
    {
        return std::make_pair(hi, lo);
    }

    /// \brief Returns true if the address has an IPv6 interface identifier.
    bool hasZone() const { return !addrInfo->zone.empty(); }

    /// \brief Get the zone identifier or an empty string if there is none.
    std::string_view getZone() const { return addrInfo->zone; }

    /// \brief Copy IPv4 address into byte array.
    void toBytes4(std::span<std::byte, 4> bytes) const
    {
        assert(is4());
        for (int i = 0; i < 4; ++i)
            bytes[i] = std::byte((lo >> 8*(3-i)) & 0xff);
    }

    /// \brief Copy IPv6 address into byte array.
    void toBytes16(std::span<std::byte, 16> bytes) const
    {
        assert(is6());
        for (int i = 0; i < 8; ++i)
            bytes[i] = std::byte((hi >> 8*(7-i)) & 0xff);
        for (int i = 0; i < 8; ++i)
            bytes[8+i] = std::byte((lo >> 8*(7-i)) & 0xff);
    }

    std::size_t size() const { return is4() ? 4 : 16; }

    /// \brief (De-)serialize an IP address.
    /// \param v4 True if the address is expected to be a 4-byte IPv4, false
    /// if a 16-byte IPv6 is expected.
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, bool v4, Error& err)
    {
        if constexpr (Stream::IsWriting) {
            if (v4 != is4()) {
                return err.error("address type does not match expectation");
            }
        } else {
            hi = 0;
            lo = 0;
            addrInfo = v4 ? &IPv4 : &IPv6NoZone;
        }
        if (v4) {
            auto ip = (std::uint32_t)lo;
            if (!stream.serializeUint32(ip, err)) return err.propagate();
            if constexpr (Stream::IsReading) {
                lo = (std::uint64_t)ip;
            }
        } else {
            if (!stream.serializeUint64(hi, err)) return err.propagate();
            if (!stream.serializeUint64(lo, err)) return err.propagate();
        }
        return true;
    }

    friend struct std::hash<scion::generic::IPAddress>;
    friend struct std::hash<scion::generic::IPEndpoint>;
    friend std::ostream& operator<<(std::ostream& stream, const IPAddress& addr);

private:
    enum class AddrType : unsigned int
    {
        IPv4,
        IPv6,
    };

    // Type for statically allocated AddrInfo sentinels.
    // Does not count references.
    struct AddrInfo
    {
        constexpr AddrInfo(AddrType type, std::string_view zone)
            : type(type), zone(zone)
        {}

        virtual ~AddrInfo() {}
        virtual void addRef() const noexcept {}
        virtual void release() const noexcept {}

        AddrType type;
        std::string zone;
    };

    // Dynamically allocated AddrInfo. Counts references.
    friend struct DynamicAddrInfo;

    friend void intrusive_ptr_add_ref(const IPAddress::AddrInfo* d) noexcept
    { d->addRef(); }
    friend void intrusive_ptr_release(const IPAddress::AddrInfo* d) noexcept
    { d->release(); }

    // Sentinels
    static const AddrInfo IPv4;       // IPv4 address
    static const AddrInfo IPv6NoZone; // IPv6 address without zone string

    IPAddress(
        std::uint64_t hi, std::uint64_t lo, boost::intrusive_ptr<const AddrInfo> info)
        : hi(hi), lo(lo), addrInfo(std::move(info))
    {}

    static boost::intrusive_ptr<const AddrInfo> makeIPv6Zone(std::string_view zone);

    std::format_context::iterator formatTo(
        std::format_context::iterator out, bool longForm, bool upperCase) const;

    friend struct std::formatter<scion::generic::IPAddress>;

private:
    // Stores 128-bit IPv6 address in two 64-bit integers in host byte order.
    // IPv4 addresses are stored as IPv4-mapped IPv6. Mapped IPv4 is
    // distinguished from native IPv4 by `addrInfo->type`.
    std::uint64_t hi = 0;
    std::uint64_t lo = 0;

    // Discriminates between IPv4 and IPv6 and contains the zone identifier.
    // Must bot be null.
    boost::intrusive_ptr<const AddrInfo> addrInfo;
};

class IPEndpoint
{
public:
    /// \brief Construct "[::]:0"
    IPEndpoint() = default;

    /// \brief Construct from host address and port.
    IPEndpoint(IPAddress host, std::uint16_t port)
        : host(host), port(port)
    {}

    /// \brief Returns the unspecified IPv4 endpoint "0.0.0.0:0".
    static IPEndpoint UnspecifiedIPv4()
    {
        return {IPAddress::UnspecifiedIPv4(), 0};
    }

    /// \brief Returns the unspecified IPv6 endpoint "[::]:0",
    static IPEndpoint UnspecifiedIPv6()
    {
        return {IPAddress::UnspecifiedIPv6(), 0};
    }

    const IPAddress& getHost() const { return host; }
    std::uint16_t getPort() const { return port; }

    /// Parse an endpoint of the format "[<IP>]:<Port>" where IP is an IPv4 or
    /// IPv6 address and Port is a valid decimal port number. The colon and port
    /// number may be are omitted if the port is 0. The square brackets are
    /// optional for IPv4 addresses.
    /// \param noZone Fail if the IP address requires storing a
    /// zone identifier.
    /// \retrun Returns `RequiresZone` if the address specifies a zone, but
    /// `noZone` is true.
    static Maybe<IPEndpoint> Parse(std::string_view text, bool noZone = false) noexcept;

    bool operator==(const IPEndpoint& other) const
    {
        return host == other.host && port == other.port;
    }

    std::strong_ordering operator<=>(const IPEndpoint& other) const
    {
        auto order = host <=> other.host;
        if (order == std::strong_ordering::equal)
            return port <=> other.port;
        else
            return order;
    }

    friend struct std::hash<scion::generic::IPEndpoint>;
    friend std::ostream& operator<<(std::ostream& stream, const IPEndpoint& addr);

private:
    IPAddress host;
    std::uint16_t port = 0;
};

/// \brief Convert an underlay-specific IPv4 or IPv6 address to a generic IP
/// address.
template <typename T>
IPAddress toGenericAddr(const T& addr)
{
    std::array<std::byte, 16> bytes;
    [[maybe_unused]] auto ec = AddressTraits<T>::toBytes(addr, bytes);
    assert(!ec);
    if (AddressTraits<T>::type(addr) == HostAddrType::IPv4) {
        return IPAddress::MakeIPv4(std::span<std::byte, 4>(bytes.data(), bytes.data() + 4));
    } else {
        return IPAddress::MakeIPv6(bytes);
    }
}

/// \brief Convert a generic IP address to an underlay-specific one.
template <typename T>
Maybe<T> toUnderlay(const IPAddress& addr)
{
    if (addr.is4()) {
        std::array<std::byte, 4> bytes;
        addr.toBytes4(bytes);
        auto res = AddressTraits<T>::fromBytes(bytes);
        if (isError(res)) return res;
        return get(res);
    } else {
        std::array<std::byte, 16> bytes;
        addr.toBytes16(bytes);
        auto res = AddressTraits<T>::fromBytes(bytes);
        if (isError(res)) return res;
        return get(res);
    }
}

/// \brief Convert an underlay-specific IPv4 or IPv6 address to a generic IP
/// address.
template <typename T>
IPEndpoint toGenericEp(const T& ep)
{
    using AddrType = EndpointTraits<T>::HostAddr;
    const auto& addr = EndpointTraits<T>::getHost(ep);
    const auto port = EndpointTraits<T>::getPort(ep);
    std::array<std::byte, 16> bytes;
    [[maybe_unused]] auto ec = AddressTraits<AddrType>::toBytes(addr, bytes);
    assert(!ec);
    if (AddressTraits<AddrType>::type(addr) == HostAddrType::IPv4) {
        return IPEndpoint(
            generic::IPAddress::MakeIPv4(
                std::span<std::byte, 4>(bytes.data(), bytes.data() + 4)), port);
    } else {
        return IPEndpoint(generic::IPAddress::MakeIPv6(bytes), port);
    }
}

/// \brief Convert a generic endpoint to an underlay-specific one.
template <typename T>
Maybe<T> toUnderlay(const IPEndpoint& ep)
{
    using AddrType = EndpointTraits<T>::HostAddr;
    auto host = toUnderlay<AddrType>(ep.getHost());
    if (isError(host)) return propagateError(host);
    return EndpointTraits<T>::fromHostPort(get(host), ep.getPort());
}

} // namespace generic
} // namespace scion

namespace scion {

using ScIPAddress = Address<generic::IPAddress>;
using ScIPEndpoint = Endpoint<generic::IPEndpoint>;

} // namespace scion

template <>
struct scion::AddressTraits<scion::generic::IPAddress>
{
    using HostAddr = scion::generic::IPAddress;

    static HostAddrType type(const HostAddr& addr) noexcept
    {
        return addr.is4() ? HostAddrType::IPv4 : HostAddrType::IPv6;
    }

    static std::size_t size(const HostAddr& addr) noexcept
    {
        return addr.size();
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        return addr.isUnspecified();
    }

    static std::uint32_t checksum(const HostAddr& addr) noexcept
    {
        return addr.checksum();
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte> bytes) noexcept
    {
        if (addr.is4()) {
            if (bytes.size() < 4) return ErrorCode::BufferTooSmall;
            addr.toBytes4(std::span<std::byte, 4>(bytes));
        } else {
            if (bytes.size() < 16) return ErrorCode::BufferTooSmall;
            addr.toBytes16(std::span<std::byte, 16>(bytes));
        }
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        const auto size = bytes.size();
        if (size == 4)
            return HostAddr::MakeIPv4(std::span<const std::byte, 4>(bytes));
        else if (size == 16)
            return HostAddr::MakeIPv6(std::span<const std::byte, 16>(bytes));
        else
            return Error(ErrorCode::InvalidArgument);
    }

    static Maybe<HostAddr> fromString(std::string_view text) noexcept
    {
        return HostAddr::Parse(text);
    }
};

template <>
struct scion::EndpointTraits<scion::generic::IPEndpoint>
{
    using LocalEp = scion::generic::IPEndpoint;
    using HostAddr = scion::generic::IPAddress;
    using ScionAddr = scion::Address<HostAddr>;

    static LocalEp fromHostPort(HostAddr host, std::uint16_t port) noexcept
    {
        return LocalEp(host, port);
    }

    static HostAddr getHost(const LocalEp& ep) noexcept
    {
        return ep.getHost();
    }

    static std::uint16_t getPort(const LocalEp& ep) noexcept
    {
        return ep.getPort();
    }
};

template <>
struct std::formatter<scion::generic::IPAddress>
{
    constexpr auto parse(auto& ctx)
    {
        auto i = ctx.begin();
        for (; i != ctx.end() && *i != '}'; ++i) {
            switch (*i) {
            case 'l':
                longForm = true;
                break;
            case 'x':
                upperCaseHex = false;
                break;
            case 'X':
                upperCaseHex = true;
                break;
            default:
                throw std::format_error("failed to parse format-spec");
            }
        }
        return i;
    }

    auto format(const scion::generic::IPAddress& addr, auto& ctx) const
    {
        return addr.formatTo(ctx.out(), longForm, upperCaseHex);
    }

private:
    bool longForm = false;
    bool upperCaseHex = false;
};

template <>
struct std::formatter<scion::generic::IPEndpoint>
{
    constexpr auto parse(auto& ctx)
    {
        return ipFormatter.parse(ctx);
    }

    auto format(const scion::generic::IPEndpoint& ep, auto& ctx) const
    {
        if (ep.getHost().is4()) {
            auto out = ipFormatter.format(ep.getHost(), ctx);
            return std::format_to(out, ":{}", ep.getPort());
        } else {
            auto out = ctx.out();
            out++ = '[';
            out = ipFormatter.format(ep.getHost(), ctx);
            return std::format_to(out, "]:{}", ep.getPort());
        }
    }

private:
    std::formatter<scion::generic::IPAddress> ipFormatter;
};

template <>
struct std::hash<scion::generic::IPAddress>
{
    std::size_t operator()(const scion::generic::IPAddress& ip) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            if (ip.is4()) {
                scion::details::MurmurHash3_x86_32(&ip.lo, sizeof(ip.lo), seed, &h);
            } else {
                std::uint64_t value[] = {ip.hi, ip.lo};
                scion::details::MurmurHash3_x86_32(&value, sizeof(value), seed, &h);
            }
            return h;
        } else {
            std::uint64_t h[2] = {};
            if (ip.is4()) {
                scion::details::MurmurHash3_x64_128(&ip.lo, sizeof(ip.lo), seed, &h);
            } else {
                std::uint64_t value[] = {ip.hi, ip.lo};
                scion::details::MurmurHash3_x64_128(&value, sizeof(value), seed, &h);
            }
            return h[0] ^ h[1];
        }
    }
};

template <>
struct std::hash<scion::generic::IPEndpoint>
{
    std::size_t operator()(const scion::generic::IPEndpoint& ep) const noexcept
    {
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            if (ep.host.is4()) {
                std::uint64_t value[] = {ep.host.lo, ep.port};
                scion::details::MurmurHash3_x86_32(&value, sizeof(value), seed, &h);
            } else {
                std::uint64_t value[] = {ep.host.hi, ep.host.lo, ep.port};
                scion::details::MurmurHash3_x86_32(&value, sizeof(value), seed, &h);
            }
            return h;
        } else {
            std::uint64_t h[2] = {};
            if (ep.host.is4()) {
                std::uint64_t value[] = {ep.host.lo, ep.port};
                scion::details::MurmurHash3_x64_128(&value, sizeof(value), seed, &h);
            } else {
                std::uint64_t value[] = {ep.host.hi, ep.host.lo, ep.port};
                scion::details::MurmurHash3_x64_128(&value, sizeof(value), seed, &h);
            }
            return h[0] ^ h[1];
        }
    }
};
