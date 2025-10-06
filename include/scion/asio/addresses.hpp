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
#include "scion/addr/isd_asn.hpp"
#include "scion/error_codes.hpp"
#include "scion/murmur_hash3.h"

#include <boost/asio.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>


namespace scion {

template <>
struct AddressTraits<boost::asio::ip::address_v4>
{
    using HostAddr = boost::asio::ip::address_v4;

    static HostAddrType type(const HostAddr&) noexcept
    {
        return HostAddrType::IPv4;
    }

    static std::size_t size(const HostAddr& addr) noexcept
    {
        return 4;
    }

    static bool is4in6(const HostAddr& addr) noexcept
    {
        return false;
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        return addr.is_unspecified();
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte, 4> bytes) noexcept
    {
        auto temp = addr.to_bytes();
        std::copy(temp.begin(), temp.end(), reinterpret_cast<std::uint8_t*>(bytes.data()));
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        if (bytes.size() != 4) return Error(ErrorCode::InvalidArgument);
        HostAddr::bytes_type temp;
        std::copy(bytes.begin(), bytes.end(), reinterpret_cast<std::byte*>(temp.data()));
        return HostAddr(temp);
    }

    static Maybe<HostAddr> fromString(std::string_view str) noexcept
    {
        boost::system::error_code ec;
        auto addr = boost::asio::ip::make_address_v4(str, ec);
        if (!ec) return addr;
        else return Error(ec);
    }
};

template <>
struct AddressTraits<boost::asio::ip::address_v6>
{
    using HostAddr = boost::asio::ip::address_v6;

    static HostAddrType type(const HostAddr&) noexcept
    {
        return HostAddrType::IPv6;
    }

    static std::size_t size(const HostAddr& addr) noexcept
    {
        return 16;
    }

    static bool is4in6(const HostAddr& addr) noexcept
    {
        return addr.is_v4_mapped();
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        using namespace boost::asio::ip;
        if (AddressTraits<HostAddr>::is4in6(addr))
            return addr == make_address_v6(v4_mapped, address_v4());
        else
            return addr.is_unspecified();
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte, 16> bytes) noexcept
    {
        auto temp = addr.to_bytes();
        std::copy(temp.begin(), temp.end(), reinterpret_cast<std::uint8_t*>(bytes.data()));
        return ErrorCode::Ok;
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        if (bytes.size() != 16) return Error(ErrorCode::InvalidArgument);
        HostAddr::bytes_type temp;
        std::copy(bytes.begin(), bytes.end(), reinterpret_cast<std::byte*>(temp.data()));
        return HostAddr(temp);
    }

    static Maybe<HostAddr> fromString(std::string_view str) noexcept
    {
        std::error_code ec;
        auto addr = boost::asio::ip::make_address_v6(str);
        if (!ec) return addr;
        else return Error(ec);
    }
};

template <>
struct AddressTraits<boost::asio::ip::address>
{
    using HostAddr = boost::asio::ip::address;

    static HostAddrType type(const HostAddr& addr) noexcept
    {
        return addr.is_v4() ? HostAddrType::IPv4 : HostAddrType::IPv6;
    }

    static std::size_t size(const HostAddr& addr) noexcept
    {
        return addr.is_v4() ? 4 : 16;
    }

    static bool is4in6(const HostAddr& addr) noexcept
    {
        return addr.is_v6() && addr.to_v6().is_v4_mapped();
    }

    static bool isUnspecified(const HostAddr& addr) noexcept
    {
        using namespace boost::asio::ip;
        if (AddressTraits<HostAddr>::is4in6(addr))
            return addr == make_address_v6(v4_mapped, address_v4());
        else
            return addr.is_unspecified();
    }

    static std::error_code toBytes(const HostAddr& addr, std::span<std::byte> bytes) noexcept
    {
        if (addr.is_v4()) {
            if (bytes.size() < 4) return ErrorCode::BufferTooSmall;
            return AddressTraits<boost::asio::ip::address_v4>::toBytes(
                addr.to_v4(), std::span<std::byte, 4>(bytes));
        } else {
            if (bytes.size() < 16) return ErrorCode::BufferTooSmall;
            return AddressTraits<boost::asio::ip::address_v6>::toBytes(
                addr.to_v6(), std::span<std::byte, 16>(bytes));
        }
    }

    static Maybe<HostAddr> fromBytes(std::span<const std::byte> bytes) noexcept
    {
        using namespace boost::asio;
        const auto size = bytes.size();
        if (size == 4) {
            auto addr = AddressTraits<ip::address_v4>::fromBytes(bytes);
            return addr.transform([] (auto&& x) { return HostAddr(x); });
        } else if (size == 16) {
            auto addr = AddressTraits<ip::address_v6>::fromBytes(bytes);
            return addr.transform([] (auto&& x) { return HostAddr(x); });
        } else {
            return Error(ErrorCode::InvalidArgument);
        }
    }

    static Maybe<HostAddr> fromString(std::string_view str) noexcept
    {
        boost::system::error_code ec;
        auto addr = boost::asio::ip::make_address(str, ec);
        if (!ec) return addr;
        else return Error(ec);
    }
};

template <typename Protocol>
struct EndpointTraits<boost::asio::ip::basic_endpoint<Protocol>>
{
    using LocalEp = boost::asio::ip::basic_endpoint<Protocol>;
    using HostAddr = boost::asio::ip::address;
    using ScionAddr = scion::Address<HostAddr>;

    static LocalEp fromHostPort(HostAddr host, std::uint16_t port) noexcept
    {
        return LocalEp(host, port);
    }

    static HostAddr host(const LocalEp& ep) noexcept
    {
        return ep.address();
    }

    static std::uint16_t port(const LocalEp& ep) noexcept
    {
        return ep.port();
    }
};

} // namespace scion

template <>
struct std::formatter<boost::asio::ip::address_v4>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const boost::asio::ip::address_v4& ip, auto& ctx) const
    {
        auto out = ctx.out();
        auto str = ip.to_string();
        return std::copy(str.begin(), str.end(), out);
    }
};

template <>
struct std::formatter<boost::asio::ip::address_v6>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const boost::asio::ip::address_v6& ip, auto& ctx) const
    {
        auto out = ctx.out();
        auto str = ip.to_string();
        return std::copy(str.begin(), str.end(), out);
    }
};

template <>
struct std::formatter<boost::asio::ip::address>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const boost::asio::ip::address& ip, auto& ctx) const
    {
        auto out = ctx.out();
        auto str = ip.to_string();
        return std::copy(str.begin(), str.end(), out);
    }
};

template <typename Protocol>
struct std::formatter<boost::asio::ip::basic_endpoint<Protocol>>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const boost::asio::ip::udp::endpoint& ep, auto& ctx) const
    {
        if (ep.address().is_v4())
            return std::format_to(ctx.out(), "{}:{}", ep.address(), ep.port());
        else
            return std::format_to(ctx.out(), "[{}]:{}", ep.address(), ep.port());
    }
};
