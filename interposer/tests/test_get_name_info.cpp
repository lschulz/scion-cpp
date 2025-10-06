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
#include "scion/addr/generic_ip.hpp"
#include "scion/addr/mapping.hpp"
#include "scion/details/c_interface.hpp"
#include "scion/posix/sockaddr.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <ranges>

using std::uint16_t;


TEST(GetNameInfoTest, NativeScion)
{
    using namespace scion;

    sockaddr_scion addr = {};
    addr.sscion_family = AF_SCION;
    addr.sscion_addr = details::addr_cast(unwrap(ScIPAddress::Parse("1-ff00:0:1,127.0.0.1")));
    addr.sscion_port = details::byteswapBE<uint16_t>(443);

    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');
    std::array<char, 8> service;
    std::ranges::fill(service, 'X');

    int res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), service.data(), service.size(), 0);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(host.data(), "1-ff00:0:1,127.0.0.1");
    EXPECT_STREQ(service.data(), "https");

    res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), service.data(), service.size(), NI_NUMERICHOST | NI_NUMERICSERV);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(host.data(), "1-ff00:0:1,127.0.0.1");
    EXPECT_STREQ(service.data(), "443");

    res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), service.data(), service.size(), NI_NAMEREQD);
    ASSERT_EQ(res, EAI_NONAME);
}

TEST(GetNameInfoTest, MappedScion)
{
    using namespace scion;

    sockaddr_in6 addr = EndpointTraits<sockaddr_in6>::fromHostPort(
        unwrap(ScIPAddress::Parse("1-64496,127.0.0.1")
        .and_then(mapToIPv6)
        .and_then([] (const scion::generic::IPAddress& x) {
            return generic::toUnderlay<in6_addr>(x);
        })),
        0
    );
    addr.sin6_port = details::byteswapBE<uint16_t>(443);

    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');
    std::array<char, 8> service;
    std::ranges::fill(service, 'X');

    int res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), service.data(), service.size(), 0);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(host.data(), "1-64496,127.0.0.1");
    EXPECT_STREQ(service.data(), "https");
}

TEST(GetNameInfoTest, Surrogate)
{
    using namespace scion;

    sockaddr_in6 addr = {};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = unwrap(AddressTraits<in6_addr>::fromString("fc00::1000"));

    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');

    int res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), nullptr, 0, 0);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(host.data(), "1-64496,::1");
}

// Test behavior when an IPv6 address is expected, but the interceptor delivers
// a longer SCION-IPv6 address.
TEST(GetNameInfoTest, ShortBuffer)
{
    using namespace scion;

    sockaddr_in6 addr = EndpointTraits<sockaddr_in6>::fromHostPort(
        unwrap(ScIPAddress::Parse("4095-2:7:ffff,fcff:ffff:ffaa:aabb:1234:5678:9abc:def0")
        .and_then(mapToIPv6)
        .and_then([] (const scion::generic::IPAddress& x) {
            return generic::toUnderlay<in6_addr>(x);
        })),
        0
    );

    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');

    int res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), INET6_ADDRSTRLEN, nullptr, 0, 0);
    ASSERT_EQ(res, EAI_OVERFLOW);

    res = interposer_getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
        host.data(), host.size(), nullptr, 0, 0);
    ASSERT_EQ(res, 0);
    EXPECT_STREQ(host.data(), "4095-2:7:ffff,fcff:ffff:ffaa:aabb:1234:5678:9abc:def0");
}

TEST(InetPtoNTest, NativeScion)
{
    using namespace scion;

    scion_addr addr = {};
    int res = interposer_inet_pton(AF_SCION, "1-64496,127.0.0.1", &addr);
    ASSERT_EQ(res, 1);

    EXPECT_EQ(addr.sscion_isd_asn, details::byteswapBE(
        std::uint64_t(unwrap(scion::IsdAsn::Parse("1-64496")))));
    EXPECT_EQ(addr.sscion_host_type, SCION_IPv4);
    EXPECT_EQ(addr.sscion_scope_id, 0);
    EXPECT_THAT(addr.u.sscion_addr32, testing::ElementsAre(
        details::byteswapBE(0x7f000001u), 0, 0, 0)
    );
}

TEST(InetPtoNTest, MappedScion)
{
    using namespace scion;

    in6_addr addr = {};
    int res = interposer_inet_pton(AF_INET6, "1-64496,fc00:10fb:f000::ffff:7f00:1", &addr);
    ASSERT_EQ(res, 1);
    EXPECT_THAT(
        (std::span<char, 16>(reinterpret_cast<char*>(&addr), 16)),
        testing::ElementsAre(0xfc, 0, 0x10, 0xfb, 0xf0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1)
    );
}

TEST(InetNtoPTest, NativeScion)
{
    using namespace scion;

    auto addr = details::addr_cast(unwrap(ScIPAddress::Parse("1-ff00:0:1,127.0.0.1")));
    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');

    const char* res = interposer_inet_ntop(AF_SCION, &addr, host.data(), host.size());
    EXPECT_EQ(res, host.data());
    EXPECT_STREQ(host.data(), "1-ff00:0:1,127.0.0.1");
}

TEST(InetNtoPTest, MappedScion)
{
    using namespace scion;

    in6_addr addr = unwrap(
        ScIPAddress::Parse("4095-2:7:ffff,fcff:ffff:ffaa:aabb:1234:5678:9abc:def0")
        .and_then(mapToIPv6)
        .and_then([] (const scion::generic::IPAddress& x) {
            return generic::toUnderlay<in6_addr>(x);
        })
    );

    std::array<char, SCION_ADDRSTRLEN> host;
    std::ranges::fill(host, 'X');

    const char* res = interposer_inet_ntop(AF_INET6, &addr, host.data(), INET6_ADDRSTRLEN);
    EXPECT_EQ(res, nullptr);
    EXPECT_EQ(errno, ENOSPC);

    res = interposer_inet_ntop(AF_INET6, &addr, host.data(), host.size());
    EXPECT_EQ(res, host.data());
    EXPECT_STREQ(host.data(), "4095-2:7:ffff,fcff:ffff:ffaa:aabb:1234:5678:9abc:def0");
}
