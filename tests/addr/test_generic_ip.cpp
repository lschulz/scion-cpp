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

#include "scion/addr/generic_ip.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <algorithm>
#include <array>
#include <format>


TEST(GenericIP, IPv4)
{
    using namespace scion::generic;

    std::array<std::byte, 4> bytesIPv4 = {10_b, 255_b, 0_b, 1_b};

    auto ipv4 = IPAddress::MakeIPv4(bytesIPv4);

    EXPECT_TRUE(ipv4.is4());
    EXPECT_FALSE(ipv4.is4in6());
    EXPECT_FALSE(ipv4.is6());
    EXPECT_EQ(ipv4.getZone(), "");

    EXPECT_EQ(ipv4, IPAddress::MakeIPv4(0x0aff0001ul));
    EXPECT_EQ(ipv4.getIPv4(), 0x0aff0001);

    std::array<std::byte, 4> out;
    ipv4.toBytes4(out);
    EXPECT_THAT(out, testing::ElementsAreArray(bytesIPv4));
}

TEST(GenericIP, IPv6)
{
    using namespace scion::generic;

    std::array<std::byte, 16> bytesIPv6 = {
        0xfc_b, 0x00_b, 0x01_b, 0x02_b, 0x03_b, 0x04_b, 0x05_b, 0x06_b,
        0x07_b, 0x08_b, 0x09_b, 0x0a_b, 0x0b_b, 0x0c_b, 0x0d_b, 0x0e_b,
    };

    auto ipv6 = IPAddress::MakeIPv6(bytesIPv6);

    EXPECT_FALSE(ipv6.is4());
    EXPECT_FALSE(ipv6.is4in6());
    EXPECT_TRUE(ipv6.is6());
    EXPECT_EQ(ipv6.getZone(), "");

    EXPECT_EQ(ipv6, IPAddress::MakeIPv6(0xfc00010203040506ul, 0x0708090a0b0c0d0eul));
    EXPECT_EQ(ipv6.getIPv6(), std::make_pair(0xfc00010203040506ul, 0x0708090a0b0c0d0eul));

    std::array<std::byte, 16> out;
    ipv6.toBytes16(out);
    EXPECT_THAT(out, testing::ElementsAreArray(bytesIPv6));
}

TEST(GenericIP, Ordering)
{
    using namespace scion::generic;

    EXPECT_LT(IPAddress::MakeIPv4(0x10ff0000ul), IPAddress::MakeIPv4(0x10ff0001ul));
    EXPECT_LT(IPAddress::MakeIPv4(0x10ff0001ul),
        IPAddress::MakeIPv6(0xfc00010203040506ul, 0x0708090a0b0c0d0eul));
    EXPECT_LT(IPAddress::MakeIPv6(0xfffful, 0x0ul, "eth0"),
        IPAddress::MakeIPv6(0x0ul, 0x0ul, "eth1"));
}

TEST(GenericIP, IPv4in6)
{
    using namespace scion::generic;

    auto ip4 = IPAddress::MakeIPv4(0xaffffff);
    auto ip4in6 = IPAddress::MakeIPv6(0x0, 0xffff'0aff'fffful);

    EXPECT_FALSE(ip4.is4in6());
    EXPECT_TRUE(ip4in6.is4in6());

    EXPECT_EQ(ip4in6.unmap4in6(), ip4);
    EXPECT_EQ(ip4.map4in6(), ip4in6);
}

TEST(GenericIP, ZoneIdentifier)
{
    using namespace std::literals;
    using namespace scion::generic;

    auto a = IPAddress::MakeIPv6(0, 0, "eth0");
    auto b = IPAddress::MakeIPv6(0, 0, "Ethernet 1");
    auto c = IPAddress::MakeIPv6(0, 0, "eth0");

    EXPECT_TRUE(a.is6());
    EXPECT_EQ(a.getZone(), "eth0"sv);

    EXPECT_TRUE(b.is6());
    EXPECT_EQ(b.getZone(), "Ethernet 1"sv);

    EXPECT_TRUE(c.is6());
    EXPECT_EQ(c.getZone(), "eth0"sv);

    EXPECT_NE(a, b);
    EXPECT_EQ(a, c);
    EXPECT_NE(a, IPAddress::MakeIPv6(0, 0));
}

TEST(GenericIP, Format)
{
    using namespace scion::generic;

    // IPv4
    EXPECT_EQ(std::format("{}", IPAddress::MakeIPv4(0xaffffff)), "10.255.255.255");

    // Suppress leading zeros
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul)),
        "fd00:102:304:506:708:90a:b0c:d0e");

    // Compress longest string of zeros
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x0000'0000'0000'fffful)),
        "fd00:0:0:1111::ffff");

    // If two strings of zeros have the same length, compress the first
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x2222'0000'0000'fffful)),
        "fd00::1111:2222:0:0:ffff");

    // Don't compress a single 16-bit field of zeros
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0xfd00'0000'0304'0506ul, 0x0708'090a'0b0c'0d0eul)),
        "fd00:0:304:506:708:90a:b0c:d0e");

    // Compress unspecified address
    EXPECT_EQ(std::format("{}", IPAddress::MakeIPv6(0x0, 0x0)), "::");

    // Zeros at beginning
    EXPECT_EQ(std::format("{}", IPAddress::MakeIPv6(0x0, 0x1)), "::1");

    // Zeros at end
    EXPECT_EQ(std::format("{}", IPAddress::MakeIPv6(0xfd00ull << 48, 0x0)), "fd00::");

    // IPv4-mapped address
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0x0, 0xffff0affffff)),
        "::ffff:10.255.255.255");

    // Optional upper case hex digits
    EXPECT_EQ(std::format("{:X}",
        IPAddress::MakeIPv6(0x0, 0xffff0affffff)),
        "::FFFF:10.255.255.255");

    // Force long form
    EXPECT_EQ(std::format("{:lx}", IPAddress::MakeIPv6(0x0, 0x0)), "0:0:0:0:0:0:0:0");

    // Long form with upper case hex digits
    EXPECT_EQ(std::format("{:lX}", IPAddress::MakeIPv6(0x0, 0xabcd)), "0:0:0:0:0:0:0:ABCD");

    // Address with interface
    EXPECT_EQ(std::format("{}",
        IPAddress::MakeIPv6(0xfe80ull << 48, 0xabcd, "eth0")),
        "fe80::abcd%eth0");
}

TEST(GenericIP, Parse)
{
    using namespace scion::generic;

    // IPv4
    EXPECT_EQ(unwrap(IPAddress::Parse("10.255.255.255")), IPAddress::MakeIPv4(0xaffffff));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10..255.255")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.256.255.255")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.1.2")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.1.2.3.4")));

    // Long-form IPv6
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:102:304:506:708:90a:b0c:d0e")),
        IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00:102:304:506:708:90a:b0c:d0e:ffff")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00:102:304:506:708:90a")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00::304:506:::90a")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("::102:304:506:708:90a:b0c::")));

    // Collapsed IPv6
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:0:0:1111:2222:3333::ffff")),
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x2222'3333'0000'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:0::1111:2222:3333:4444:ffff")),
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x2222'3333'4444'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00::1111:2222:3333:4444:ffff")),
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x2222'3333'4444'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:0:0:1111::ffff")),
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x0000'0000'0000'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("::ffff")),
        IPAddress::MakeIPv6(0x0ul, 0xfffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("ffff::")),
        IPAddress::MakeIPv6(0xffff'0000'0000'0000ul, 0x0ul));
    EXPECT_EQ(unwrap(IPAddress::Parse("::")),
        IPAddress::MakeIPv6(0x0ul, 0x0ul));
    // EXPECT_TRUE(hasFailed(IPAddress::Parse(":0:0:0:0:0:0:0")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("::ffff::")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00::1111::ffff")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00:0::1111:2222:3333:4444:5555:ffff")));

    // IPv4-in-6
    EXPECT_EQ(unwrap(IPAddress::Parse("0:0:0:0:0:ffff:10.255.255.255")),
        IPAddress::MakeIPv6(0x0ul, 0xffff'0aff'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("::ffff:10.255.255.255")),
        IPAddress::MakeIPv6(0x0ul, 0xffff'0aff'fffful));
    EXPECT_EQ(unwrap(IPAddress::Parse("::10.255.255.255")),
        IPAddress::MakeIPv6(0x0ul, 0x0aff'fffful));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("0:0:0:0:10.255.255.255:0:0")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.255.255.255:0:0:0:0:0:0")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.255.255.255::")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("0:0:0:0:10.255.255.255:0:0")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("::10.255.255.255:0")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.255.255.255:0:0:0:0:10.255.255.255")));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.255.255.255::10.255.255.255")));

    // Zone identifier
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:102:304:506:708:90a:b0c:d0e%eth0")),
        IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul, "eth0"));
    EXPECT_EQ(unwrap(IPAddress::Parse("fd00:0:0:1111::ffff%eth0")),
        IPAddress::MakeIPv6(0xfd00'0000'0000'1111ul, 0x0000'0000'0000'fffful, "eth0"));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("fd00:0:0:1111::ffff%eth0", true)));
    EXPECT_TRUE(hasFailed(IPAddress::Parse("10.255.255.255%eth0")));
}

TEST(GenericIP, ScionMapped)
{
    using namespace scion::generic;

    auto scion4 = IPAddress::MakeIPv6(0xfc01'0000'0100'0000ul, 0xffff'0aff'fffful);
    auto scion6 = IPAddress::MakeIPv6(0xfc01'0000'0100'1234ul, 0x0aff'fffful);

    EXPECT_TRUE(scion4.is6());
    EXPECT_TRUE(scion4.isScion());
    EXPECT_TRUE(scion4.isScion4());
    EXPECT_FALSE(scion4.isScion6());

    EXPECT_TRUE(scion6.is6());
    EXPECT_TRUE(scion6.isScion());
    EXPECT_FALSE(scion6.isScion4());
    EXPECT_TRUE(scion6.isScion6());

    EXPECT_EQ(std::format("{}", scion4), "fc01:0:100::ffff:10.255.255.255");
    EXPECT_EQ(std::format("{}", scion6), "fc01:0:100:1234::aff:ffff");
}

TEST(GenericEP, Format)
{
    using namespace scion::generic;

    auto ip4 = IPAddress::MakeIPv4(0x0affffff);
    auto ip6 = IPAddress::MakeIPv6(0x0ul, 0xffff'0aff'fffful, "eth0");

    EXPECT_EQ(std::format("{}", IPEndpoint(ip4, 1024)), "10.255.255.255:1024");
    EXPECT_EQ(std::format("{}", IPEndpoint(ip6, 1024)),
        "[::ffff:10.255.255.255%eth0]:1024");
    EXPECT_EQ(std::format("{:lX}", IPEndpoint(ip6, 1024)),
        "[0:0:0:0:0:FFFF:10.255.255.255%eth0]:1024");
}

TEST(GenericEP, Parse)
{
    using namespace scion::generic;

    auto ip4 = IPAddress::MakeIPv4(0x0affffff);
    auto ip6 = IPAddress::MakeIPv6(0x0ul, 0xffff'0aff'fffful, "eth0");

    EXPECT_EQ(unwrap(IPEndpoint::Parse("10.255.255.255")),
        IPEndpoint(ip4, 0));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("fd00:1:2:3:4:5:6:7")),
        IPEndpoint(IPAddress::MakeIPv6(0xfd00'0001'0002'0003ul, 0x0004'0005'0006'0007ul), 0));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("10.255.255.255:1024")),
        IPEndpoint(ip4, 1024));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("[10.255.255.255]:1024")),
        IPEndpoint(ip4, 1024));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("[::ffff:10.255.255.255%eth0]:1024", false)),
        IPEndpoint(ip6, 1024));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("[0:0:0:0:0:FFFF:10.255.255.255%eth0]:1024", false)),
        IPEndpoint(ip6, 1024));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("[fd00:1:2:3:4:5:6:7]:1000")),
        IPEndpoint(IPAddress::MakeIPv6(0xfd00'0001'0002'0003ul, 0x0004'0005'0006'0007ul), 1000));
    EXPECT_EQ(unwrap(IPEndpoint::Parse("[fd00:1:2:3:4:5:6:7]")),
        IPEndpoint(IPAddress::MakeIPv6(0xfd00'0001'0002'0003ul, 0x0004'0005'0006'0007ul), 0));
    EXPECT_TRUE(hasFailed(IPEndpoint::Parse("10.255.255.255:")));
    EXPECT_TRUE(hasFailed(IPEndpoint::Parse("[fd00:1:2:3:4:5:6:7]:")));
    EXPECT_TRUE(hasFailed(IPEndpoint::Parse("fd00:1:2:3:4:5:6:7:1000")));
    EXPECT_TRUE(hasFailed(IPEndpoint::Parse("[fd00:1:2:3:4:5:6:7:1000")));
    EXPECT_TRUE(hasFailed(IPEndpoint::Parse("fd00:1:2:3:4:5:6:7]:1000")));
}
