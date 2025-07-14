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

#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/asio/addresses.hpp"
#include "scion/posix/sockaddr.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <format>
#include <system_error>
#include <variant>


template <typename T>
class ScionIPv4AddrTest : public testing::Test
{};

using IPv4Types = testing::Types<
    scion::generic::IPAddress,
    scion::posix::IPAddress,
    in_addr,
    boost::asio::ip::address_v4,
    boost::asio::ip::address
>;
TYPED_TEST_SUITE(ScionIPv4AddrTest, IPv4Types);

TYPED_TEST(ScionIPv4AddrTest, AddressTraits)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using AddrTraits = AddressTraits<HostAddr>;

    std::array<std::byte, 4> in = {10_b, 255_b, 0_b, 1_b};
    std::array<std::byte, 4> out = {};

    auto ip = unwrap(AddrTraits::fromBytes(in));
    EXPECT_FALSE(AddrTraits::toBytes(ip, out));
    EXPECT_THAT(out, testing::ElementsAreArray(in));

    EXPECT_EQ(AddrTraits::type(ip), HostAddrType::IPv4);
    EXPECT_EQ(AddrTraits::size(ip), 4);

    EXPECT_EQ(unwrap(AddrTraits::fromString("10.255.0.1")), ip);
    EXPECT_EQ(std::format("{}", ip), "10.255.0.1");
}

TYPED_TEST(ScionIPv4AddrTest, ScionAddress)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    IsdAsn ia2(Isd(2), Asn(0xff00'0000'0002));
    auto ip1 = unwrap(AddrTraits::fromString("127.0.0.1"));
    auto ip2 = unwrap(AddrTraits::fromString("127.0.0.2"));

    Address addr(ia1, ip1);
    EXPECT_EQ(ia1, addr.isdAsn());
    EXPECT_EQ(ip1, addr.host());

    EXPECT_EQ(Address(ia1, ip1), addr);
    EXPECT_GT(Address(ia2, ip2), addr);

    EXPECT_TRUE(addr.matches(addr));
    EXPECT_FALSE(addr.matches(Address(ia1, ip2)));
    EXPECT_FALSE(addr.matches(Address(ia2, ip1)));
    EXPECT_TRUE(Address(ia1, HostAddr()).matches(addr));

    std::hash<Address> h;
    EXPECT_NE(h(Address(ia2, ip1)), h(addr));
    EXPECT_EQ(h(Address(ia1, ip1)), h(addr));
}

TYPED_TEST(ScionIPv4AddrTest, Parse)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ip1 = unwrap(AddrTraits::fromString("127.0.0.1"));

    EXPECT_EQ(unwrap(Address::Parse("1-ff00:0:1,127.0.0.1")),
        Address(ia1, ip1));
    EXPECT_EQ(unwrap(Address::Parse("1-1,127.0.0.1")),
        Address(IsdAsn(Isd(1), Asn(1)), ip1));

    EXPECT_TRUE(hasFailed(Address::Parse("")));
    EXPECT_TRUE(hasFailed(Address::Parse(",")));
    EXPECT_TRUE(hasFailed(Address::Parse("1-ff00:0:1,")));
    EXPECT_TRUE(hasFailed(Address::Parse(",127.0.0.1")));
    EXPECT_TRUE(hasFailed(Address::Parse("[1-ff00:0:1,127.0.0.1]")));
}

TYPED_TEST(ScionIPv4AddrTest, Format)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    Address addr(
        IsdAsn(Isd(1), Asn(0xff00'0000'0001)),
        unwrap(AddrTraits::fromString("127.0.0.1")));
    EXPECT_EQ(std::format("{}", addr), "1-ff00:0:1,127.0.0.1");
}

template <typename T>
class ScionIPv6AddrTest : public testing::Test
{};

using IPv6Types = testing::Types<
    scion::generic::IPAddress,
    scion::posix::IPAddress,
    in6_addr,
    boost::asio::ip::address_v6,
    boost::asio::ip::address
>;
TYPED_TEST_SUITE(ScionIPv6AddrTest, IPv6Types);

TYPED_TEST(ScionIPv6AddrTest, AddressTraits)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using AddrTraits = AddressTraits<HostAddr>;

    std::array<std::byte, 16> in = {
        0xfc_b, 0x00_b, 0x01_b, 0x02_b, 0x03_b, 0x04_b, 0x05_b, 0x06_b,
        0x07_b, 0x08_b, 0x09_b, 0x0a_b, 0x0b_b, 0x0c_b, 0x0d_b, 0x0e_b,
    };
    std::array<std::byte, 16> out = {};

    auto ip = unwrap(AddrTraits::fromBytes(in));
    EXPECT_FALSE(AddrTraits::toBytes(ip, out));
    EXPECT_THAT(out, testing::ElementsAreArray(in));

    EXPECT_EQ(AddrTraits::type(ip), HostAddrType::IPv6);
    EXPECT_EQ(AddrTraits::size(ip), 16);

    EXPECT_EQ(
        unwrap(AddrTraits::fromString("fc00:102:304:506:708:90a:b0c:d0e")),
        ip);
    EXPECT_EQ(std::format("{}", ip), "fc00:102:304:506:708:90a:b0c:d0e");
}

TYPED_TEST(ScionIPv6AddrTest, ScionAddress)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    IsdAsn ia2(Isd(2), Asn(0xff00'0000'0002));
    auto ip1 = unwrap(AddrTraits::fromString("::1"));
    auto ip2 = unwrap(AddrTraits::fromString("::2"));

    Address addr(ia1, ip1);
    EXPECT_EQ(ia1, addr.isdAsn());
    EXPECT_EQ(ip1, addr.host());

    EXPECT_EQ(Address(ia1, ip1), addr);
    EXPECT_GT(Address(ia2, ip2), addr);

    EXPECT_TRUE(addr.matches(addr));
    EXPECT_FALSE(addr.matches(Address(ia1, ip2)));
    EXPECT_FALSE(addr.matches(Address(ia2, ip1)));
    EXPECT_TRUE(Address(ia1, HostAddr()).matches(addr));

    std::hash<Address> h;
    EXPECT_NE(h(Address(ia2, ip1)), h(addr));
    EXPECT_EQ(h(Address(ia1, ip1)), h(addr));
}

TYPED_TEST(ScionIPv6AddrTest, Parse)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ip1 = unwrap(AddrTraits::fromString("::1"));

    EXPECT_EQ(unwrap(Address::Parse("1-ff00:0:1,::1")),
        Address(ia1, ip1));
    EXPECT_EQ(unwrap(Address::Parse("1-1,::1")),
        Address(IsdAsn(Isd(1), Asn(1)), ip1));

    EXPECT_TRUE(hasFailed(Address::Parse("")));
    EXPECT_TRUE(hasFailed(Address::Parse(",")));
    EXPECT_TRUE(hasFailed(Address::Parse("::1,")));
    EXPECT_TRUE(hasFailed(Address::Parse(",::1")));
    EXPECT_TRUE(hasFailed(Address::Parse("[1-ff00:0:1,::1]")));
}

TYPED_TEST(ScionIPv6AddrTest, Format)
{
    using namespace scion;
    using HostAddr = TypeParam;
    using Address = scion::Address<HostAddr>;
    using AddrTraits = AddressTraits<HostAddr>;

    Address addr(
        IsdAsn(Isd(1), Asn(0xff00'0000'0001)),
        unwrap(AddrTraits::fromString("::1")));
    EXPECT_EQ(std::format("{}", addr), "1-ff00:0:1,::1");
}
