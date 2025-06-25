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

#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/asio/addresses.hpp"
#include "scion/bsd/sockaddr.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <array>
#include <format>
#include <system_error>
#include <variant>


template <typename T>
class ScionIPv4EpTest : public testing::Test
{};

using IPv4Types = testing::Types<
    scion::generic::IPEndpoint,
    scion::bsd::IPEndpoint,
    sockaddr_in,
    boost::asio::ip::udp::endpoint
>;
TYPED_TEST_SUITE(ScionIPv4EpTest, IPv4Types);

TYPED_TEST(ScionIPv4EpTest, EndpointTraits)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    auto ip = unwrap(AddrTraits::fromString("10.255.0.1"));
    uint16_t port = 1024;
    auto ep = EpTraits::fromHostPort(ip, port);
    EXPECT_EQ(EpTraits::getHost(ep), ip);
    EXPECT_EQ(EpTraits::getPort(ep), port);
}

TYPED_TEST(ScionIPv4EpTest, Endpoint)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    IsdAsn ia2(Isd(2), Asn(0xff00'0000'0002));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("127.0.0.1")), 50000);
    auto ep2 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("255.255.255.255")), 50001);

    Endpoint endpoint(ia1, ep1);
    EXPECT_EQ(ia1, endpoint.getIsdAsn());
    EXPECT_EQ(ep1, endpoint.getLocalEp());

    EXPECT_EQ(Endpoint(ia1, ep1), endpoint);
    EXPECT_GT(Endpoint(ia2, ep2), endpoint);

    std::hash<Endpoint> h;
    EXPECT_EQ(h(Endpoint(ia1, ep1)), h(endpoint));
    EXPECT_NE(h(Endpoint(ia2, ep1)), h(endpoint));
}

TYPED_TEST(ScionIPv4EpTest, Parse)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("127.0.0.1")), 50000);
    auto ep2 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("127.0.0.1")), 0);

    EXPECT_EQ(unwrap(Endpoint::Parse("[1-ff00:0:1,127.0.0.1]:50000")), Endpoint(ia1, ep1));
    EXPECT_EQ(unwrap(Endpoint::Parse("1-ff00:0:1,127.0.0.1:50000")), Endpoint(ia1, ep1));
    EXPECT_EQ(
        unwrap(Endpoint::Parse("[1-1,127.0.0.1]:50000")),
        Endpoint(IsdAsn(Isd(1), Asn(1)), ep1));
    EXPECT_EQ(unwrap(Endpoint::Parse("1-ff00:0:1,127.0.0.1")), Endpoint(ia1, ep2));
    EXPECT_EQ(unwrap(Endpoint::Parse("[1-ff00:0:1,127.0.0.1]")), Endpoint(ia1, ep2));

    EXPECT_TRUE(hasFailed(Endpoint::Parse("")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(",")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("127.0.0.1")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(",127.0.0.1")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("127.0.0.1:80")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("[1-ff00:0:1,127.0.0.1]:")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(":50000")));
}

TYPED_TEST(ScionIPv4EpTest, Format)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("127.0.0.1")), 50000);

    EXPECT_EQ(std::format("{}", Endpoint(ia1, ep1)), "1-ff00:0:1,127.0.0.1:50000");
}

template <typename T>
class ScionIPv6EpTest : public testing::Test
{};

using IPv6Types = testing::Types<
    scion::generic::IPEndpoint,
    scion::bsd::IPEndpoint,
    sockaddr_in6,
    boost::asio::ip::udp::endpoint
>;
TYPED_TEST_SUITE(ScionIPv6EpTest, IPv6Types);

TYPED_TEST(ScionIPv6EpTest, EndpointTraits)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    auto ip = unwrap(AddrTraits::fromString("fd00:102:304:506:708:90a:b0c:d0e"));
    uint16_t port = 1024;
    auto ep = EpTraits::fromHostPort(ip, port);
    EXPECT_EQ(EpTraits::getHost(ep), ip);
    EXPECT_EQ(EpTraits::getPort(ep), port);
}

TYPED_TEST(ScionIPv6EpTest, Endpoint)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    IsdAsn ia2(Isd(2), Asn(0xff00'0000'0002));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("fd00::1")), 50000);
    auto ep2 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("fd00::2")), 50001);

    Endpoint endpoint(ia1, ep1);
    EXPECT_EQ(ia1, endpoint.getIsdAsn());
    EXPECT_EQ(ep1, endpoint.getLocalEp());

    EXPECT_EQ(Endpoint(ia1, ep1), endpoint);
    EXPECT_GT(Endpoint(ia2, ep2), endpoint);

    std::hash<Endpoint> h;
    EXPECT_EQ(h(Endpoint(ia1, ep1)), h(endpoint));
    EXPECT_NE(h(Endpoint(ia2, ep1)), h(endpoint));
}

TYPED_TEST(ScionIPv6EpTest, Parse)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("::1")), 50000);
    auto ep2 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("::1")), 0);

    EXPECT_EQ(unwrap(Endpoint::Parse("[1-ff00:0:1,::1]:50000")), Endpoint(ia1, ep1));
    EXPECT_EQ(unwrap(Endpoint::Parse("[1-1,::1]:50000")), Endpoint(IsdAsn(Isd(1), Asn(1)), ep1));
    EXPECT_EQ(unwrap(Endpoint::Parse("1-ff00:0:1,::1")), Endpoint(ia1, ep2));
    EXPECT_EQ(unwrap(Endpoint::Parse("[1-ff00:0:1,::1]")), Endpoint(ia1, ep2));
    EXPECT_EQ(unwrap(Endpoint::Parse("1-ff00:0:1,::1:80")),  Endpoint(ia1,
        EpTraits::fromHostPort(unwrap(AddrTraits::fromString("::1:80")), 0)
    ));

    EXPECT_TRUE(hasFailed(Endpoint::Parse("")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(",")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("::1")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(",::1")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("fd00:102:304:506:708:90a:b0c:d0e:80")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse("[1-ff00:0:1,::1]:")));
    EXPECT_TRUE(hasFailed(Endpoint::Parse(":50000")));
}

TYPED_TEST(ScionIPv6EpTest, Format)
{
    using namespace scion;
    using LocalEp = TypeParam;
    using Endpoint = scion::Endpoint<LocalEp>;
    using EpTraits = EndpointTraits<LocalEp>;
    using AddrTraits = AddressTraits<typename Endpoint::HostAddr>;

    IsdAsn ia1(Isd(1), Asn(0xff00'0000'0001));
    auto ep1 = EpTraits::fromHostPort(unwrap(AddrTraits::fromString("fd00::1")), 50000);

    EXPECT_EQ(std::format("{}", ep1), "[fd00::1]:50000");
    EXPECT_EQ(std::format("{}", Endpoint(ia1, ep1)), "[1-ff00:0:1,fd00::1]:50000");
}
