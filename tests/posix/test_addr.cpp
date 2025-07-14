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
#include "scion/posix/sockaddr.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"


TEST(InAddr, ConvertToGeneric)
{
    using namespace scion;
    using namespace scion::generic;

    auto ip4 = unwrap(AddressTraits<in_addr>::fromString("10.255.255.255"));
    auto ip6 = unwrap(AddressTraits<in6_addr>::fromString("fd00:102:304:506:708:90a:b0c:d0e"));

    EXPECT_EQ(
        toGenericAddr(ip4),
        IPAddress::MakeIPv4(0xaffffff)
    );

    EXPECT_EQ(
        toGenericAddr(ip6),
        IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul)
    );
}

TEST(InAddr, ConvertFromGeneric)
{
    using namespace scion;
    using namespace scion::generic;

    auto ip4 = IPAddress::MakeIPv4(0xaffffff);
    auto ip6 = IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul);

    EXPECT_EQ(
        unwrap(toUnderlay<in_addr>(ip4)),
        unwrap(AddressTraits<in_addr>::fromString("10.255.255.255")));

    EXPECT_EQ(
        unwrap(toUnderlay<in6_addr>(ip6)),
        unwrap(AddressTraits<in6_addr>::fromString("fd00:102:304:506:708:90a:b0c:d0e")));
}

TEST(SockAddr, ConvertToGeneric)
{
    using namespace scion;
    using namespace scion::generic;

    auto ep4 = EndpointTraits<sockaddr_in>::fromHostPort(
        unwrap(AddressTraits<in_addr>::fromString("10.255.255.255")),
        80
    );
    auto ep6 = EndpointTraits<sockaddr_in6>::fromHostPort(
        unwrap(AddressTraits<in6_addr>::fromString(
            "fd00:102:304:506:708:90a:b0c:d0e"
        )), 80
    );

    EXPECT_EQ(
        toGenericEp(ep4),
        IPEndpoint(IPAddress::MakeIPv4(0xaffffff), 80)
    );

    EXPECT_EQ(
        toGenericEp(ep6),
        IPEndpoint(
            IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul),
            80
        )
    );
}

TEST(SockAddr, ConvertFromGeneric)
{
    using namespace scion;
    using namespace scion::generic;

    auto ip4 = IPAddress::MakeIPv4(0xaffffff);
    IPEndpoint ep4(ip4, 80);
    auto ip6 = IPAddress::MakeIPv6(0xfd00'0102'0304'0506ul, 0x0708'090a'0b0c'0d0eul);
    IPEndpoint ep6(ip6, 80);

    EXPECT_EQ(
        unwrap(toUnderlay<sockaddr_in>(ep4)),
        EndpointTraits<sockaddr_in>::fromHostPort(
            unwrap(AddressTraits<in_addr>::fromString("10.255.255.255")),
            80
        )
    );

    EXPECT_EQ(
        unwrap(toUnderlay<sockaddr_in6>(ep6)),
        EndpointTraits<sockaddr_in6>::fromHostPort(
            unwrap(AddressTraits<in6_addr>::fromString(
                "fd00:102:304:506:708:90a:b0c:d0e"
            )), 80
        )
    );
}
