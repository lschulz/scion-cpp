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
#include "scion/details/c_interface.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include <cstdlib>
#include <iostream>
#include <memory>

using std::uint8_t;


TEST(GetAddrInfoTest, Localhost)
{
    addrinfo hints = {};
    hints.ai_family = AF_SCION;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("localhost", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_SCION);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_scion));
    auto* sa = reinterpret_cast<sockaddr_scion*>(res->ai_addr);
    EXPECT_EQ(sa->sscion_addr.sscion_isd_asn, scion_htonll((1ull << 48 )| 64496ull));
    EXPECT_EQ(sa->sscion_addr.sscion_host_type, SCION_IPv4);
    EXPECT_EQ(sa->sscion_addr.sscion_scope_id, 0);
    EXPECT_THAT(sa->sscion_addr.u.sscion_addr, testing::ElementsAre(
        127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ));
    EXPECT_EQ(sa->sscion_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}

TEST(GetAddrInfoTest, PassiveAddress)
{
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo(nullptr, "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_SCION);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_scion));
    auto* sa = reinterpret_cast<sockaddr_scion*>(res->ai_addr);
    EXPECT_EQ(sa->sscion_addr.sscion_isd_asn, scion_htonll((1ull << 48 )| 64496ull));
    EXPECT_EQ(sa->sscion_addr.sscion_host_type, SCION_IPv4);
    EXPECT_EQ(sa->sscion_port, htons(443));
    ASSERT_NE(res->ai_next, nullptr);
    for (auto* node = res->ai_next; node; node = node->ai_next) {
        if (node->ai_addr->sa_family == AF_INET) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in));
            auto* sa = reinterpret_cast<sockaddr_in*>(node->ai_addr);
            EXPECT_EQ(sa->sin_port, htons(443));
        } else if (node->ai_addr->sa_family == AF_INET6) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in6));
            auto* sa = reinterpret_cast<sockaddr_in6*>(node->ai_addr);
            EXPECT_EQ(sa->sin6_port, htons(443));
        } else {
            FAIL();
        }
    }
}

TEST(GetAddrInfoTest, ARecord)
{
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("netsys.ovgu.de", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_INET);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_in));
    auto* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    EXPECT_EQ(sa->sin_family, AF_INET);
    EXPECT_EQ(sa->sin_addr.s_addr, 0x7b112c8d);
    EXPECT_EQ(sa->sin_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}

TEST(GetAddrInfoTest, DualStack)
{
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("google.com", "https", NULL, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    int ipv4 = 0, ipv6 = 0;
    for (auto* node = res; node; node = node->ai_next) {
        if (node->ai_family == AF_INET) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in));
            auto* sa = reinterpret_cast<sockaddr_in*>(node->ai_addr);
            EXPECT_EQ(sa->sin_port, htons(443));
            ++ipv4;
        } else if (node->ai_family == AF_INET6) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in6));
            auto* sa = reinterpret_cast<sockaddr_in6*>(node->ai_addr);
            EXPECT_EQ(sa->sin6_port, htons(443));
            ++ipv6;
        } else {
            FAIL();
        }
    }
    EXPECT_GT(ipv4, 1);
    EXPECT_GT(ipv6, 1);
}

TEST(GetAddrInfoTest, DualStackScionNative)
{
    addrinfo hints = {};
    hints.ai_flags = AI_SCION_NATIVE;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("netsys.ovgu.de", "https", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    int ipv4 = 0, scion = 0;
    for (auto* node = res; node; node = node->ai_next) {
        if (node->ai_family == AF_INET) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in));
            auto* sa = reinterpret_cast<sockaddr_in*>(node->ai_addr);
            EXPECT_EQ(sa->sin_port, htons(443));
            ++ipv4;
        } else if (node->ai_family == AF_SCION) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_scion));
            auto* sa = reinterpret_cast<sockaddr_scion*>(node->ai_addr);
            EXPECT_EQ(sa->sscion_addr.sscion_isd_asn, scion_htonll(0x13ffaa00010c3full));
            EXPECT_EQ(sa->sscion_addr.sscion_host_type, SCION_IPv4);
            EXPECT_EQ(sa->sscion_addr.sscion_scope_id, 0);
            EXPECT_THAT(sa->sscion_addr.u.sscion_addr, testing::ElementsAre(
                127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ));
            EXPECT_EQ(sa->sscion_port, htons(443));
            ++scion;
        }
    }
    EXPECT_EQ(ipv4, 1);
    EXPECT_EQ(scion, 1);
}

TEST(GetAddrInfoTest, DualStackScionSurrogate)
{
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("netsys.ovgu.de", "https", NULL, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    int ipv4 = 0, ipv6 = 0;
    for (auto* node = res; node; node = node->ai_next) {
        if (node->ai_family == AF_INET) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in));
            auto* sa = reinterpret_cast<sockaddr_in*>(node->ai_addr);
            EXPECT_EQ(sa->sin_port, htons(443));
            ++ipv4;
        } else if (node->ai_family == AF_INET6) {
            ASSERT_EQ(node->ai_addrlen, sizeof(sockaddr_in6));
            auto* sa = reinterpret_cast<sockaddr_in6*>(node->ai_addr);
            EXPECT_EQ(sa->sin6_flowinfo, 0);
            EXPECT_EQ(sa->sin6_scope_id, 0);
            EXPECT_THAT((std::span<char, 8>(reinterpret_cast<char*>(&sa->sin6_addr), 8)),
                testing::ElementsAre(0xfc, 0, 0, 0, 0, 0, 0, 0));
            EXPECT_EQ(sa->sin6_port, htons(443));
            ++ipv6;
        }
    }
    EXPECT_EQ(ipv4, 1);
    EXPECT_EQ(ipv6, 1);
}

TEST(GetAddrInfoTest, NumericalIP)
{
    addrinfo hints = {};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("127.0.0.1", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_INET);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_in));
    auto* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    EXPECT_EQ(sa->sin_family, AF_INET);
    EXPECT_EQ(sa->sin_addr.s_addr, htonl(0x7f000001));
    EXPECT_EQ(sa->sin_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}

TEST(GetAddrInfoTest, NumericalScionNative)
{
    addrinfo hints = {};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_SCION_NATIVE;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("1-ff00:0:1,127.0.0.1", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_SCION);
    ASSERT_EQ(res->ai_socktype, SOCK_DGRAM);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_scion));
    auto* sa = reinterpret_cast<sockaddr_scion*>(res->ai_addr);
    EXPECT_EQ(sa->sscion_family, AF_SCION);
    EXPECT_EQ(sa->sscion_addr.sscion_isd_asn, scion_htonll(0x1ff0000000001ull));
    EXPECT_EQ(sa->sscion_addr.sscion_host_type, SCION_IPv4);
    EXPECT_EQ(sa->sscion_addr.sscion_scope_id, 0);
    EXPECT_THAT(sa->sscion_addr.u.sscion_addr, testing::ElementsAre(
        127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    ));
    EXPECT_EQ(sa->sscion_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}

TEST(GetAddrInfoTest, NumericalScionSurrogate)
{
    addrinfo hints = {};
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("1-ff00:0:1,127.0.0.1", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_INET6);
    ASSERT_EQ(res->ai_socktype, SOCK_DGRAM);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_in6));
    auto* sa = reinterpret_cast<sockaddr_in6*>(res->ai_addr);
    EXPECT_EQ(sa->sin6_flowinfo, 0);
    EXPECT_EQ(sa->sin6_scope_id, 0);
    EXPECT_THAT((std::span<uint8_t, 8>(reinterpret_cast<uint8_t*>(&sa->sin6_addr), 8)),
        testing::ElementsAre(0xfc, 0, 0, 0, 0, 0, 0, 0));
    EXPECT_EQ(sa->sin6_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}

TEST(GetAddrInfoTest, NumericalScionMapped)
{
    addrinfo hints = {};
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    ASSERT_EQ(interposer_getaddrinfo("1-1,127.0.0.1", "443", &hints, &res), 0);
    std::unique_ptr<addrinfo, void(*)(addrinfo*)> defer(res, &interposer_freeaddrinfo);

    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->ai_family, AF_INET6);
    ASSERT_EQ(res->ai_socktype, SOCK_DGRAM);
    ASSERT_EQ(res->ai_addrlen, sizeof(sockaddr_in6));
    auto* sa = reinterpret_cast<sockaddr_in6*>(res->ai_addr);
    EXPECT_EQ(sa->sin6_flowinfo, 0);
    EXPECT_EQ(sa->sin6_scope_id, 0);
    auto ip = scion::generic::IPAddress::MakeIPv6(
        std::span<std::byte, 16>(reinterpret_cast<std::byte*>(&sa->sin6_addr), 16));
    EXPECT_TRUE(ip.isScion4());
    EXPECT_EQ(sa->sin6_port, htons(443));
    ASSERT_EQ(res->ai_next, nullptr);
}
