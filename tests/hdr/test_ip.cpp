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

#include "scion/bit_stream.hpp"
#include "scion/hdr/ethernet.hpp"
#include "scion/hdr/ip.hpp"
#include "scion/hdr/udp.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <cstring>
#include <span>
#include <vector>


TEST(IPv4, Checksum)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    std::array<std::byte, 20> buffer = {};
    IPv4 hdr;
    hdr.src = IPAddress::MakeIPv4(0x0a000001u);
    hdr.dst = IPAddress::MakeIPv4(0x0a000002u);

    // Write correct checksum
    {
        scion::WriteStream wstream(buffer);
        scion::StreamError err;
        ASSERT_TRUE(hdr.serialize(wstream, err)) << err;
    }
    EXPECT_EQ(buffer[10], 0x26_b);
    EXPECT_EQ(buffer[11], 0xea_b);

    // Parse with correct checksum
    {
        scion::ReadStream rstream(buffer);
        scion::StreamError err;
        ASSERT_TRUE(hdr.serialize(rstream, err)) << err;
    }

    // Parse with incorrect checksum
    buffer[10] = 0x00_b;
    {
        scion::ReadStream rstream(buffer);
        scion::StreamError err;
        ASSERT_FALSE(hdr.serialize(rstream, err));
        EXPECT_STREQ(err.getMessage(), "incorrect IP checksum");
    }
}

TEST(IPv4, Parse)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkt = loadPackets("hdr/data/udp_ipv4.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    Ethernet ether;
    IPv4 ip;
    UDP udp;

    // Ethernet
    ASSERT_TRUE(ether.serialize(stream, err)) << err;
    EXPECT_THAT(ether.dst, testing::ElementsAre(0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x01_b));
    EXPECT_THAT(ether.src, testing::ElementsAre(0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x02_b));
    EXPECT_THAT(ether.type, EtherType::IPv4);

    // IPv4
    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    EXPECT_EQ(ip.flags, IPv4::Flags::MoreFragments);
    EXPECT_EQ(ip.tos, 32);
    EXPECT_EQ(ip.ttl, 20);
    EXPECT_EQ(ip.proto, IPProto::UDP);
    EXPECT_EQ(ip.len, 32);
    EXPECT_EQ(ip.id, 1);
    EXPECT_EQ(ip.frag, 0);
    EXPECT_EQ(ip.src, IPAddress::MakeIPv4(0x0a000001u));
    EXPECT_EQ(ip.dst, IPAddress::MakeIPv4(0x0a000002u));

    // UDP
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    EXPECT_EQ(udp.sport, 43000);
    EXPECT_EQ(udp.dport, 1200);
    EXPECT_EQ(udp.len, 12);
    EXPECT_EQ(udp.chksum, 0x39f2u);

    // Payload
    uint32_t payload = 0;
    ASSERT_TRUE(stream.serializeUint32(payload, err)) << err;
    EXPECT_EQ(payload, 1337);
}

TEST(IPv4, Emit)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto expected = loadPackets("hdr/data/udp_ipv4.bin").at(0);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;
    Ethernet ether;
    IPv4 ip;
    UDP udp;

    // Ethernet
    ether.dst = std::array<std::byte, 6>{0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x01_b};
    ether.src = std::array<std::byte, 6>{0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x02_b};
    ether.type = EtherType::IPv4;

    // IPv4
    ip.flags = IPv4::Flags::MoreFragments;
    ip.tos = 32;
    ip.ttl = 20;
    ip.proto = IPProto::UDP;
    ip.len = 32;
    ip.id = 1;
    ip.frag = 0;
    ip.src = IPAddress::MakeIPv4(0x0a000001u);
    ip.dst = IPAddress::MakeIPv4(0x0a000002u);

    // UDP
    udp.sport = 43000;
    udp.dport = 1200;
    udp.len = 12;
    udp.chksum = 0;

    // Payload
    std::array<std::byte, 4> payload = { 0_b, 0_b, 5_b, 57_b };

    udp.chksum = details::internetChecksum(payload, ip.checksum(udp.len) + udp.checksum());

    ASSERT_TRUE(ether.serialize(stream, err)) << err;
    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    ASSERT_TRUE(stream.serializeBytes(payload, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(IPv4, Print)
{
    using namespace scion::hdr;
    static const char* expected =
        "###[ Ethernet ]###\n"
        "dst  = 00:00:00:00:00:00\n"
        "src  = 00:00:00:00:00:00\n"
        "type = 0x800\n"
        "###[ IPv4 ]###\n"
        "  tos   = 0\n"
        "  len   = 0\n"
        "  id    = 1\n"
        "  flags = 0x2\n"
        "  ttl   = 64\n"
        "  proto = 17\n"
        "  src   = 0.0.0.0\n"
        "  dst   = 0.0.0.0\n"
        "###[ UDP ]###\n"
        "    sport  = 0\n"
        "    dport  = 0\n"
        "    len    = 0\n"
        "    chksum = 0\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = Ethernet().print(out, 0);
    out = IPv4().print(out, 2);
    out = UDP().print(out, 4);
    EXPECT_EQ(str, expected);
}

TEST(IPv4, ICMP)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkt = loadPackets("hdr/data/icmp4.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    IPv4 ip;
    ICMP icmp;

    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    ASSERT_TRUE(icmp.serialize(stream, err)) << err;

    EXPECT_EQ(ip.proto, IPProto::ICMP);
    EXPECT_EQ(icmp.type, ICMP::Type::EchoReply);
    EXPECT_EQ(icmp.chksum, 0xfac5);
    EXPECT_EQ(icmp.param1, 1337);
    EXPECT_EQ(icmp.param2, 1);

    EXPECT_EQ(details::onesComplementChecksum(std::span<std::byte>(), icmp.checksum()), 0xffff);

    static const char* expected =
        "###[ IPv4 ]###\n"
        "tos   = 32\n"
        "len   = 28\n"
        "id    = 1\n"
        "flags = 0x2\n"
        "ttl   = 20\n"
        "proto = 1\n"
        "src   = 10.0.0.1\n"
        "dst   = 10.0.0.2\n"
        "###[ ICMP ]###\n"
        "  type   = 0\n"
        "  code   = 0\n"
        "  chksum = 64197\n"
        "  param1 = 1337\n"
        "  param2 = 1\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = ip.print(out, 0);
    out = icmp.print(out, 2);
    EXPECT_EQ(str, expected);
}

TEST(IPv6, Parse)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkt = loadPackets("hdr/data/udp_ipv6.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    Ethernet ether;
    IPv6 ip;
    UDP udp;

    // Ethernet
    ASSERT_TRUE(ether.serialize(stream, err)) << err;
    EXPECT_THAT(ether.dst, testing::ElementsAre(0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x01_b));
    EXPECT_THAT(ether.src, testing::ElementsAre(0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x02_b));
    EXPECT_THAT(ether.type, EtherType::IPv6);

    // IPv6
    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    EXPECT_EQ(ip.tc, 32);
    EXPECT_EQ(ip.fl, 0xf'ffffu);
    EXPECT_EQ(ip.plen, 12);
    EXPECT_EQ(ip.hlim, 20);
    EXPECT_EQ(ip.nh, IPProto::UDP);
    EXPECT_EQ(ip.src, unwrap(IPAddress::Parse("fd00::1")));
    EXPECT_EQ(ip.dst, unwrap(IPAddress::Parse("fd00::2")));

    // UDP
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    EXPECT_EQ(udp.sport, 43000);
    EXPECT_EQ(udp.dport, 1200);
    EXPECT_EQ(udp.len, 12);
    EXPECT_EQ(udp.chksum, 0x53f0);

    // Payload
    uint32_t payload = 0;
    ASSERT_TRUE(stream.serializeUint32(payload, err)) << err;
    EXPECT_EQ(payload, 1337);
}

TEST(IPv6, Emit)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto expected = loadPackets("hdr/data/udp_ipv6.bin").at(0);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;
    Ethernet ether;
    IPv6 ip;
    UDP udp;

    // Ethernet
    ether.dst = std::array<std::byte, 6>{0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x01_b};
    ether.src = std::array<std::byte, 6>{0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x02_b};
    ether.type = EtherType::IPv6;

    // IPv6
    ip.tc = 32;
    ip.fl = 0xf'ffffu;
    ip.plen = 12;
    ip.hlim = 20;
    ip.nh = IPProto::UDP;
    ip.src = unwrap(IPAddress::Parse("fd00::1"));
    ip.dst = unwrap(IPAddress::Parse("fd00::2"));

    // UDP
    udp.sport = 43000;
    udp.dport = 1200;
    udp.len = 12;
    udp.chksum = 0;

    // Payload
    std::array<std::byte, 4> payload = { 0_b, 0_b, 5_b, 57_b };

    udp.chksum = details::internetChecksum(payload, ip.checksum(udp.len) + udp.checksum());

    ASSERT_TRUE(ether.serialize(stream, err)) << err;
    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    ASSERT_TRUE(stream.serializeBytes(payload, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(IPv6, Print)
{
    using namespace scion::hdr;
    static const char* expected =
        "###[ Ethernet ]###\n"
        "dst  = 00:00:00:00:00:00\n"
        "src  = 00:00:00:00:00:00\n"
        "type = 0x800\n"
        "###[ IPv6 ]###\n"
        "  tc   = 0\n"
        "  fl   = 0\n"
        "  plen = 0\n"
        "  nh   = 17\n"
        "  hlim = 64\n"
        "  src  = ::\n"
        "  dst  = ::\n"
        "###[ UDP ]###\n"
        "    sport  = 0\n"
        "    dport  = 0\n"
        "    len    = 0\n"
        "    chksum = 0\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = Ethernet().print(out, 0);
    out = IPv6().print(out, 2);
    out = UDP().print(out, 4);
    EXPECT_EQ(str, expected);
}

TEST(IPv6, ICMPv6)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkt = loadPackets("hdr/data/icmp6.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    IPv6 ip;
    ICMPv6 icmp;

    ASSERT_TRUE(ip.serialize(stream, err)) << err;
    ASSERT_TRUE(icmp.serialize(stream, err)) << err;

    EXPECT_EQ(ip.nh, IPProto::ICMPv6);
    EXPECT_EQ(icmp.type, ICMPv6::Type::EchoReply);
    EXPECT_EQ(icmp.chksum, 0x7f7e);
    EXPECT_EQ(icmp.param1, 1337);
    EXPECT_EQ(icmp.param2, 1);

    EXPECT_EQ(details::onesComplementChecksum(
        std::span<std::byte>(), ip.checksum(ip.plen) + icmp.checksum()),
        0xffff);

    static const char* expected =
        "###[ IPv6 ]###\n"
        "tc   = 32\n"
        "fl   = 1048575\n"
        "plen = 8\n"
        "nh   = 58\n"
        "hlim = 20\n"
        "src  = fd00::1\n"
        "dst  = fd00::2\n"
        "###[ ICMPv6 ]###\n"
        "  type   = 129\n"
        "  code   = 0\n"
        "  chksum = 32638\n"
        "  param1 = 1337\n"
        "  param2 = 1\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = ip.print(out, 0);
    out = icmp.print(out, 2);
    EXPECT_EQ(str, expected);
}
