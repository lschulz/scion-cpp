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

#include "scitra/translator.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <ranges>
#include <vector>


static scion::PathPtr loadTestPath(int i)
{
    using namespace scion;
    auto rawPaths = loadPackets("data/paths.bin");
    switch (i) {
    case 0:
        return makePath(
            IsdAsn(Isd(1), Asn(64496)),
            IsdAsn(Isd(2), Asn(64497)),
            hdr::PathType::SCION,
            Path::Expiry::clock::now(),
            1280,
            unwrap(generic::IPEndpoint::Parse("127.0.0.9:31002")),
            rawPaths.at(0)
        );
    case 1:
        return makePath(
            IsdAsn(Isd(1), Asn(64496)),
            IsdAsn(Isd(2), Asn(64497)),
            hdr::PathType::SCION,
            Path::Expiry::clock::now(),
            1280,
            unwrap(generic::IPEndpoint::Parse("[::1]:31002")),
            rawPaths.at(0)
        );
    default:
        throw std::logic_error("index out of range");
    }
}

static class NeverScion : public scion::scitra::IsScion
{
public:
    bool operator()(
        const scion::generic::IPEndpoint& src,
        const scion::generic::IPEndpoint& dst)
     override {
        return false;
    }
} neverScion;

static class IsScion : public scion::scitra::IsScion
{
public:
    bool operator()(
        const scion::generic::IPEndpoint& src,
        const scion::generic::IPEndpoint& dst)
     override {
        auto port =  dst.port();
        return 31000 <= port && port <= 32767;
    }
} isScion;

TEST(ScitraCore, TranslatePrefix)
{
    using namespace scion::generic;
    using namespace scion::scitra;

    auto addr = IPAddress::MakeIPv6(0xfd01'0203'0405'0607u, 0x0809'0a0b'cb0d'0e0fu);
    auto prefix = IPAddress::MakeIPv6(0xfcff'ffff'ffff'ffffu, 0xffff'ffff'ffff'ffffu);
    auto ipv4 = IPAddress::MakeIPv4(0x7f000001u);

    EXPECT_EQ(translateIPv6Prefix(addr, prefix, 0), addr);
    EXPECT_EQ(translateIPv6Prefix(addr, prefix, 8),
        IPAddress::MakeIPv6(0xfc01'0203'0405'0607u, 0x0809'0a0b'cb0d'0e0fu));
    EXPECT_EQ(translateIPv6Prefix(addr, prefix, 64),
        IPAddress::MakeIPv6(0xfcff'ffff'ffff'ffffu, 0x0809'0a0b'cb0d'0e0fu));
    EXPECT_EQ(translateIPv6Prefix(addr, prefix, 72),
        IPAddress::MakeIPv6(0xfcff'ffff'ffff'ffffu, 0xff09'0a0b'cb0d'0e0fu));
    EXPECT_EQ(translateIPv6Prefix(addr, prefix, REPLACE_ADDRESS), prefix);
    EXPECT_EQ(translateIPv6Prefix(addr, ipv4, REPLACE_ADDRESS), ipv4);
}

// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv4 underlay.
TEST(ScitraCore, TranslateIpUdpToScion4)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv4.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("127.0.0.9:31002")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/SCION with a UDP/IPv4 underlay to UDP/IPv6.
TEST(ScitraCore, TranslateScion4ToIpUdp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv4.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(0);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:20fb:f100::ffff:a00:2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv4 underlay and an empty path.
TEST(ScitraCore, TranslateIpUdpToScion4Local)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv4_local.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(makeEmptyPath(dst.isdAsn()), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("10.0.0.2:32767")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/SCION with a UDP/IPv4 underlay and an empty path to UDP/IPv6.
TEST(ScitraCore, TranslateScion4ToIpUdpLocal)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv4_local.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(0);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:10fb:f000::ffff:a00:2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay.
TEST(ScitraCore, TranslateIpUdpToScion6)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv6.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(1), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("fc00:10fb:f000::1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("[::1]:31002")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/SCION with a UDP/IPv6 underlay to UDP/IPv6.
TEST(ScitraCore, TranslateScion6ToIpUdp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv6.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(1);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:20fb:f100::2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/IPv6 to UDP/SCION with a UDP/IPv6 underlay and an empty path.
TEST(ScitraCore, TranslateIpUdpToScion6Local)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv6_local.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(makeEmptyPath(dst.isdAsn()), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("fc00:10fb:f000::1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("[fc00:10fb:f000::2]:32767")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/SCION with a UDP/IPv6 underlay and an empty path to UDP/IPv6.
TEST(ScitraCore, TranslateScion6ToIpUdpLocal)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_ipv6_local.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(1);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:10fb:f000::2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/IPv6 to UDP/SCION without an underlay.
TEST(ScitraCore, TranslateIpUdpToScionNoUnderlay)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_no_underlay.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("127.0.0.9:31002")));

    auto translated = pkt.emitPacket(true);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate UDP/SCION without an underlay to UDP/IPv6.
TEST(ScitraCore, TranslateScionNoUnderlayToIpUdp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_udp_no_underlay.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), true, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(0);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:20fb:f100::ffff:a00:2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate TCP/IPv6 to TCP/SCION with a UDP/IPv4 underlay.
TEST(ScitraCore, TranslateIpTcpToScion4)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_tcp_ipv4.bin");
    auto& input = data.at(0);
    auto& expected = data.at(3);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 32766);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("127.0.0.9:31002")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate TCP/SCION with a UDP/IPv4 underlay to TCP/IPv6.
TEST(ScitraCore, TranslateScion4ToIpTcp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_tcp_ipv4.bin");
    auto& input = data.at(2);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(0);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:20fb:f100::ffff:a00:2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate ICMP/IPv6 to SCMP/SCION with a UDP/IPv4 underlay.
TEST(ScitraCore, TranslateIcmpToScmp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_scmp.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1280);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Pass);
    EXPECT_EQ(egPort, 30041);
    EXPECT_EQ(nextHop, unwrap(generic::IPEndpoint::Parse("127.0.0.9:31002")));

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Translate SCMP/SCION with a UDP/IPv4 underlay to ICMP/IPv6.
TEST(ScitraCore, TranslateScmpToIcmp)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/translate_scmp.bin");
    auto& input = data.at(1);
    auto& expected = data.at(0);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &isScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto path = loadTestPath(0);
    auto getMTU = [&] (const hdr::SCION& sci, const RawPath& rp) {
        return 1280;
    };

    auto mappedIP = unwrap(generic::IPAddress::Parse("fc00:20fb:f100::ffff:a00:2"));
    auto verdict = translateIngress(pkt, mappedIP, mappedIP, 128, getMTU);
    ASSERT_EQ(verdict, Verdict::Pass);

    auto translated = pkt.emitPacket(false);
    ASSERT_FALSE(isError(translated)) << fmtError(translated.error());
    EXPECT_TRUE(std::ranges::equal(*translated, expected)) << printBufferDiff(*translated, expected);
}

// Test ICMP Packet Too Big response
TEST(ScitraCore, RespondPacketTooBig)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/packet_too_big.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1472);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Return);

    auto response = pkt.emitPacket(false);
    ASSERT_FALSE(isError(response)) << fmtError(response.error());
    EXPECT_TRUE(std::ranges::equal(*response, expected)) << printBufferDiff(*response, expected);
}

// Test ICMP Packet Destination Unreachable (Address UNreachable) response
TEST(ScitraCore, RespondAddressUnreachable)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/address_unreachable.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(loadTestPath(0), 1472);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Return);

    auto response = pkt.emitPacket(false);
    ASSERT_FALSE(isError(response)) << fmtError(response.error());
    EXPECT_TRUE(std::ranges::equal(*response, expected)) << printBufferDiff(*response, expected);
}

// Test ICMP Packet Destination Unreachable (No Route) response
TEST(ScitraCore, RespondNoRouteToDestination)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/no_route_to_destination.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(2048));
    {
        auto dst = pkt.clearAndGetBuffer(512);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), false, &neverScion);
    ASSERT_FALSE(ec) << fmtError(ec);

    auto getPath = [] (
        const ScIPAddress& src, const ScIPAddress& dst,
        std::uint16_t sport, std::uint16_t dport, hdr::ScionProto proto, std::uint8_t tc
    ) -> std::tuple<Maybe<PathPtr>, std::uint16_t> {
        return std::make_tuple(Maybe<PathPtr>(nullptr), 1472);
    };

    auto hostIP = unwrap(generic::IPAddress::Parse("10.0.0.1"));
    auto [verdict, egPort, nextHop] = translateEgress(pkt, hostIP, REPLACE_ADDRESS, getPath);
    ASSERT_EQ(verdict, Verdict::Return);

    auto response = pkt.emitPacket(false);
    ASSERT_FALSE(isError(response)) << fmtError(response.error());
    EXPECT_TRUE(std::ranges::equal(*response, expected)) << printBufferDiff(*response, expected);
}
