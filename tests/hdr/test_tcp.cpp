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
#include "scion/hdr/ip.hpp"
#include "scion/hdr/tcp.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <cstdint>
#include <cstring>

using std::uint16_t;


TEST(TCP, Parse)
{
    using namespace scion::hdr;

    auto pkts = loadPackets("hdr/data/tcp.bin");

    // SYN
    {
        scion::ReadStream stream(pkts.at(0));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN);
        EXPECT_EQ(tcp.sport, 34776);
        EXPECT_EQ(tcp.dport, 32000);
        EXPECT_EQ(tcp.window, 65495);
        EXPECT_EQ(tcp.urgptr, 0);
        EXPECT_EQ(tcp.seq, 2060855180);
        EXPECT_EQ(tcp.ack, 0);
        EXPECT_EQ(tcp.chksum, 0xbe57);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1380);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 1667661695);
        EXPECT_EQ(tcp.options.ts.TSecr, 0);
    }

    // SYN+ACK
    {
        scion::ReadStream stream(pkts.at(1));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN | TCP::Flags::ACK);
        EXPECT_EQ(tcp.sport, 32000);
        EXPECT_EQ(tcp.dport, 34776);
        EXPECT_EQ(tcp.window, 65483);
        EXPECT_EQ(tcp.urgptr, 0);
        EXPECT_EQ(tcp.seq, 2615407415);
        EXPECT_EQ(tcp.ack, 2060855181);
        EXPECT_EQ(tcp.chksum, 0x4c51);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1380);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 1667661695);
        EXPECT_EQ(tcp.options.ts.TSecr, 1667661695);
    }

    // ACK
    {
        scion::ReadStream stream(pkts.at(2));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.sport, 34776);
        EXPECT_EQ(tcp.dport, 32000);
        EXPECT_EQ(tcp.window, 512);
        EXPECT_EQ(tcp.urgptr, 0);
        EXPECT_EQ(tcp.seq, 2060855181);
        EXPECT_EQ(tcp.ack, 2615407416);
        EXPECT_EQ(tcp.chksum, 0x7899);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 1667661695);
        EXPECT_EQ(tcp.options.ts.TSecr, 1667661695);
    }

    // Data
    {
        scion::ReadStream stream(pkts.at(3));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::PSH | TCP::Flags::ACK);
        EXPECT_EQ(tcp.sport, 34776);
        EXPECT_EQ(tcp.dport, 32000);
        EXPECT_EQ(tcp.window, 512);
        EXPECT_EQ(tcp.urgptr, 0);
        EXPECT_EQ(tcp.seq, 2060855181);
        EXPECT_EQ(tcp.ack, 2615407416);
        EXPECT_EQ(tcp.chksum, 0x8595);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 0);
    }

    // Selective ACK
    {
        scion::ReadStream stream(pkts.at(4));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.sport, 34776);
        EXPECT_EQ(tcp.dport, 32000);
        EXPECT_EQ(tcp.window, 512);
        EXPECT_EQ(tcp.urgptr, 0);
        EXPECT_EQ(tcp.seq, 2060855181);
        EXPECT_EQ(tcp.ack, 2615407416);
        EXPECT_EQ(tcp.chksum, 0x0130);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 1);
        EXPECT_EQ(tcp.optMask.TS, 0);
        EXPECT_EQ(tcp.options.sack.blocks, 3);
        EXPECT_EQ(tcp.options.sack.left[0], 1);
        EXPECT_EQ(tcp.options.sack.right[0], 2);
        EXPECT_EQ(tcp.options.sack.left[1], 3);
        EXPECT_EQ(tcp.options.sack.right[1], 4);
        EXPECT_EQ(tcp.options.sack.left[2], 5);
        EXPECT_EQ(tcp.options.sack.right[2], 6);
    }
}

TEST(TCP, Emit)
{
    using namespace scion::hdr;

    auto pkts = loadPackets("hdr/data/tcp.bin");
    // IPv4 Underlay
    IPv4 ip;
    ip.flags = IPv4::Flags(0);
    ip.proto = IPProto::TCP;

    // SYN
    {
        auto& expected = pkts.at(0);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 65495;
        tcp.seq = 2060855180;
        tcp.ack = 0;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.options.mss.mss = 1380;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 1667661695;
        tcp.options.ts.TSecr = 0;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // SYN+ACK
    {
        auto& expected = pkts.at(1);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN | TCP::Flags::ACK;
        tcp.sport = 32000;
        tcp.dport = 34776;
        tcp.window = 65483;
        tcp.seq = 2615407415;
        tcp.ack = 2060855181;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.options.mss.mss = 1380;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 1667661695;
        tcp.options.ts.TSecr = 1667661695;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // ACK
    {
        auto& expected = pkts.at(2);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 512;
        tcp.seq = 2060855181;
        tcp.ack = 2615407416;
        tcp.optMask.TS = 1;
        tcp.options.ts.TSval = 1667661695;
        tcp.options.ts.TSecr = 1667661695;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // Data
    {
        auto& expected = pkts.at(3);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        TCP tcp;
        tcp.flags = TCP::Flags::PSH | TCP::Flags::ACK;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 512;
        tcp.seq = 2060855181;
        tcp.ack = 2615407416;
        std::array<std::byte, 5> payload = { // "test\n"
            0x74_b, 0x65_b, 0x73_b, 0x74_b, 0x0a_b
        };

        ip.len = (std::uint16_t)(ip.size() + tcp.size() + payload.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)(tcp.size() + payload.size())) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        ASSERT_TRUE(stream.serializeBytes(payload, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // Selective ACK
    {
        auto& expected = pkts.at(4);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        TCP tcp;
        ip.len = 68;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 512;
        tcp.seq = 2060855181;
        tcp.ack = 2615407416;
        tcp.optMask.MSS = 0;
        tcp.optMask.WS = 0;
        tcp.optMask.SAckPerm = 0;
        tcp.optMask.SAck = 1;
        tcp.optMask.TS = 0;
        tcp.options.sack.blocks = 3;
        tcp.options.sack.left = {1, 3, 5};
        tcp.options.sack.right = {2, 4, 6};
        std::span<std::byte> payload = {};

        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)(tcp.size() + payload.size())) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        ASSERT_TRUE(stream.serializeBytes(payload, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }
}

TEST(TCP, Print)
{
    using namespace scion::hdr;

    TCP tcp;
    tcp.flags = TCP::Flags::SYN | TCP::Flags::ACK;
    tcp.sport = 32000;
    tcp.dport = 34776;
    tcp.window = 65483;
    tcp.urgptr = 0;
    tcp.seq = 2615407415;
    tcp.ack = 2060855181;
    tcp.optMask.MSS = 1;
    tcp.optMask.WS = 1;
    tcp.optMask.SAckPerm = 1;
    tcp.optMask.SAck = 1;
    tcp.optMask.TS = 1;
    tcp.options.mss.mss = 1380;
    tcp.options.ws.wndShift = 7;
    tcp.options.sack.blocks = 1;
    tcp.options.sack.left[0] = 0;
    tcp.options.sack.right[0] = 1;
    tcp.options.ts.TSval = 1667661695;
    tcp.options.ts.TSecr = 1667661696;

    static const char* expected =
        "###[ TCP ]###\n"
        "sport  = 32000\n"
        "dport  = 34776\n"
        "seq    = 2615407415\n"
        "ack    = 2060855181\n"
        "flags  = 0x12\n"
        "window = 65483\n"
        "chksum = 0\n"
        "urgptr = 0\n"
        "mss    = 1380\n"
        "sack   = permitted\n"
        "sack   = (0, 1)\n"
        "TSval  = 1667661695\n"
        "TSecr  = 1667661696\n"
        "wshift = 7\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = tcp.print(out, 0);
    EXPECT_EQ(str, expected);
}

TEST(TCP, PrintOptions)
{
    using namespace scion::hdr;

    TcpUnknownOpt unknown;
    TcpMssOpt mss = { 1500 };
    TcpWsOpt ws = { 7 };
    TcpSAckPermOpt sackPerm;
    TcpSAckOpt sack;
    sack.blocks = 3;
    sack.left = {1, 3, 5};
    sack.right = {2, 4, 6};
    TcpTsOpt ts = {1667661695, 1667661696};

    static const char* expected =
        "###[ TCP Opt ]###\n"
        "kind   = 255\n"
        "length = 2\n"
        "###[ TCP MSS Opt ]###\n"
        "kind   = 2\n"
        "length = 4\n"
        "mss    = 1500\n"
        "###[ TCP WS Opt ]###\n"
        "kind   = 3\n"
        "length = 3\n"
        "shift  = 7\n"
        "###[ TCP SAckPerm Opt ]###\n"
        "kind   = 4\n"
        "length = 2\n"
        "###[ TCP SAck Opt ]###\n"
        "kind     = 5\n"
        "length   = 26\n"
        "left[0]  = 1\n"
        "right[0] = 2\n"
        "left[1]  = 3\n"
        "right[1] = 4\n"
        "left[2]  = 5\n"
        "right[2] = 6\n"
        "###[ TCP TS Opt ]###\n"
        "kind   = 8\n"
        "length = 10\n"
        "TSval  = 1667661695\n"
        "TSecr  = 1667661696\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = unknown.print(out, 0);
    out = mss.print(out, 0);
    out = ws.print(out, 0);
    out = sackPerm.print(out, 0);
    out = sack.print(out, 0);
    out = ts.print(out, 0);
    EXPECT_EQ(str, expected);
}

TEST(MPTCP, Parse)
{
    using namespace scion::hdr;

    auto pkts = loadPackets("hdr/data/mptcp.bin");

    // SYN + MP_CAPABLE
    {
        scion::ReadStream stream(pkts.at(0));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN);
        EXPECT_EQ(tcp.chksum, 0x21e6);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1460);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 3301642972);
        EXPECT_EQ(tcp.options.ts.TSecr, 0);
        EXPECT_EQ(tcp.options.mpCap.flags, TcpMpCapableOpt::Flags::HMAC_SHA256);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.senderKey, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.receiverKey, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.dataLevelLen, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.chksum, 0);
        EXPECT_EQ(tcp.options.mpCap.version, 1);
    }

    // SYN+ACK + MP_CAPABLE
    {
        scion::ReadStream stream(pkts.at(1));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN | TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0x3f06);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1460);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 2874606264);
        EXPECT_EQ(tcp.options.ts.TSecr, 3301642972);
        EXPECT_EQ(tcp.options.mpCap.flags, TcpMpCapableOpt::Flags::HMAC_SHA256);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.senderKey, 1);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.receiverKey, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.dataLevelLen, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.chksum, 0);
        EXPECT_EQ(tcp.options.mpCap.version, 1);
        EXPECT_EQ(tcp.options.mpCap.senderKey, 0x5193274a5611d62b);
    }

    // ACK + MP_CAPABLE
    {
        scion::ReadStream stream(pkts.at(2));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0x4ed4);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 3301642972);
        EXPECT_EQ(tcp.options.ts.TSecr, 2874606264);
        EXPECT_EQ(tcp.options.mpCap.flags, TcpMpCapableOpt::Flags::HMAC_SHA256);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.senderKey, 1);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.receiverKey, 1);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.dataLevelLen, 0);
        EXPECT_EQ(tcp.options.mpCap.fieldMask.chksum, 0);
        EXPECT_EQ(tcp.options.mpCap.version, 1);
        EXPECT_EQ(tcp.options.mpCap.senderKey, 0xbf7c79774d5b7531);
        EXPECT_EQ(tcp.options.mpCap.receiverKey, 0x5193274a5611d62b);
    }

    // DSS 1
    {
        scion::ReadStream stream(pkts.at(3));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0xb34a);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 2874606264);
        EXPECT_EQ(tcp.options.ts.TSecr, 3301642972);
        EXPECT_EQ(tcp.options.mpDss.flags, TcpMpDssOpt::Flags::ACK | TcpMpDssOpt::Flags::ACK8);
        EXPECT_EQ(tcp.options.mpDss.dataAck.u64, 2398994140307282948);
        EXPECT_FALSE(tcp.options.mpDss.chksum.has_value());
    }

    // DSS 2
    {
        scion::ReadStream stream(pkts.at(4));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        using Flags = TcpMpDssOpt::Flags;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::PSH | TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0x6a1c);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 3301643078);
        EXPECT_EQ(tcp.options.ts.TSecr, 2874606265);
        EXPECT_EQ(tcp.options.mpDss.flags, Flags::ACK | Flags::DSN | Flags::DSN8);
        EXPECT_EQ(tcp.options.mpDss.dataAck.u32, 1785050047);
        EXPECT_EQ(tcp.options.mpDss.dsn.u64, 2398994140307414020);
        EXPECT_EQ(tcp.options.mpDss.subflowSeq, 131110);
        EXPECT_EQ(tcp.options.mpDss.dataLevelLen, 64080);
        EXPECT_FALSE(tcp.options.mpDss.chksum.has_value());
    }

    // ADD_ADDR
    {
        scion::ReadStream stream(pkts.at(5));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0x841d);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 2874606264);
        EXPECT_EQ(tcp.options.ts.TSecr, 3301642972);
        EXPECT_EQ(tcp.options.mpAdd.flags, 0);
        EXPECT_EQ(tcp.options.mpAdd.addressId, 2);
        EXPECT_EQ(tcp.options.mpAdd.address,
            unwrap(scion::generic::IPAddress::Parse("fc00:10fc:100::2")));
        EXPECT_FALSE(tcp.options.mpAdd.port.has_value());
        EXPECT_EQ(tcp.options.mpAdd.mac, 0x02af8006b38daba6);
    }

    // ADD_ADDR Echo
    {
        scion::ReadStream stream(pkts.at(6));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0xb143);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 3301642972);
        EXPECT_EQ(tcp.options.ts.TSecr, 2874606264);
        EXPECT_EQ(tcp.options.mpAdd.flags, TcpMpAddAddrOpt::Flags::Echo);
        EXPECT_EQ(tcp.options.mpAdd.addressId, 2);
        EXPECT_EQ(tcp.options.mpAdd.address,
            unwrap(scion::generic::IPAddress::Parse("fc00:10fc:100::2")));
        EXPECT_FALSE(tcp.options.mpAdd.port.has_value());
    }

    // SYN + MP_JOIN
    {
        scion::ReadStream stream(pkts.at(7));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN);
        EXPECT_EQ(tcp.chksum, 0x30a6);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1460);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 3318849759);
        EXPECT_EQ(tcp.options.ts.TSecr, 0);
        EXPECT_EQ(tcp.options.mpJoin.content.index(), 0);
        if (auto content = std::get_if<0>(&tcp.options.mpJoin.content); content) {
            EXPECT_EQ(content->flags, 0);
            EXPECT_EQ(content->addressId, 1);
            EXPECT_EQ(content->receiverToken, 2816019784);
            EXPECT_EQ(content->senderRand, 2665909875);
        }
    }

    // SYN+ACK + MP_JOIN
    {
        scion::ReadStream stream(pkts.at(8));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::SYN | TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0xee55);
        EXPECT_EQ(tcp.optMask.MSS, 1);
        EXPECT_EQ(tcp.optMask.WS, 1);
        EXPECT_EQ(tcp.optMask.SAckPerm, 1);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 1);
        EXPECT_EQ(tcp.options.mss.mss, 1460);
        EXPECT_EQ(tcp.options.ws.wndShift, 7);
        EXPECT_EQ(tcp.options.ts.TSval, 2891813051);
        EXPECT_EQ(tcp.options.ts.TSecr, 3318849759);
        EXPECT_EQ(tcp.options.mpJoin.content.index(), 1);
        if (auto content = std::get_if<1>(&tcp.options.mpJoin.content); content) {
            EXPECT_EQ(content->flags, 0);
            EXPECT_EQ(content->addressId, 1);
            EXPECT_EQ(content->senderMac, 0x1dfa588a2e6df167);
            EXPECT_EQ(content->senderRand, 2845163021);
        }
    }

    // ACK + MP_JOIN
    {
        scion::ReadStream stream(pkts.at(9));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::ACK);
        EXPECT_EQ(tcp.chksum, 0x6fb8);
        EXPECT_EQ(tcp.optMask.MSS, 0);
        EXPECT_EQ(tcp.optMask.WS, 0);
        EXPECT_EQ(tcp.optMask.SAckPerm, 0);
        EXPECT_EQ(tcp.optMask.SAck, 0);
        EXPECT_EQ(tcp.optMask.TS, 1);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 1);
        EXPECT_EQ(tcp.options.ts.TSval, 3318849759);
        EXPECT_EQ(tcp.options.ts.TSecr, 2891813051);
        EXPECT_EQ(tcp.options.mpJoin.content.index(), 2);
        if (auto content = std::get_if<2>(&tcp.options.mpJoin.content); content) {
            static const std::byte mac[] = {
                0x70_b, 0xb2_b, 0x03_b, 0x9a_b, 0xf4_b, 0x40_b, 0x9d_b, 0x31_b,
                0x33_b, 0xae_b, 0x8b_b, 0xbd_b, 0x91_b, 0x34_b, 0x02_b, 0xf6_b,
                0xb6_b, 0x95_b, 0x77_b, 0xfa_b
            };
            EXPECT_THAT(content->senderMac, testing::ElementsAreArray(mac));
        }
    }

    // REMOVE_ADDR 1
    {
        scion::ReadStream stream(pkts.at(10));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.chksum, 0x7c21);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 0);
        EXPECT_EQ(tcp.optMask.MpRemAddr, 1);
        EXPECT_EQ(tcp.optMask.MpPrio, 1);
        EXPECT_EQ(tcp.optMask.MpFail, 0);
        EXPECT_EQ(tcp.optMask.MpClose, 0);
        EXPECT_EQ(tcp.optMask.MpRst, 0);
        EXPECT_THAT(tcp.options.mpRem.getAddressIds(), testing::ElementsAre(2));
        EXPECT_TRUE(tcp.options.mpPrio.backup);
    }

    // REMOVE_ADDR 2
    {
        scion::ReadStream stream(pkts.at(11));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.chksum, 0xd736);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 0);
        EXPECT_EQ(tcp.optMask.MpRemAddr, 1);
        EXPECT_EQ(tcp.optMask.MpPrio, 0);
        EXPECT_EQ(tcp.optMask.MpFail, 0);
        EXPECT_EQ(tcp.optMask.MpClose, 0);
        EXPECT_EQ(tcp.optMask.MpRst, 0);
        EXPECT_THAT(tcp.options.mpRem.getAddressIds(), testing::ElementsAre(1, 2));
    }

    // MP_FAIL
    {
        scion::ReadStream stream(pkts.at(12));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.chksum, 0x137d);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 0);
        EXPECT_EQ(tcp.optMask.MpRemAddr, 0);
        EXPECT_EQ(tcp.optMask.MpPrio, 0);
        EXPECT_EQ(tcp.optMask.MpFail, 1);
        EXPECT_EQ(tcp.optMask.MpClose, 0);
        EXPECT_EQ(tcp.optMask.MpRst, 0);
        EXPECT_EQ(tcp.options.mpFail.dsn, 2398994140307414020);
    }

    // MP_FASTCLOSE
    {
        scion::ReadStream stream(pkts.at(13));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::RST);
        EXPECT_EQ(tcp.chksum, 0x9b67);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 0);
        EXPECT_EQ(tcp.optMask.MpRemAddr, 0);
        EXPECT_EQ(tcp.optMask.MpPrio, 0);
        EXPECT_EQ(tcp.optMask.MpFail, 0);
        EXPECT_EQ(tcp.optMask.MpClose, 1);
        EXPECT_EQ(tcp.optMask.MpRst, 0);
        EXPECT_EQ(tcp.options.mpClose.receiverKey, 0x5193274a5611d62b);
    }

    // MP_TCPRST
    {
        scion::ReadStream stream(pkts.at(14));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;
        EXPECT_EQ(tcp.flags, TCP::Flags::RST);
        EXPECT_EQ(tcp.chksum, 0x4f90);
        EXPECT_EQ(tcp.optMask.MpCapable, 0);
        EXPECT_EQ(tcp.optMask.MpJoin, 0);
        EXPECT_EQ(tcp.optMask.MpDss, 0);
        EXPECT_EQ(tcp.optMask.MpAddAddr, 0);
        EXPECT_EQ(tcp.optMask.MpRemAddr, 0);
        EXPECT_EQ(tcp.optMask.MpPrio, 0);
        EXPECT_EQ(tcp.optMask.MpFail, 0);
        EXPECT_EQ(tcp.optMask.MpClose, 0);
        EXPECT_EQ(tcp.optMask.MpRst, 1);
        EXPECT_EQ(tcp.options.mpRst.flags, TcpMpRstOpt::Flags::Transient);
        EXPECT_EQ(tcp.options.mpRst.reason, TcpMpRstOpt::Reason::LackOfResources);
    }
}

TEST(MPTCP, Emit)
{
    using namespace scion::hdr;

    auto pkts = loadPackets("hdr/data/mptcp.bin");

    auto host1 = unwrap(scion::generic::IPAddress::Parse("10.128.0.1"));
    auto host2 = unwrap(scion::generic::IPAddress::Parse("10.128.0.2"));
    IPv4 ip;
    ip.flags = IPv4::Flags(0);
    ip.proto = IPProto::TCP;

    // SYN + MP_CAPABLE
    {
        auto& expected = pkts.at(0);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.window = 64240;
        tcp.seq = 2156917410;
        tcp.ack = 0;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.optMask.MpCapable = 1;
        tcp.options.mss.mss = 1460;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 3301642972;
        tcp.options.ts.TSecr = 0;
        tcp.options.mpCap.flags = TcpMpCapableOpt::Flags::HMAC_SHA256;
        tcp.options.mpCap.version = 1;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // SYN+ACK + MP_CAPABLE
    {
        auto& expected = pkts.at(1);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host2;
        ip.dst = host1;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN | TCP::Flags::ACK;
        tcp.sport = 5201;
        tcp.dport = 34802;
        tcp.window = 65160;
        tcp.seq = 1960638239;
        tcp.ack = 2156917411;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.optMask.MpCapable = 1;
        tcp.options.mss.mss = 1460;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 2874606264;
        tcp.options.ts.TSecr = 3301642972;
        tcp.options.mpCap.fieldMask.senderKey = 1;
        tcp.options.mpCap.flags = TcpMpCapableOpt::Flags::HMAC_SHA256;
        tcp.options.mpCap.version = 1;
        tcp.options.mpCap.senderKey = 0x5193274a5611d62b;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // ACK + MP_CAPABLE
    {
        auto& expected = pkts.at(2);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.window = 502;
        tcp.seq = 2156917411;
        tcp.ack = 1960638240;
        tcp.optMask.TS = 1;
        tcp.optMask.MpCapable = 1;
        tcp.options.ts.TSval = 3301642972;
        tcp.options.ts.TSecr = 2874606264;
        tcp.options.mpCap.fieldMask.senderKey = 1;
        tcp.options.mpCap.fieldMask.receiverKey = 1;
        tcp.options.mpCap.flags = TcpMpCapableOpt::Flags::HMAC_SHA256;
        tcp.options.mpCap.version = 1;
        tcp.options.mpCap.senderKey = 0xbf7c79774d5b7531;
        tcp.options.mpCap.receiverKey = 0x5193274a5611d62b;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // DSS 1
    {
        auto& expected = pkts.at(3);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host2;
        ip.dst = host1;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 5201;
        tcp.dport = 34802;
        tcp.window = 509;
        tcp.seq = 1960638240;
        tcp.ack = 2156917448;
        tcp.optMask.TS = 1;
        tcp.optMask.MpDss = 1;
        tcp.options.ts.TSval = 2874606264;
        tcp.options.ts.TSecr = 3301642972;
        tcp.options.mpDss.flags = TcpMpDssOpt::Flags::ACK | TcpMpDssOpt::Flags::ACK8;
        tcp.options.mpDss.dataAck.u64 = 2398994140307282948;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // DSS 2
    {
        auto& expected = pkts.at(4);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        using Flags = TcpMpDssOpt::Flags;
        tcp.flags = TCP::Flags::PSH | TCP::Flags::ACK;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.window = 502;
        tcp.seq = 2157048520;
        tcp.ack = 1960638240;
        tcp.optMask.TS = 1;
        tcp.optMask.MpDss = 1;
        tcp.options.ts.TSval = 3301643078;
        tcp.options.ts.TSecr = 2874606265;
        tcp.options.mpDss.flags = Flags::ACK | Flags::DSN | Flags::DSN8;
        tcp.options.mpDss.dataAck.u32 = 1785050047;
        tcp.options.mpDss.dsn.u64 = 2398994140307414020;
        tcp.options.mpDss.subflowSeq = 131110;
        tcp.options.mpDss.dataLevelLen = 64080;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // ADD_ADDR
    {
        auto& expected = pkts.at(5);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host2;
        ip.dst = host1;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 5201;
        tcp.dport = 34802;
        tcp.window = 502;
        tcp.seq = 3928170229;
        tcp.ack = 3710395719;
        tcp.optMask.TS = 1;
        tcp.optMask.MpAddAddr = 1;
        tcp.options.ts.TSval = 2874606264;
        tcp.options.ts.TSecr = 3301642972;
        tcp.options.mpAdd.addressId = 2;
        tcp.options.mpAdd.address =
            unwrap(scion::generic::IPAddress::Parse("fc00:10fc:100::2"));
        tcp.options.mpAdd.mac = 0x02af8006b38daba6;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // ADD_ADDR Echo
    {
        auto& expected = pkts.at(6);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.window = 509;
        tcp.seq = 2156917448;
        tcp.ack = 1960638240;
        tcp.optMask.TS = 1;
        tcp.optMask.MpAddAddr = 1;
        tcp.options.ts.TSval = 3301642972;
        tcp.options.ts.TSecr = 2874606264;
        tcp.options.mpAdd.flags = TcpMpAddAddrOpt::Flags::Echo;
        tcp.options.mpAdd.addressId = 2;
        tcp.options.mpAdd.address =
            unwrap(scion::generic::IPAddress::Parse("fc00:10fc:100::2"));
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // SYN + MP_JOIN
    {
        auto& expected = pkts.at(7);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN;
        tcp.sport = 51435;
        tcp.dport = 5201;
        tcp.window = 64896;
        tcp.seq = 3321739861;
        tcp.ack = 0;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.optMask.MpJoin = 1;
        tcp.options.mss.mss = 1460;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 3318849759;
        tcp.options.ts.TSecr = 0;
        tcp.options.mpJoin.content = TcpMpJoinOpt::Syn{
            .flags = TcpMpJoinOpt::Flags(0),
            .addressId = 1,
            .receiverToken = 2816019784,
            .senderRand = 2665909875
        };
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // SYN+ACK + MP_JOIN
    {
        auto& expected = pkts.at(8);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host2;
        ip.dst = host1;

        TCP tcp;
        tcp.flags = TCP::Flags::SYN | TCP::Flags::ACK;
        tcp.sport = 5201;
        tcp.dport = 51435;
        tcp.window = 65160;
        tcp.seq = 464174314;
        tcp.ack = 3321739862;
        tcp.optMask.MSS = 1;
        tcp.optMask.WS = 1;
        tcp.optMask.SAckPerm = 1;
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.optMask.MpJoin = 1;
        tcp.options.mss.mss = 1460;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 2891813051;
        tcp.options.ts.TSecr = 3318849759;
        tcp.options.mpJoin.content = TcpMpJoinOpt::SynAck{
            .flags = TcpMpJoinOpt::Flags(0),
            .addressId = 1,
            .senderMac = 0x1dfa588a2e6df167,
            .senderRand = 2845163021
        };
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // ACK + MP_JOIN
    {
        auto& expected = pkts.at(9);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::ACK;
        tcp.sport = 51435;
        tcp.dport = 5201;
        tcp.window = 507;
        tcp.seq = 3321739862;
        tcp.ack = 464174315;
        tcp.optMask.TS = 1;
        tcp.optMask.MpJoin = 1;
        tcp.options.ts.TSval = 3318849759;
        tcp.options.ts.TSecr = 2891813051;
        tcp.options.mpJoin.content = TcpMpJoinOpt::Ack{
            .senderMac = {
                0x70_b, 0xb2_b, 0x03_b, 0x9a_b, 0xf4_b, 0x40_b, 0x9d_b, 0x31_b,
                0x33_b, 0xae_b, 0x8b_b, 0xbd_b, 0x91_b, 0x34_b, 0x02_b, 0xf6_b,
                0xb6_b, 0x95_b, 0x77_b, 0xfa_b
            }
        };
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // REMOVE_ADDR 1
    {
        auto& expected = pkts.at(10);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.optMask.MpRemAddr = 1;
        tcp.optMask.MpPrio = 1;
        tcp.options.mpRem.addressIds = {2};
        tcp.options.mpRem.count = 1;
        tcp.options.mpPrio.backup = true;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // REMOVE_ADDR 2
    {
        auto& expected = pkts.at(11);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.optMask.MpRemAddr = 1;
        tcp.options.mpRem.addressIds = {1, 2};
        tcp.options.mpRem.count = 2;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // MP_FAIL
    {
        auto& expected = pkts.at(12);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.optMask.MpFail = 1;
        tcp.options.mpFail.dsn = 2398994140307414020;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // MP_FASTCLOSE
    {
        auto& expected = pkts.at(13);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::RST;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.optMask.MpClose= 1;
        tcp.options.mpClose.receiverKey = 0x5193274a5611d62b;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }

    // MP_TCPRST
    {
        auto& expected = pkts.at(14);
        std::vector<std::byte> buffer(expected.size());
        scion::WriteStream stream(buffer);
        scion::StreamError err;

        ip.src = host1;
        ip.dst = host2;

        TCP tcp;
        tcp.flags = TCP::Flags::RST;
        tcp.sport = 34802;
        tcp.dport = 5201;
        tcp.optMask.MpRst= 1;
        tcp.options.mpRst.flags = TcpMpRstOpt::Flags::Transient;
        tcp.options.mpRst.reason = TcpMpRstOpt::Reason::LackOfResources;
        std::span<std::byte> payload = {};

        ip.len = (std::uint16_t)(ip.size() + tcp.size());
        tcp.chksum = details::internetChecksum(payload,
            ip.checksum((uint16_t)tcp.size()) + tcp.checksum());

        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
    }
}

TEST(MPTCP, Print)
{
    using namespace scion::hdr;

    auto pkts = loadPackets("hdr/data/mptcp.bin");

    static std::array<const char*, 15> expected = {
        // SYN + MP_CAPABLE
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 2156917410\n"
        "ack    = 0\n"
        "flags  = 0x2\n"
        "window = 64240\n"
        "chksum = 8678\n"
        "urgptr = 0\n"
        "mss    = 1460\n"
        "sack   = permitted\n"
        "TSval  = 3301642972\n"
        "TSecr  = 0\n"
        "wshift = 7\n"
        "###[ TCP MP_CAPABLE Opt ]###\n"
        "kind         = 30\n"
        "length       = 4\n"
        "subtype      = 0\n"
        "version      = 1\n"
        "flags        = 0x1\n",
        // SYN+ACK + MP_CAPABLE
        "###[ TCP ]###\n"
        "sport  = 5201\n"
        "dport  = 34802\n"
        "seq    = 1960638239\n"
        "ack    = 2156917411\n"
        "flags  = 0x12\n"
        "window = 65160\n"
        "chksum = 16134\n"
        "urgptr = 0\n"
        "mss    = 1460\n"
        "sack   = permitted\n"
        "TSval  = 2874606264\n"
        "TSecr  = 3301642972\n"
        "wshift = 7\n"
        "###[ TCP MP_CAPABLE Opt ]###\n"
        "kind         = 30\n"
        "length       = 12\n"
        "subtype      = 0\n"
        "version      = 1\n"
        "flags        = 0x1\n"
        "senderKey    = 0x5193274a5611d62b\n",
        // ACK + MP_CAPABLE
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 2156917411\n"
        "ack    = 1960638240\n"
        "flags  = 0x10\n"
        "window = 502\n"
        "chksum = 20180\n"
        "urgptr = 0\n"
        "TSval  = 3301642972\n"
        "TSecr  = 2874606264\n"
        "###[ TCP MP_CAPABLE Opt ]###\n"
        "kind         = 30\n"
        "length       = 20\n"
        "subtype      = 0\n"
        "version      = 1\n"
        "flags        = 0x1\n"
        "senderKey    = 0xbf7c79774d5b7531\n"
        "receiverKey  = 0x5193274a5611d62b\n",
        // DSS 1
        "###[ TCP ]###\n"
        "sport  = 5201\n"
        "dport  = 34802\n"
        "seq    = 1960638240\n"
        "ack    = 2156917448\n"
        "flags  = 0x10\n"
        "window = 509\n"
        "chksum = 45898\n"
        "urgptr = 0\n"
        "TSval  = 2874606264\n"
        "TSecr  = 3301642972\n"
        "###[ TCP MP_CAPABLE Opt ]###\n"
        "kind         = 30\n"
        "length       = 12\n"
        "subtype      = 2\n"
        "flags        = 0x3\n"
        "dataAck      = 2398994140307282948\n",
        // DSS 2
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 2157048520\n"
        "ack    = 1960638240\n"
        "flags  = 0x18\n"
        "window = 502\n"
        "chksum = 27164\n"
        "urgptr = 0\n"
        "TSval  = 3301643078\n"
        "TSecr  = 2874606265\n"
        "###[ TCP MP_CAPABLE Opt ]###\n"
        "kind         = 30\n"
        "length       = 22\n"
        "subtype      = 2\n"
        "flags        = 0xd\n"
        "dataAck      = 1785050047\n"
        "dsn          = 2398994140307414020\n"
        "subflowSeq   = 131110\n"
        "dataLevelLen = 64080\n",
        // ADD_ADDR
        "###[ TCP ]###\n"
        "sport  = 5201\n"
        "dport  = 34802\n"
        "seq    = 3928170229\n"
        "ack    = 3710395719\n"
        "flags  = 0x10\n"
        "window = 502\n"
        "chksum = 33821\n"
        "urgptr = 0\n"
        "TSval  = 2874606264\n"
        "TSecr  = 3301642972\n"
        "###[ TCP ADD_ADDR Opt ]###\n"
        "kind      = 30\n"
        "length    = 28\n"
        "subtype   = 3\n"
        "flags     = 0x0\n"
        "addressId = 2\n"
        "address   = fc00:10fc:100::2\n"
        "mac       = 0x2af8006b38daba6\n",
        // ADD_ADDR Echo
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 2156917448\n"
        "ack    = 1960638240\n"
        "flags  = 0x10\n"
        "window = 509\n"
        "chksum = 45379\n"
        "urgptr = 0\n"
        "TSval  = 3301642972\n"
        "TSecr  = 2874606264\n"
        "###[ TCP ADD_ADDR Opt ]###\n"
        "kind      = 30\n"
        "length    = 20\n"
        "subtype   = 3\n"
        "flags     = 0x1\n"
        "addressId = 2\n"
        "address   = fc00:10fc:100::2\n",
        // SYN + MP_JOIN
        "###[ TCP ]###\n"
        "sport  = 51435\n"
        "dport  = 5201\n"
        "seq    = 3321739861\n"
        "ack    = 0\n"
        "flags  = 0x2\n"
        "window = 64896\n"
        "chksum = 12454\n"
        "urgptr = 0\n"
        "mss    = 1460\n"
        "sack   = permitted\n"
        "TSval  = 3318849759\n"
        "TSecr  = 0\n"
        "wshift = 7\n"
        "###[ TCP MP_JOIN Opt ]###\n"
        "kind          = 30\n"
        "length        = 12\n"
        "subtype       = 1\n"
        "flags         = 0x0\n"
        "addressId     = 1\n"
        "receiverToken = 2816019784\n"
        "senderRand    = 2665909875\n",
        // SYN+ACK + MP_JOIN
        "###[ TCP ]###\n"
        "sport  = 5201\n"
        "dport  = 51435\n"
        "seq    = 464174314\n"
        "ack    = 3321739862\n"
        "flags  = 0x12\n"
        "window = 65160\n"
        "chksum = 61013\n"
        "urgptr = 0\n"
        "mss    = 1460\n"
        "sack   = permitted\n"
        "TSval  = 2891813051\n"
        "TSecr  = 3318849759\n"
        "wshift = 7\n"
        "###[ TCP MP_JOIN Opt ]###\n"
        "kind          = 30\n"
        "length        = 16\n"
        "subtype       = 1\n"
        "flags         = 0x0\n"
        "addressId     = 1\n"
        "senderMac     = 2160136321785262439\n"
        "senderRand    = 2845163021\n",
        // ACK + MP_JOIN
        "###[ TCP ]###\n"
        "sport  = 51435\n"
        "dport  = 5201\n"
        "seq    = 3321739862\n"
        "ack    = 464174315\n"
        "flags  = 0x10\n"
        "window = 507\n"
        "chksum = 28600\n"
        "urgptr = 0\n"
        "TSval  = 3318849759\n"
        "TSecr  = 2891813051\n"
        "###[ TCP MP_JOIN Opt ]###\n"
        "kind          = 30\n"
        "length        = 24\n"
        "subtype       = 1\n"
        "senderMac     = 70:b2:03:9a:f4:40:9d:31:33:ae:8b:bd:91:34:02:f6:b6:95:77:fa\n",
        // REMOVE_ADDR 1
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 0\n"
        "ack    = 0\n"
        "flags  = 0x0\n"
        "window = 0\n"
        "chksum = 31777\n"
        "urgptr = 0\n"
        "###[ TCP REMOVE_ADDR Opt ]###\n"
        "kind         = 30\n"
        "length       = 4\n"
        "subtype      = 4\n"
        "addressId[0] = 2\n"
        "###[ TCP MP_PRIO Opt ]###\n"
        "kind    = 30\n"
        "length  = 3\n"
        "subtype = 5\n"
        "backup  = true\n",
        // REMOVE_ADDR 2
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 0\n"
        "ack    = 0\n"
        "flags  = 0x0\n"
        "window = 0\n"
        "chksum = 55094\n"
        "urgptr = 0\n"
        "###[ TCP REMOVE_ADDR Opt ]###\n"
        "kind         = 30\n"
        "length       = 5\n"
        "subtype      = 4\n"
        "addressId[0] = 1\n"
        "addressId[1] = 2\n",
        // MP_FAIL
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 0\n"
        "ack    = 0\n"
        "flags  = 0x0\n"
        "window = 0\n"
        "chksum = 4989\n"
        "urgptr = 0\n"
        "###[ TCP MP_FAIL Opt ]###\n"
        "kind    = 30\n"
        "length  = 12\n"
        "subtype = 6\n"
        "dsn     = 2398994140307414020\n",
        // MP_FASTCLOSE
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 0\n"
        "ack    = 0\n"
        "flags  = 0x4\n"
        "window = 0\n"
        "chksum = 39783\n"
        "urgptr = 0\n"
        "###[ TCP MP_FASTCLOSE Opt ]###\n"
        "kind         = 30\n"
        "length       = 12\n"
        "subtype      = 7\n"
        "receiverKey  = 0x5193274a5611d62b\n",
        // MP_TCPRST
        "###[ TCP ]###\n"
        "sport  = 34802\n"
        "dport  = 5201\n"
        "seq    = 0\n"
        "ack    = 0\n"
        "flags  = 0x4\n"
        "window = 0\n"
        "chksum = 20368\n"
        "urgptr = 0\n"
        "###[ TCP MP_TCPRST Opt ]###\n"
        "kind    = 30\n"
        "length  = 4\n"
        "subtype = 8\n"
        "flags   = 0x1\n"
        "reason  = 2\n"
    };

    for (std::size_t i = 0; i < expected.size(); ++i) {
        scion::ReadStream stream(pkts.at(i));
        scion::StreamError err;
        IPv4 ip;
        TCP tcp;
        ASSERT_TRUE(ip.serialize(stream, err)) << err;
        ASSERT_TRUE(tcp.serialize(stream, err)) << err;

        std::string str;
        str.reserve(std::strlen(expected[i]));
        std::back_insert_iterator out(str);
        out = tcp.print(out, 0);
        EXPECT_EQ(str, expected[i]);
    }
}
