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
        ip.len = 60;
        tcp.flags = TCP::Flags::SYN;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 65495;
        tcp.urgptr = 0;
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
        ip.len = 60;
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
        tcp.optMask.SAck = 0;
        tcp.optMask.TS = 1;
        tcp.options.mss.mss = 1380;
        tcp.options.ws.wndShift = 7;
        tcp.options.ts.TSval = 1667661695;
        tcp.options.ts.TSecr = 1667661695;
        std::span<std::byte> payload = {};

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
        ip.len = 45;
        tcp.flags = TCP::Flags::PSH | TCP::Flags::ACK;
        tcp.sport = 34776;
        tcp.dport = 32000;
        tcp.window = 512;
        tcp.urgptr = 0;
        tcp.seq = 2060855181;
        tcp.ack = 2615407416;
        std::array<std::byte, 5> payload = { // "test\n"
            0x74_b, 0x65_b, 0x73_b, 0x74_b, 0x0a_b
        };

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
        tcp.urgptr = 0;
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
