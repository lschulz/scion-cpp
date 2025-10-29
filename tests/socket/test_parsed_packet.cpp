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

#include "scion/extensions/extension.hpp"
#include "scion/extensions/idint.hpp"
#include "scion/hdr/udp.hpp"
#include "scion/path/raw.hpp"
#include "scion/socket/parsed_packet.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <ranges>


class ParsedPacketFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace scion::generic;
        src = unwrap(Address<IPAddress>::Parse("1-ff00:0:1,10.0.0.1"));
        dst = unwrap(Address<IPAddress>::Parse("2-ff00:0:2,fd00::1"));
        pathBytes = loadPackets("socket/data/raw_path.bin").at(0);
        packets = loadPackets("socket/data/packets.bin");
    };

    inline static scion::Address<scion::generic::IPAddress> src, dst;
    inline static std::vector<std::byte> pathBytes;
    inline static std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    inline static std::vector<std::vector<std::byte>> packets;
};

TEST_F(ParsedPacketFixture, ParseUDP)
{
    using namespace scion;
    using namespace scion::generic;
    using namespace scion::hdr;

    ParsedPacket<UDP> pkt;
    ReadStream rs(packets.at(0));
    StreamError err;
    ASSERT_TRUE(pkt.parse(rs, err)) << err;
    EXPECT_EQ(pkt.checksum(), 0xffffu);

    // SCION main header
    EXPECT_EQ(pkt.sci.qos, 64);
    EXPECT_EQ(pkt.sci.hlen, 46);
    EXPECT_EQ(pkt.sci.nh, ScionProto::UDP);
    EXPECT_EQ(pkt.sci.ptype, PathType::SCION);
    EXPECT_EQ(pkt.sci.plen, 16);
    EXPECT_EQ(pkt.sci.fl, 0x05'4b20u);
    EXPECT_EQ(pkt.sci.dst, dst);
    EXPECT_EQ(pkt.sci.src, src);

    // Path
    EXPECT_TRUE(std::ranges::equal(pkt.path, pathBytes)) << printBufferDiff(pkt.path, pathBytes);

    // Extensions
    EXPECT_TRUE(pkt.hbhOpts.empty());
    EXPECT_TRUE(pkt.e2eOpts.empty());

    // UDP
    ASSERT_TRUE(std::holds_alternative<UDP>(pkt.l4));
    auto& udp = std::get<UDP>(pkt.l4);
    EXPECT_EQ(udp.sport, 3000);
    EXPECT_EQ(udp.dport, 8000);
    EXPECT_EQ(udp.len, 16);

    // Payload
    EXPECT_TRUE(std::ranges::equal(pkt.payload, payload)) << printBufferDiff(pkt.payload, payload);
}

TEST_F(ParsedPacketFixture, ParseSCMP)
{
    using namespace scion;
    using namespace scion::generic;
    using namespace scion::hdr;

    ParsedPacket<UDP> pkt;
    ReadStream rs(packets.at(2));
    StreamError err;
    ASSERT_TRUE(pkt.parse(rs, err)) << err;
    EXPECT_EQ(pkt.checksum(), 0xffffu);

    // SCION main header
    EXPECT_EQ(pkt.sci.qos, 64);
    EXPECT_EQ(pkt.sci.hlen, 46);
    EXPECT_EQ(pkt.sci.nh, ScionProto::SCMP);
    EXPECT_EQ(pkt.sci.ptype, PathType::SCION);
    EXPECT_EQ(pkt.sci.plen, 16);
    EXPECT_EQ(pkt.sci.fl, 0x01'7124u);
    EXPECT_EQ(pkt.sci.dst, dst);
    EXPECT_EQ(pkt.sci.src, src);

    // Path
    EXPECT_TRUE(std::ranges::equal(pkt.path, pathBytes)) << printBufferDiff(pkt.path, pathBytes);

    // Extensions
    EXPECT_TRUE(pkt.hbhOpts.empty());
    EXPECT_TRUE(pkt.e2eOpts.empty());

    // SCMP
    ASSERT_TRUE(std::holds_alternative<SCMP>(pkt.l4));
    auto& scmp = std::get<SCMP>(pkt.l4);
    ASSERT_TRUE(std::holds_alternative<ScmpEchoRequest>(scmp.msg));
    auto& echo = std::get<ScmpEchoRequest>(scmp.msg);
    EXPECT_EQ(echo.id, 1);
    EXPECT_EQ(echo.seq, 100);

    // Payload
    EXPECT_TRUE(std::ranges::equal(pkt.payload, payload)) << printBufferDiff(pkt.payload, payload);
}

TEST_F(ParsedPacketFixture, ParseIdInt)
{
    using namespace scion;
    using namespace scion::generic;
    using namespace scion::hdr;

    ParsedPacket<UDP> pkt;
    ReadStream rs(packets.at(4));
    StreamError err;
    ASSERT_TRUE(pkt.parse(rs, err)) << err;
    EXPECT_EQ(pkt.checksum(), 0xffffu);

    // SCION main header
    EXPECT_EQ(pkt.sci.qos, 64);
    EXPECT_EQ(pkt.sci.hlen, 46);
    EXPECT_EQ(pkt.sci.nh, ScionProto::HBHOpt);
    EXPECT_EQ(pkt.sci.ptype, PathType::SCION);
    EXPECT_EQ(pkt.sci.plen, 104);
    EXPECT_EQ(pkt.sci.fl, 0x05'4b20u);
    EXPECT_EQ(pkt.sci.dst, dst);
    EXPECT_EQ(pkt.sci.src, src);

    // Path
    EXPECT_TRUE(std::ranges::equal(pkt.path, pathBytes)) << printBufferDiff(pkt.path, pathBytes);

    // Extensions
    EXPECT_EQ(pkt.hbhOpts.size(), 86);
    EXPECT_TRUE(pkt.e2eOpts.empty());

    // UDP
    ASSERT_TRUE(std::holds_alternative<UDP>(pkt.l4));
    auto& udp = std::get<UDP>(pkt.l4);
    EXPECT_EQ(udp.sport, 3000);
    EXPECT_EQ(udp.dport, 8000);
    EXPECT_EQ(udp.len, 16);

    // Payload
    EXPECT_TRUE(std::ranges::equal(pkt.payload, payload)) << printBufferDiff(pkt.payload, payload);
}
