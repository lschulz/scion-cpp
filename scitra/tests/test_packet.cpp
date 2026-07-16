// Copyright (c) 2026 Lars-Christian Schulz
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

#include "scitra/packet.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"


TEST(Packet, RemovePayload)
{
    using namespace scion;
    using namespace scion::scitra;

    auto data = loadPackets("data/remove_payload.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);

    PacketBuffer pkt(std::pmr::vector<std::byte>(256));
    {
        auto dst = pkt.clearAndGetBuffer(64);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), true, nullptr);
    ASSERT_FALSE(ec) << fmtError(ec);

    pkt.removePayload();

    auto out = pkt.emitPacket(false);
    ASSERT_FALSE(isError(out)) << fmtError(out.error());
    EXPECT_TRUE(std::ranges::equal(*out, expected)) << printBufferDiff(*out, expected);
}

TEST(Packet, ChangePayload)
{
    using namespace scion;
    using namespace scion::scitra;

    static const std::array<const std::byte, 16> newPayload = {
        0x00_b, 0x01_b, 0x02_b, 0x03_b, 0x04_b, 0x05_b, 0x06_b, 0x07_b,
        0x08_b, 0x09_b, 0x0a_b, 0x0b_b, 0x0c_b, 0x0d_b, 0x0e_b, 0x0f_b,
    };

    auto data = loadPackets("data/remove_payload.bin");
    auto& input = data.at(0);
    auto& expected = data.at(1);
    expected.reserve(expected.size() + newPayload.size());
    std::ranges::copy(newPayload, std::back_inserter(expected));

    PacketBuffer pkt(std::pmr::vector<std::byte>(256));
    {
        auto dst = pkt.clearAndGetBuffer(64);
        ASSERT_LE(input.size(), dst.size());
        std::ranges::copy(input, dst.begin());
    }

    auto ec = pkt.parsePacket(input.size(), true, nullptr);
    ASSERT_FALSE(ec) << fmtError(ec);

    std::vector<std::byte> largePayload(200);
    EXPECT_EQ(pkt.setPayload(largePayload), ErrorCondition::BufferTooSmall);
    EXPECT_EQ(pkt.setPayload(newPayload), ErrorCondition::Ok);

    EXPECT_THAT(pkt.payload(), testing::ElementsAreArray(newPayload));

    auto out = pkt.emitPacket(false);
    ASSERT_FALSE(isError(out)) << fmtError(out.error());
    EXPECT_TRUE(std::ranges::equal(*out, expected)) << printBufferDiff(*out, expected);
}
