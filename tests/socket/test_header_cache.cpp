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
#include "scion/socket/header_cache.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <ranges>


class HeaderCacheFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
        tgt = unwrap(IsdAsn::Parse("2-ff00:0:2"));
        pathBytes = loadPackets("socket/data/raw_path.bin").at(0);
        packets = loadPackets("socket/data/packets.bin");
    };

    template <typename Alloc>
    static std::error_code initIdIntExt(scion::idint::IdInt<Alloc>& idint)
    {
        using namespace scion::idint;
        using scion::drkey::Key;

        IntRequest req;
        req.flags.discard = 1;
        req.agrMode = AM::AS;
        req.vtype = Verifier::Destination;
        req.bitmap = InstrFlag::NodeID;
        req.maxStackLen = 384;
        req.agrFuncs = {AF::Last, AF::Last, AF::First, AF::First};
        req.instructions = {
            Instr::IngressTstamp,
            Instr::DeviceTypeRole,
            Instr::Nop,
            Instr::Nop,
        };
        req.identifier.timestamp = 1000;
        req.identifier.port = 10;
        req.srcData.setNodeId(2);
        req.srcData.setMetadata(0, Instr::IngressTstamp, 3u);
        req.srcData.setMetadata(1, Instr::DeviceTypeRole, 4u);

        Key k;
        k.key = {};
        return idint.encodeIntRequest(req, k, nullptr);
    }

    inline static scion::IsdAsn src, tgt;
    inline static std::vector<std::byte> pathBytes;
    inline static std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    inline static std::vector<std::vector<std::byte>> packets;
};

TEST_F(HeaderCacheFixture, BuildUDP)
{
    using namespace scion;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    HeaderCache hdr;
    auto err = hdr.build(64, to, from, rp, ext::NoExtensions, hdr::UDP{}, payload);
    ASSERT_FALSE(err);

    auto expected = truncate(packets.at(0), -8);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(HeaderCacheFixture, UpdatePayload)
{
    using namespace scion;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    HeaderCache hdr;
    hdr::UDP udp;
    auto err = hdr.build(64, to, from, rp, ext::NoExtensions, udp, payload);
    ASSERT_FALSE(err);

    static std::array<std::byte, 16> newPayload = {
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b,
        0x07_b, 0x06_b, 0x05_b, 0x04_b, 0x03_b, 0x02_b, 0x01_b, 0x00_b,
    };
    err = hdr.updatePayload(udp, newPayload);
    ASSERT_FALSE(err);

    auto expected = truncate(packets.at(1), -16);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(HeaderCacheFixture, BuildSCMP)
{
    using namespace scion;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    hdr::SCMP scmp;
    scmp.msg = hdr::ScmpEchoRequest{1, 100};

    HeaderCache hdr;
    auto err = hdr.build(64, to, from, rp, ext::NoExtensions, scmp, payload);
    ASSERT_FALSE(err);

    auto expected = truncate(packets.at(2), -8);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(HeaderCacheFixture, UpdateL4Type)
{
    using namespace scion;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    HeaderCache hdr;
    auto err = hdr.build(64, to, from, rp, ext::NoExtensions, hdr::UDP{}, payload);
    ASSERT_FALSE(err);

    hdr::SCMP scmp;
    scmp.msg = hdr::ScmpEchoRequest{1, 100};
    err = hdr.updatePayload(scmp, std::span<std::byte>());
    ASSERT_FALSE(err);

    auto expected = packets.at(3);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(HeaderCacheFixture, BuildIdInt)
{
    using namespace scion;
    using namespace scion::hdr;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    idint::IdInt idint;
    ASSERT_FALSE(initIdIntExt(idint));

    HeaderCache hdr;
    std::array<ext::Extension*, 1> extensions = { &idint };
    auto err = hdr.build(64, to, from, rp, extensions, hdr::UDP{}, payload);
    ASSERT_FALSE(err);

    auto expected = truncate(packets.at(4), -8);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}
