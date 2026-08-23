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
    static void initIdIntExt(scion::ext::IdInt<Alloc>& idint)
    {
        using namespace scion::hdr;

        idint.main.dataLen = 22;
        idint.main.flags = IdIntOpt::Flags::Discard;
        idint.main.agrMode = IdIntOpt::AgrMode::AS;
        idint.main.vtype = IdIntOpt::Verifier::Destination;
        idint.main.stackLen = 16;
        idint.main.tos = 0;
        idint.main.delayHops = 0;
        idint.main.bitmap = IdIntInstFlags::NodeID;
        idint.main.agrFunc[0] = IdIntOpt::AgrFunction::Last;
        idint.main.agrFunc[1] = IdIntOpt::AgrFunction::Last;
        idint.main.agrFunc[2] = IdIntOpt::AgrFunction::First;
        idint.main.agrFunc[3] = IdIntOpt::AgrFunction::First;
        idint.main.instr[0] = IdIntInstruction::IngressTstamp;
        idint.main.instr[1] = IdIntInstruction::DeviceTypeRole;
        idint.main.instr[2] = IdIntInstruction::Nop;
        idint.main.instr[3] = IdIntInstruction::Nop;
        idint.main.sourceTS = 1000;
        idint.main.sourcePort = 10;
        idint.entries.emplace_back();

        auto& source = idint.entries.back();
        static const std::array<std::byte, 10> entry1 = {
            0x00_b, 0x00_b, 0x00_b, 0x02_b,
            0x00_b, 0x00_b, 0x00_b, 0x03_b,
            0x00_b, 0x04_b,
        };
        source.dataLen = 20;
        source.flags = IdIntEntry::Flags::Source;
        source.mask = IdIntInstFlags::NodeID;
        source.ml = {2, 1, 0, 0};
        std::copy(entry1.begin(), entry1.end(), source.metadata.begin());
        source.mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
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

    auto actual = clearScionFlowLabel(hdr.get());
    auto expected = clearScionFlowLabel(truncate(packets.at(0), -8));
    EXPECT_TRUE(std::ranges::equal(actual, expected)) << printBufferDiff(actual, expected);
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

    auto actual = clearScionFlowLabel(hdr.get());
    auto expected = clearScionFlowLabel(truncate(packets.at(1), -16));
    EXPECT_TRUE(std::ranges::equal(actual, expected)) << printBufferDiff(actual, expected);
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

    auto actual = clearScionFlowLabel(hdr.get());
    auto expected = clearScionFlowLabel(truncate(packets.at(2), -8));
    EXPECT_TRUE(std::ranges::equal(actual, expected)) << printBufferDiff(actual, expected);
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

    auto actual = clearScionFlowLabel(hdr.get());
    auto expected = clearScionFlowLabel(packets.at(3));
    EXPECT_TRUE(std::ranges::equal(actual, expected)) << printBufferDiff(actual, expected);
}

TEST_F(HeaderCacheFixture, BuildIdInt)
{
    using namespace scion;
    using namespace scion::hdr;
    using namespace scion::generic;

    RawPath rp(src, tgt, hdr::PathType::SCION, pathBytes);
    Endpoint<IPEndpoint> from(src, unwrap(IPEndpoint::Parse("10.0.0.1:3000")));
    Endpoint<IPEndpoint> to(tgt, unwrap(IPEndpoint::Parse("[fd00::1]:8000")));

    ext::IdInt idint;
    initIdIntExt(idint);

    HeaderCache hdr;
    std::array<ext::Extension*, 1> extensions = { &idint };
    auto err = hdr.build(64, to, from, rp, extensions, hdr::UDP{}, payload);
    ASSERT_FALSE(err);

    auto actual = clearScionFlowLabel(hdr.get());
    auto expected = clearScionFlowLabel(truncate(packets.at(4), -8));
    EXPECT_TRUE(std::ranges::equal(actual, expected)) << printBufferDiff(actual, expected);
}
