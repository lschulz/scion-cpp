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
#include "scion/socket/packager.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <ranges>
#include <vector>


class PacketSocketFixture : public testing::Test
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

    template <typename Alloc>
    static void checkIdInt(const scion::ext::IdInt<Alloc>& idint)
    {
        using namespace scion::hdr;

        EXPECT_EQ(idint.main.dataLen, 22);
        EXPECT_EQ(idint.main.flags, IdIntOpt::Flags::Discard);
        EXPECT_EQ(idint.main.agrMode, IdIntOpt::AgrMode::AS);
        EXPECT_EQ(idint.main.vtype, IdIntOpt::Verifier::Destination);
        EXPECT_EQ(idint.main.stackLen, 16);
        EXPECT_EQ(idint.main.tos, 0);
        EXPECT_EQ(idint.main.delayHops, 0);
        EXPECT_EQ(idint.main.bitmap, IdIntInstFlags::NodeID);
        EXPECT_EQ(idint.main.agrFunc[0], IdIntOpt::AgrFunction::Last);
        EXPECT_EQ(idint.main.agrFunc[1], IdIntOpt::AgrFunction::Last);
        EXPECT_EQ(idint.main.agrFunc[2], IdIntOpt::AgrFunction::First);
        EXPECT_EQ(idint.main.agrFunc[3], IdIntOpt::AgrFunction::First);
        EXPECT_EQ(idint.main.instr[0], IdIntInstruction::IngressTstamp);
        EXPECT_EQ(idint.main.instr[1], IdIntInstruction::DeviceTypeRole);
        EXPECT_EQ(idint.main.instr[2], IdIntInstruction::Nop);
        EXPECT_EQ(idint.main.instr[3], IdIntInstruction::Nop);
        EXPECT_EQ(idint.main.sourceTS, 1000);
        EXPECT_EQ(idint.main.sourcePort, 10);

        EXPECT_EQ(idint.entries.size(), 1);
        auto& source = idint.entries[0];
        EXPECT_EQ(source.dataLen, 20);
        EXPECT_EQ(source.flags, IdIntEntry::Flags::Source);
        EXPECT_EQ(source.mask, IdIntInstFlags::NodeID);
        EXPECT_THAT(source.ml, testing::ElementsAre(2, 1, 0, 0));
        static const std::array<std::byte, 10> expected = {
            0x00_b, 0x00_b, 0x00_b, 0x02_b,
            0x00_b, 0x00_b, 0x00_b, 0x03_b,
            0x00_b, 0x04_b,
        };
        EXPECT_TRUE(std::ranges::equal(source.getMetadata(), expected))
            << printBufferDiff(source.getMetadata(), expected);
        EXPECT_THAT(source.mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));
    }

    inline static scion::Address<scion::generic::IPAddress> src, dst;
    inline static std::vector<std::byte> pathBytes;
    inline static std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    inline static std::vector<std::vector<std::byte>> packets;
};

TEST_F(PacketSocketFixture, PrepareSendUDP)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(src, 3000);
    Endpoint<IPEndpoint> remote(dst, 8000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    packager.setTrafficClass(64);
    EXPECT_EQ(packager.trafficClass(), 64);

    HeaderCache hdr;
    RawPath rp(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes);
    hdr::UDP udp;
    ASSERT_EQ(
        packager.pack(hdr, &remote, rp, ext::NoExtensions, udp, payload),
        ErrorCode::Ok);

    EXPECT_EQ(udp.sport, 3000);
    EXPECT_EQ(udp.dport, 8000);
    EXPECT_EQ(udp.len, 16);
    EXPECT_EQ(udp.chksum, 0xbfb7u);

    auto expected = truncate(packets.at(0), -8);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(PacketSocketFixture, PrepareSendUDPConnected)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(IsdAsn{}, src.host(), 3000); // will get ISD-ASN from path
    Endpoint<IPEndpoint> remote(dst, 8000);
    HeaderCache hdr;
    RawPath rp(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes);
    hdr::UDP udp;

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    packager.setTrafficClass(64);
    EXPECT_EQ(packager.trafficClass(), 64);

    ASSERT_EQ(
        packager.pack(hdr, nullptr, rp, ext::NoExtensions, udp, payload),
        ErrorCode::InvalidArgument);

    packager.setRemoteEp(Endpoint<IPEndpoint>(IsdAsn{}, dst.host(), 8000));

    ASSERT_EQ(
        packager.pack(hdr, nullptr, rp, ext::NoExtensions, udp, payload),
        ErrorCode::InvalidArgument);

    packager.setRemoteEp(remote);
    EXPECT_EQ(packager.remoteEp(), remote);

    ASSERT_EQ(
        packager.pack(hdr, nullptr, rp, ext::NoExtensions, udp, payload),
        ErrorCode::Ok);

    EXPECT_EQ(udp.sport, 3000);
    EXPECT_EQ(udp.dport, 8000);
    EXPECT_EQ(udp.len, 16);
    EXPECT_EQ(udp.chksum, 0xbfb7u);

    auto expected = truncate(packets.at(0), -8);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(PacketSocketFixture, PrepareSendUDPUpdate)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(src, 3000);
    Endpoint<IPEndpoint> remote(dst, 8000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    packager.setTrafficClass(64);
    EXPECT_EQ(packager.trafficClass(), 64);

    HeaderCache hdr;
    RawPath rp(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes);
    hdr::UDP udp;
    ASSERT_EQ(
        packager.pack(hdr, &remote, rp, ext::NoExtensions, udp, payload),
        ErrorCode::Ok);

    static std::array<std::byte, 16> newPayload = {
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b,
        0x07_b, 0x06_b, 0x05_b, 0x04_b, 0x03_b, 0x02_b, 0x01_b, 0x00_b,
    };
    ASSERT_EQ(
        packager.pack(hdr, udp, newPayload),
        ErrorCode::Ok);

    EXPECT_EQ(udp.sport, 3000);
    EXPECT_EQ(udp.dport, 8000);
    EXPECT_EQ(udp.len, 24);
    EXPECT_EQ(udp.chksum, 0xbfafu);

    auto expected = truncate(packets.at(1), -16);
    EXPECT_TRUE(std::ranges::equal(hdr.get(), expected)) << printBufferDiff(hdr.get(), expected);
}

TEST_F(PacketSocketFixture, ReceiveUDP)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(dst, 8000);
    Endpoint<IPEndpoint> remote(src, 3000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    auto ulSource = remote.host();
    ScionPackager::Endpoint from;
    RawPath path;
    auto recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, &from, &path);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    EXPECT_EQ(from, remote);
    EXPECT_EQ(path, RawPath(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes));
    EXPECT_TRUE(std::ranges::equal(get(recv), payload)) << printBufferDiff(get(recv), payload);
}

TEST_F(PacketSocketFixture, ReceiveUDPConnected)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(dst, 8000);
    Endpoint<IPEndpoint> remote(src, 3000);
    auto ulSource = remote.host();

    // Receive from anyone at any address
    auto recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    // Receive at specific local address
    packager.setLocalEp(local);
    recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    packager.setLocalEp(remote);
    recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
    ASSERT_TRUE(isError(recv));
    EXPECT_EQ(getError(recv), ErrorCode::DstAddrMismatch);

    // Receive from connected host
    packager.setLocalEp(local);
    packager.setRemoteEp(remote);
    recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    packager.setRemoteEp(local);
    recv = packager.unpack<hdr::UDP>(
        packets.at(0), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
    ASSERT_TRUE(isError(recv));
    EXPECT_EQ(getError(recv), ErrorCode::SrcAddrMismatch);
}

// Test receiveing a packet from a host in the same AS
TEST_F(PacketSocketFixture, ReceiveUDPLocal)
{
    using namespace scion;
    using namespace scion::generic;

    auto buf = loadPackets("socket/data/local_packet.bin").at(0);

    ScionPackager packager;
    auto local = unwrap(Endpoint<IPEndpoint>::Parse("[1-ff00:0:1,fd00::1]:8000"));
    auto remote = unwrap(Endpoint<IPEndpoint>::Parse("[1-ff00:0:1,10.0.0.1]:3000"));

    packager.setLocalEp(local);
    ScionPackager::Endpoint from;
    RawPath path;

    auto ulSource = local.host();
    auto recv = packager.unpack<hdr::UDP>(
        buf, ulSource, ext::NoExtensions, ext::NoExtensions, &from, &path);
    ASSERT_TRUE(isError(recv));
    EXPECT_EQ(getError(recv), ErrorCode::InvalidPacket);

    ulSource = remote.host();
    recv = packager.unpack<hdr::UDP>(
        buf, ulSource, ext::NoExtensions, ext::NoExtensions, &from, &path);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    EXPECT_EQ(from, remote);
    EXPECT_EQ(path.type(), hdr::PathType::Empty);
    EXPECT_TRUE(std::ranges::equal(get(recv), payload)) << printBufferDiff(get(recv), payload);
}

#ifndef SCION_DISABLE_CHECKSUM
TEST_F(PacketSocketFixture, ReceiveUDPChksumError)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(dst, 8000);
    Endpoint<IPEndpoint> remote(src, 3000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    auto ulSource = remote.host();
    auto recv = packager.unpack<hdr::UDP>(
        packets.at(5), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr);
        ASSERT_TRUE(isError(recv));
        EXPECT_EQ(getError(recv), ErrorCode::ChecksumError);
}
#endif

TEST_F(PacketSocketFixture, ReceiveSCMP)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(dst, 8000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    auto ulSource = src.host();
    auto scmp = [&] (const Address<IPAddress>& from, const RawPath& path,
        const hdr::ScmpMessage& msg, std::span<const std::byte> data)
    {
        EXPECT_EQ(from, src);
        EXPECT_EQ(path, RawPath(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes));
        ASSERT_TRUE(std::holds_alternative<hdr::ScmpEchoRequest>(msg));
        EXPECT_EQ(std::get<hdr::ScmpEchoRequest>(msg), (hdr::ScmpEchoRequest{1, 100}));
        EXPECT_TRUE(std::ranges::equal(data, payload)) << printBufferDiff(data, payload);
    };

    auto recv = packager.unpack<hdr::UDP>(
        packets.at(2), ulSource, ext::NoExtensions, ext::NoExtensions, nullptr, nullptr, scmp);
    ASSERT_TRUE(isError(recv));
    EXPECT_EQ(getError(recv), ErrorCode::ScmpReceived);
}

TEST_F(PacketSocketFixture, ReceiveIdInt)
{
    using namespace scion;
    using namespace scion::generic;

    ScionPackager packager;
    Endpoint<IPEndpoint> local(dst, 8000);
    Endpoint<IPEndpoint> remote(src, 3000);

    packager.setLocalEp(local);
    EXPECT_EQ(packager.localEp(), local);

    auto ulSource = remote.host();
    ext::IdInt idint;
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    ScionPackager::Endpoint from;
    RawPath path;

    auto recv = packager.unpack<hdr::UDP>(
        packets.at(4), ulSource, hbhExt, ext::NoExtensions, &from, &path);
    ASSERT_FALSE(isError(recv)) << getError(recv);

    EXPECT_EQ(from, remote);
    EXPECT_EQ(path, RawPath(src.isdAsn(), dst.isdAsn(), hdr::PathType::SCION, pathBytes));
    EXPECT_TRUE(std::ranges::equal(get(recv), payload)) << printBufferDiff(get(recv), payload);

    ASSERT_TRUE(idint.isValid());
    checkIdInt(idint);
}
