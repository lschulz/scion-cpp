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
#include "scion/hdr/scion.hpp"
#include "scion/hdr/udp.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <cstring>
#include <vector>

using std::uint16_t;
using std::uint32_t;
using std::size_t;


TEST(ScionHdr, Parse)
{
    using namespace scion::hdr;
    using scion::Address;
    using scion::generic::IPAddress;
    using MAC = std::array<std::byte, 6>;

    auto pkt = loadPackets("hdr/data/scion.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    SCION scion;
    PathMeta meta;
    std::vector<InfoField> info;
    std::vector<HopField> hfs;
    UDP udp;

    // SCION Common
    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    EXPECT_EQ(scion.qos, 32);
    EXPECT_EQ(scion.hlen, 32);
    EXPECT_EQ(scion.nh, ScionProto::UDP);
    EXPECT_EQ(scion.ptype, PathType::SCION);
    EXPECT_EQ(scion.plen, 12);
    EXPECT_EQ(scion.fl, 0xf'ffffu);
    EXPECT_EQ(scion.dst, unwrap(Address<IPAddress>::Parse("1-ff00:0:1,10.0.0.1")));
    EXPECT_EQ(scion.src, unwrap(Address<IPAddress>::Parse("2-ff00:0:2,fd00::2")));

    // Path Meta
    ASSERT_TRUE(meta.serialize(stream, err)) << err;
    EXPECT_EQ(meta.currInf, 1);
    EXPECT_EQ(meta.currHf, 4);
    ASSERT_EQ(meta.segLen[0], 3);
    ASSERT_EQ(meta.segLen[1], 2);
    ASSERT_EQ(meta.segLen[2], 0);

    // Info Fields
    static const std::array<uint16_t, 2> segid = { 0x7200, 0x6991 };
    info.resize(meta.segmentCount());
    for (size_t i = 0; i < info.size(); ++i) {
        auto& seg = info[i];
        ASSERT_TRUE(seg.serialize(stream, err)) << err;
        EXPECT_EQ(seg.segid, segid.at(i));
        EXPECT_EQ(seg.timestamp, 0x67e29ac0u);
    }

    // HopFields
    static const std::array<uint16_t, 5> time = { 0, 0, 0, 255, 255 };
    static const std::array<uint16_t, 5> igr = { 0, 2, 4, 0, 6 };
    static const std::array<uint16_t, 5> egr = { 1, 3, 0, 5, 0 };
    static const std::array<MAC, 5> macs = {
        MAC{0x14_b, 0x8d_b, 0xe1_b, 0x52_b, 0x17_b, 0x01_b},
        MAC{0xc8_b, 0x5e_b, 0x6c_b, 0xf0_b, 0x4d_b, 0xf6_b},
        MAC{0x27_b, 0x0d_b, 0xe0_b, 0x16_b, 0x13_b, 0x9a_b},
        MAC{0x2e_b, 0x4c_b, 0x17_b, 0x01_b, 0x14_b, 0x5d_b},
        MAC{0x71_b, 0x64_b, 0x12_b, 0xe4_b, 0x80_b, 0x55_b},
    };
    hfs.resize(meta.hopFieldCount());
    for (size_t i = 0; i < hfs.size(); ++i) {
        auto& hf = hfs[i];
        ASSERT_TRUE(hf.serialize(stream, err)) << err;
        EXPECT_EQ(hf.expTime, time.at(i));
        EXPECT_EQ(hf.relativeExpiry(), ((1 + time.at(i)) *24*60*60) / 256);
        EXPECT_EQ(hf.consIngress, igr.at(i));
        EXPECT_EQ(hf.consEgress, egr.at(i));
        EXPECT_EQ(hf.mac, macs.at(i));
    }

    // UDP
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    EXPECT_EQ(udp.sport, 43000);
    EXPECT_EQ(udp.dport, 1200);
    EXPECT_EQ(udp.len, 12);
    EXPECT_EQ(udp.chksum, 0x48e9u);

    // Payload
    uint32_t payload = 0;
    ASSERT_TRUE(stream.serializeUint32(payload, err)) << err;
    EXPECT_EQ(payload, 1337);
}

TEST(ScionHdr, ParseFaulty)
{
    using namespace scion::hdr;
    using scion::generic::IPAddress;

    auto pkts = loadPackets("hdr/data/scion_faulty.bin");
    for (const auto& pkt : pkts) {
        scion::ReadStream stream(pkt);
        scion::StreamError err;
        SCION scion;
        PathMeta meta;
        ASSERT_FALSE(scion.serialize(stream, err) && meta.serialize(stream, err))
            << printHeader(scion) << printHeader(meta, 2);
    }
}

TEST(ScionHdr, Emit)
{
    using namespace scion::hdr;
    using scion::Address;
    using scion::generic::IPAddress;
    using MAC = std::array<std::byte, 6>;

    auto expected = loadPackets("hdr/data/scion.bin").at(0);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;

    // SCION Common
    SCION scion;
    scion.qos = 32;
    scion.hlen = 32;
    scion.nh = ScionProto::UDP;
    scion.ptype = PathType::SCION;
    scion.plen = 12;
    scion.fl = 0xf'ffffu;
    scion.dst = unwrap(Address<IPAddress>::Parse("1-ff00:0:1,10.0.0.1"));
    scion.src = unwrap(Address<IPAddress>::Parse("2-ff00:0:2,fd00::2"));

    // Path Meta
    PathMeta meta;
    meta.currInf = 1;
    meta.currHf = 4;
    meta.segLen = {3, 2, 0};

    // Info Fields
    static const std::array<InfoField, 2> info = {
        InfoField{InfoField::Flags{}, 0x7200, 0x67e29ac0u},
        InfoField{InfoField::Flags::ConsDir, 0x6991, 0x67e29ac0u},
    };

    // HopFields
    static const std::array<HopField, 5> hfs = {
        HopField{HopField::Flags{}, 0, 0, 1,
            MAC{0x14_b, 0x8d_b, 0xe1_b, 0x52_b, 0x17_b, 0x01_b}},
        HopField{HopField::Flags{}, 0, 2, 3,
            MAC{0xc8_b, 0x5e_b, 0x6c_b, 0xf0_b, 0x4d_b, 0xf6_b}},
        HopField{HopField::Flags{}, 0, 4, 0,
            MAC{0x27_b, 0x0d_b, 0xe0_b, 0x16_b, 0x13_b, 0x9a_b}},
        HopField{HopField::Flags{}, 255, 0, 5,
            MAC{0x2e_b, 0x4c_b, 0x17_b, 0x01_b, 0x14_b, 0x5d_b}},
        HopField{HopField::Flags{}, 255, 6, 0,
            MAC{0x71_b, 0x64_b, 0x12_b, 0xe4_b, 0x80_b, 0x55_b}},
    };

    // UDP
    UDP udp;
    udp.sport = 43000;
    udp.dport = 1200;
    udp.len = 12;
    udp.chksum = 0;

    // Payload
    std::array<std::byte, 4> payload = { 0_b, 0_b, 5_b, 57_b };

    udp.chksum = details::internetChecksum(
        payload, scion.checksum(udp.len, scion.nh) + udp.checksum());

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(meta.serialize(stream, err)) << err;
    for (const auto& inf : info) {
        ASSERT_TRUE(const_cast<InfoField&>(inf).serialize(stream, err)) << err;
    }
    for (const auto& hf : hfs) {
        ASSERT_TRUE(const_cast<HopField&>(hf).serialize(stream, err)) << err;
    }
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    ASSERT_TRUE(stream.serializeBytes(payload, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(ScionHdr, Print)
{
    using namespace scion::hdr;
    static const char* expected =
        "###[ SCION ]###\n"
        "qos   = 0\n"
        "fl    = 0\n"
        "nh    = 17\n"
        "hlen  = 9\n"
        "plen  = 0\n"
        "ptype = 0\n"
        "src   = 0-0,::\n"
        "dst   = 0-0,::\n"
        "###[ SCION Path ]###\n"
        "  currInf = 0\n"
        "  currHf  = 0\n"
        "  seg0Len = 0\n"
        "  seg1Len = 0\n"
        "  seg2Len = 0\n"
        "###[ Info Field ]###\n"
        "  flags     = 0x0\n"
        "  segid     = 0\n"
        "  timestamp = 0\n"
        "###[ Hop Field ]###\n"
        "  flags       = 0x0\n"
        "  expTime     = 0\n"
        "  consIngress = 0\n"
        "  consEgress  = 0\n"
        "  mac         = 00:00:00:00:00:00\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = SCION().print(out, 0);
    out = PathMeta().print(out, 2);
    out = InfoField().print(out, 2);
    out = HopField().print(out, 2);
    EXPECT_EQ(str, expected);
}

TEST(ScionOptions, Parse)
{
    using namespace scion::hdr;
    using scion::Address;
    using scion::generic::IPAddress;

    auto pkt = loadPackets("hdr/data/scion_opts.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    HopByHopOpts hbh;
    SciOpt opt;
    AuthenticatorOpt spao;

    // Hop-by-Hop options
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;
    EXPECT_EQ(hbh.nh, ScionProto::E2EOpt);
    EXPECT_EQ(hbh.extLen, 1);

    ASSERT_TRUE(opt.serialize(stream, err)) << err;
    EXPECT_EQ(opt.type, OptType::Pad1);
    EXPECT_EQ(opt.dataLen, 0);

    ASSERT_TRUE(opt.serialize(stream, err)) << err;
    EXPECT_EQ(opt.type, OptType::Pad1);
    EXPECT_EQ(opt.dataLen, 0);

    ASSERT_TRUE(opt.serialize(stream, err)) << err;
    EXPECT_EQ(opt.type, OptType::PadN);
    EXPECT_EQ(opt.dataLen, 2);

    // End-to-End Options
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;
    EXPECT_EQ(hbh.nh, ScionProto::UDP);
    EXPECT_EQ(hbh.extLen, 7);

    ASSERT_TRUE(spao.serialize(stream, err)) << err;
    EXPECT_EQ(spao.type, OptType::SPAO);
    EXPECT_EQ(spao.dataLen, 28);
    EXPECT_EQ(spao.algorithm, 0);
    EXPECT_EQ(spao.spi, 0xffffu);
    EXPECT_EQ(spao.timestamp, 1);
    EXPECT_EQ(spao.getAuthSize(), 16);
    static const std::array<std::byte, 16> auth = {
        0x00_b, 0x01_b, 0x02_b, 0x03_b, 0x04_b, 0x05_b, 0x06_b, 0x07_b,
        0x08_b, 0x09_b, 0x0a_b, 0x0b_b, 0x0c_b, 0x0d_b, 0x0e_b, 0x0f_b,
    };
    ASSERT_THAT(spao.getAuth(), testing::ElementsAreArray(auth));
}

TEST(ScionOptions, Emit)
{
    using namespace scion::hdr;
    using scion::Address;
    using scion::generic::IPAddress;

    auto expected = loadPackets("hdr/data/scion_opts.bin").at(0);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;
    HopByHopOpts hbh;
    SciOpt opt;
    AuthenticatorOpt spao;
    UDP udp;

    // Hop-by-Hop options
    hbh.nh = ScionProto::E2EOpt;
    hbh.extLen = 1;
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;

    opt.type = OptType::Pad1;
    opt.dataLen = 0;
    ASSERT_TRUE(opt.serialize(stream, err)) << err;

    opt.type = OptType::Pad1;
    opt.dataLen = 0;
    ASSERT_TRUE(opt.serialize(stream, err)) << err;

    opt.type = OptType::PadN;
    opt.dataLen = 2;
    ASSERT_TRUE(opt.serialize(stream, err)) << err;

    // End-to-End Options
    hbh.nh = ScionProto::UDP;
    hbh.extLen = 7;
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;

    spao.algorithm = 0;
    spao.spi = 0xffffu;
    spao.timestamp = 1;
    static const std::array<std::byte, 16> auth = {
        0x00_b, 0x01_b, 0x02_b, 0x03_b, 0x04_b, 0x05_b, 0x06_b, 0x07_b,
        0x08_b, 0x09_b, 0x0a_b, 0x0b_b, 0x0c_b, 0x0d_b, 0x0e_b, 0x0f_b,
    };
    spao.setAuthSize(auth.size());
    EXPECT_EQ(spao.type, OptType::SPAO);
    EXPECT_EQ(spao.dataLen, 28);
    EXPECT_EQ(spao.getAuth().size(), 16);
    std::copy(auth.begin(), auth.end(), spao.getAuth().begin());
    ASSERT_TRUE(spao.serialize(stream, err)) << err;

    // UDP
    udp.sport = 53;
    udp.dport = 53;
    udp.len = 8;
    udp.chksum = 0;
    ASSERT_TRUE(udp.serialize(stream, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(ScionOptions, Print)
{
    using namespace scion::hdr;
    static const char* expected =
        "###[ Hop-by-Hop Options ]###\n"
        "nh     = 201\n"
        "extLen = 1\n"
        "###[ Option ]###\n"
        " type    = 0\n"
        " dataLen = 0\n"
        "###[ Option ]###\n"
        " type    = 0\n"
        " dataLen = 0\n"
        "###[ Option ]###\n"
        " type    = 1\n"
        " dataLen = 2\n"
        "###[ Hop-by-Hop Options ]###\n"
        "nh     = 17\n"
        "extLen = 1\n"
        "###[ SPAO ]###\n"
        " type          = 2\n"
        " dataLen       = 28\n"
        " algorithm     = 0\n"
        " spi           = 0\n"
        " timestamp     = 0x0000000000\n"
        " authenticator = 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = HopByHopOpts{ScionProto::E2EOpt, 1}.print(out, 0);
    out = SciOpt{OptType::Pad1, 0}.print(out, 1);
    out = SciOpt{OptType::Pad1, 0}.print(out, 1);
    out = SciOpt{OptType::PadN, 2}.print(out, 1);
    out = HopByHopOpts{ScionProto::UDP, 1}.print(out, 0);
    AuthenticatorOpt auth;
    auth.setAuthSize(16);
    out = auth.print(out, 1);
    EXPECT_EQ(str, expected);
}
