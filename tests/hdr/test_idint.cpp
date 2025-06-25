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

#include "scion/addr/address.hpp"
#include "scion/bit_stream.hpp"
#include "scion/hdr/idint.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/hdr/udp.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <cstring>


TEST(IdInt, Parse)
{
    using namespace scion::hdr;

    auto pkt = loadPackets("hdr/data/idint.bin");
    scion::ReadStream stream(pkt.at(0));
    scion::StreamError err;
    HopByHopOpts hbh;
    IdIntOpt intOpt;
    std::array<IdIntEntry, 3> entry;
    SciOpt padding;
    UDP udp;

    // Hop-by-Hop Extension Header
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;
    EXPECT_EQ(hbh.nh, ScionProto::UDP);
    EXPECT_EQ(hbh.extLen, 21);

    // ID-INT Main Option
    ASSERT_TRUE(intOpt.serialize(stream, err)) << err;
    EXPECT_EQ(intOpt.type, OptType::IdInt);
    EXPECT_EQ(intOpt.dataLen, 22);
    EXPECT_EQ(intOpt.size(), 22);
    EXPECT_EQ(intOpt.version, 0);
    EXPECT_EQ(intOpt.flags, IdIntOpt::Flags::Discard);
    EXPECT_EQ(intOpt.agrMode, IdIntOpt::AgrMode::AS);
    EXPECT_EQ(intOpt.vtype, IdIntOpt::Verifier::Source);
    EXPECT_EQ(intOpt.stackLen, 16);
    EXPECT_EQ(intOpt.tos, 8);
    EXPECT_EQ(intOpt.delayHops, 0);
    EXPECT_EQ(intOpt.bitmap, IdIntInstFlags::NodeID);
    EXPECT_EQ(intOpt.agrFunc[0], IdIntOpt::AgrFunction::Last);
    EXPECT_EQ(intOpt.agrFunc[1], IdIntOpt::AgrFunction::Last);
    EXPECT_EQ(intOpt.agrFunc[2], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.agrFunc[3], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.instr[0], IdIntInstruction::IngressTstamp);
    EXPECT_EQ(intOpt.instr[1], IdIntInstruction::DeviceTypeRole);
    EXPECT_EQ(intOpt.instr[2], IdIntInstruction::Nop);
    EXPECT_EQ(intOpt.instr[3], IdIntInstruction::Nop);
    EXPECT_EQ(intOpt.sourceTS, 1000);
    EXPECT_EQ(intOpt.sourcePort, 10);

    // ID-INT Source Entry
    ASSERT_TRUE(entry[0].serialize(stream, err)) << err;
    EXPECT_EQ(entry[0].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[0].dataLen, 12);
    EXPECT_EQ(entry[0].size(), 12);
    EXPECT_EQ(entry[0].mdSize(), 2);
    EXPECT_EQ(entry[0].flags, IdIntEntry::Flags::Source | IdIntEntry::Flags::Egress);
    EXPECT_EQ(entry[0].hop, 0);
    EXPECT_EQ(entry[0].mask, IdIntInstBitmap{});
    EXPECT_THAT(entry[0].ml, testing::ElementsAre(0, 0, 0, 0));
    EXPECT_THAT(entry[0].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // ID-INT Entry
    ASSERT_TRUE(entry[1].serialize(stream, err)) << err;
    EXPECT_EQ(entry[1].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[1].dataLen, 20);
    EXPECT_EQ(entry[1].size(), 20);
    EXPECT_EQ(entry[1].mdSize(), 10);
    EXPECT_EQ(entry[1].flags, IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Egress);
    EXPECT_EQ(entry[1].hop, 1);
    EXPECT_EQ(entry[1].mask, IdIntInstFlags::NodeID);
    EXPECT_THAT(entry[1].ml, testing::ElementsAre(2, 1, 0, 0));
    EXPECT_THAT(entry[1].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // ID-INT Entry
    ASSERT_TRUE(entry[2].serialize(stream, err)) << err;
    EXPECT_EQ(entry[2].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[2].dataLen, 20);
    EXPECT_EQ(entry[2].size(), 20);
    EXPECT_EQ(entry[2].mdSize(), 10);
    EXPECT_EQ(entry[2].flags, IdIntEntry::Flags::Ingress);
    EXPECT_EQ(entry[2].hop, 2);
    EXPECT_EQ(entry[2].mask, IdIntInstFlags::NodeID);
    EXPECT_THAT(entry[2].ml, testing::ElementsAre(2, 1, 0, 0));
    EXPECT_THAT(entry[2].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // Telemetry Stack Padding
    ASSERT_TRUE(padding.serialize(stream, err)) << err;
    EXPECT_EQ(padding.type, OptType::PadN);
    EXPECT_EQ(padding.dataLen, 10);

    // UDP
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    EXPECT_EQ(stream.getPos(), std::make_pair((size_t)pkt.at(0).size(), (size_t)0));
}

TEST(IdInt, Emit)
{
    using namespace scion;
    using namespace scion::hdr;

    auto expected = loadPackets("hdr/data/idint.bin").at(0);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;
    HopByHopOpts hbh;
    IdIntOpt intOpt;
    std::array<IdIntEntry, 3> entry;
    SciOpt padding;
    UDP udp;

    // Hop-by-Hop Extension Header
    hbh.nh = ScionProto::UDP;
    hbh.extLen = 21;
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;

    // ID-INT Main Option
    intOpt.dataLen = 22;
    intOpt.flags = IdIntOpt::Flags::Discard;
    intOpt.agrMode = IdIntOpt::AgrMode::AS;
    intOpt.vtype = IdIntOpt::Verifier::Source;
    intOpt.stackLen = 16;
    intOpt.tos = 8;
    intOpt.delayHops = 0;
    intOpt.bitmap = IdIntInstFlags::NodeID;
    intOpt.agrFunc[0] = IdIntOpt::AgrFunction::Last;
    intOpt.agrFunc[1] = IdIntOpt::AgrFunction::Last;
    intOpt.agrFunc[2] = IdIntOpt::AgrFunction::First;
    intOpt.agrFunc[3] = IdIntOpt::AgrFunction::First;
    intOpt.instr[0] = IdIntInstruction::IngressTstamp;
    intOpt.instr[1] = IdIntInstruction::DeviceTypeRole;
    intOpt.instr[2] = IdIntInstruction::Nop;
    intOpt.instr[3] = IdIntInstruction::Nop;
    intOpt.sourceTS = 1000;
    intOpt.sourcePort = 10;
    intOpt.verifier = ScIPAddress(IsdAsn{}, generic::IPAddress::UnspecifiedIPv4());
    EXPECT_EQ(intOpt.size(), 22);
    ASSERT_TRUE(intOpt.serialize(stream, err)) << err;

    // ID-INT Source Entry
    entry[0].dataLen = 12;
    entry[0].flags = IdIntEntry::Flags::Source | IdIntEntry::Flags::Egress;
    entry[0].hop = 0;
    entry[0].mask = IdIntInstBitmap{};
    entry[0].ml = {0, 0, 0, 0};
    entry[0].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    EXPECT_EQ(entry[0].size(), 12);
    EXPECT_EQ(entry[0].mdSize(), 2);
    ASSERT_TRUE(entry[0].serialize(stream, err)) << err;

    // ID-INT Entry
    static const std::array<std::byte, 10> entry1 = {
        0x00_b, 0x00_b, 0x00_b, 0x02_b,
        0x00_b, 0x00_b, 0x00_b, 0x03_b,
        0x00_b, 0x04_b,
    };
    entry[1].dataLen = 20;
    entry[1].flags = IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Egress;
    entry[1].hop = 1;
    entry[1].mask = IdIntInstFlags::NodeID;
    entry[1].ml = {2, 1, 0, 0};
    std::copy(entry1.begin(), entry1.end(), entry[1].metadata.begin());
    entry[1].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    EXPECT_EQ(entry[1].size(), 20);
    EXPECT_EQ(entry[1].mdSize(), 10);
    ASSERT_TRUE(entry[1].serialize(stream, err)) << err;

    // ID-INT Entry
    static const std::array<std::byte, 10> entry2 = {
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
        0x00_b, 0x02_b,
    };
    entry[2].dataLen = 20;
    entry[2].flags = IdIntEntry::Flags::Ingress;
    entry[2].hop = 2;
    entry[2].mask = IdIntInstFlags::NodeID;
    entry[2].ml = {2, 1, 0, 0};
    std::copy(entry2.begin(), entry2.end(), entry[2].metadata.begin());
    entry[2].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    ASSERT_TRUE(entry[2].serialize(stream, err)) << err;

    // Telemetry Stack Padding
    padding.type = OptType::PadN;
    padding.dataLen = 10;
    ASSERT_TRUE(padding.serialize(stream, err)) << err;

    // UDP
    udp.sport = 53;
    udp.dport = 53;
    udp.len = 8;
    ASSERT_TRUE(udp.serialize(stream, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(IdInt, ParseEncrypted)
{
    using namespace scion;
    using namespace scion::hdr;

    auto pkt = loadPackets("hdr/data/idint.bin");
    scion::ReadStream stream(pkt.at(1));
    scion::StreamError err;
    HopByHopOpts hbh;
    IdIntOpt intOpt;
    std::array<IdIntEntry, 3> entry;
    SciOpt padding;
    UDP udp;

    // Hop-by-Hop Extension Header
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;
    EXPECT_EQ(hbh.nh, ScionProto::UDP);
    EXPECT_EQ(hbh.extLen, 43);

    // ID-INT Main Option
    ASSERT_TRUE(intOpt.serialize(stream, err)) << err;
    EXPECT_EQ(intOpt.type, OptType::IdInt);
    EXPECT_EQ(intOpt.dataLen, 46);
    EXPECT_EQ(intOpt.size(), 46);
    EXPECT_EQ(intOpt.version, 0);
    EXPECT_EQ(intOpt.flags, IdIntOpt::Flags::Encrypted);
    EXPECT_EQ(intOpt.agrMode, IdIntOpt::AgrMode::Off);
    EXPECT_EQ(intOpt.vtype, IdIntOpt::Verifier::ThirdParty);
    EXPECT_EQ(intOpt.stackLen, 32);
    EXPECT_EQ(intOpt.tos, 14);
    EXPECT_EQ(intOpt.delayHops, 0);
    EXPECT_EQ(intOpt.bitmap, IdIntInstFlags::NodeID);
    EXPECT_EQ(intOpt.agrFunc[0], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.agrFunc[1], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.agrFunc[2], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.agrFunc[3], IdIntOpt::AgrFunction::First);
    EXPECT_EQ(intOpt.instr[0], IdIntInstruction::IngressTstamp);
    EXPECT_EQ(intOpt.instr[1], IdIntInstruction::DeviceTypeRole);
    EXPECT_EQ(intOpt.instr[2], IdIntInstruction::Nop);
    EXPECT_EQ(intOpt.instr[3], IdIntInstruction::Nop);
    EXPECT_EQ(intOpt.sourceTS, 1000);
    EXPECT_EQ(intOpt.sourcePort, 10);
    EXPECT_EQ(intOpt.verifier, unwrap(ScIPAddress::Parse("1-ff00:0:1,fd00::1")));

    // ID-INT Source Entry
    ASSERT_TRUE(entry[0].serialize(stream, err)) << err;
    EXPECT_EQ(entry[0].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[0].dataLen, 24);
    EXPECT_EQ(entry[0].size(), 24);
    EXPECT_EQ(entry[0].mdSize(), 2);
    EXPECT_EQ(entry[0].flags,
        IdIntEntry::Flags::Source | IdIntEntry::Flags::Egress | IdIntEntry::Flags::Encrypted);
    EXPECT_EQ(entry[0].hop, 0);
    EXPECT_EQ(entry[0].mask, IdIntInstBitmap{});
    EXPECT_THAT(entry[0].ml, testing::ElementsAre(0, 0, 0, 0));
    static const std::array<std::byte, 12> nonce1 = {
        0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b,
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
    };
    EXPECT_EQ(entry[0].nonce, nonce1);
    EXPECT_THAT(entry[0].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // ID-INT Entry
    ASSERT_TRUE(entry[1].serialize(stream, err)) << err;
    EXPECT_EQ(entry[1].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[1].dataLen, 32);
    EXPECT_EQ(entry[1].size(), 32);
    EXPECT_EQ(entry[1].mdSize(), 10);
    EXPECT_EQ(entry[1].flags,
        IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Egress | IdIntEntry::Flags::Encrypted);
    EXPECT_EQ(entry[1].hop, 1);
    EXPECT_EQ(entry[1].mask, IdIntInstFlags::NodeID);
    EXPECT_THAT(entry[1].ml, testing::ElementsAre(2, 1, 0, 0));
    static const std::array<std::byte, 12> nonce2 = {
        0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b,
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
    };
    EXPECT_EQ(entry[0].nonce, nonce2);
    EXPECT_THAT(entry[1].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // ID-INT Entry
    ASSERT_TRUE(entry[2].serialize(stream, err)) << err;
    EXPECT_EQ(entry[2].type, OptType::IdIntEntry);
    EXPECT_EQ(entry[2].dataLen, 32);
    EXPECT_EQ(entry[2].size(), 32);
    EXPECT_EQ(entry[2].mdSize(), 10);
    EXPECT_EQ(entry[2].flags, IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Encrypted);
    EXPECT_EQ(entry[2].hop, 2);
    EXPECT_EQ(entry[2].mask, IdIntInstFlags::NodeID);
    EXPECT_THAT(entry[2].ml, testing::ElementsAre(2, 1, 0, 0));
    static const std::array<std::byte, 12> nonce3 = {
        0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b, 0x00_b,
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
    };
    EXPECT_EQ(entry[0].nonce, nonce3);
    EXPECT_THAT(entry[2].mac, testing::ElementsAre(0xff_b, 0xff_b, 0xff_b, 0xff_b));

    // Telemetry Stack Padding
    ASSERT_TRUE(padding.serialize(stream, err)) << err;
    EXPECT_EQ(padding.type, OptType::PadN);
    EXPECT_EQ(padding.dataLen, 38);

    // UDP
    ASSERT_TRUE(udp.serialize(stream, err)) << err;
    EXPECT_EQ(stream.getPos(), std::make_pair((size_t)pkt.at(1).size(), (size_t)0));
}

TEST(IdInt, EmitEncrypted)
{
    using namespace scion;
    using namespace scion::hdr;

    auto expected = loadPackets("hdr/data/idint.bin").at(1);
    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;
    HopByHopOpts hbh;
    IdIntOpt intOpt;
    std::array<IdIntEntry, 3> entry;
    SciOpt padding;
    UDP udp;

    // Hop-by-Hop Extension Header
    hbh.nh = ScionProto::UDP;
    hbh.extLen = 43;
    ASSERT_TRUE(hbh.serialize(stream, err)) << err;

    // ID-INT Main Option
    intOpt.dataLen = 46;
    intOpt.flags = IdIntOpt::Flags::Encrypted;
    intOpt.agrMode = IdIntOpt::AgrMode::Off;
    intOpt.vtype = IdIntOpt::Verifier::ThirdParty;
    intOpt.stackLen = 32;
    intOpt.tos = 14;
    intOpt.delayHops = 0;
    intOpt.bitmap = IdIntInstFlags::NodeID;
    intOpt.instr[0] = IdIntInstruction::IngressTstamp;
    intOpt.instr[1] = IdIntInstruction::DeviceTypeRole;
    intOpt.instr[2] = IdIntInstruction::Nop;
    intOpt.instr[3] = IdIntInstruction::Nop;
    intOpt.sourceTS = 1000;
    intOpt.sourcePort = 10;
    intOpt.verifier = unwrap(ScIPAddress::Parse("1-ff00:0:1,fd00::1"));
    EXPECT_EQ(intOpt.size(), 46);
    ASSERT_TRUE(intOpt.serialize(stream, err)) << err;

    // ID-INT Source Entry
    entry[0].dataLen = 24;
    entry[0].flags = IdIntEntry::Flags::Source | IdIntEntry::Flags::Egress
        | IdIntEntry::Flags::Encrypted;
    entry[0].hop = 0;
    entry[0].mask = IdIntInstBitmap{};
    entry[0].ml = {0, 0, 0, 0};
    entry[0].nonce[11] = 1_b;
    entry[0].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    EXPECT_EQ(entry[0].size(), 24);
    EXPECT_EQ(entry[0].mdSize(), 2);
    ASSERT_TRUE(entry[0].serialize(stream, err)) << err;

    // ID-INT Entry
    static const std::array<std::byte, 10> entry1 = {
        0x00_b, 0x00_b, 0x00_b, 0x02_b,
        0x00_b, 0x00_b, 0x00_b, 0x03_b,
        0x00_b, 0x04_b,
    };
    entry[1].dataLen = 32;
    entry[1].flags = IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Egress
        | IdIntEntry::Flags::Encrypted;
    entry[1].hop = 1;
    entry[1].mask = IdIntInstFlags::NodeID;
    entry[1].ml = {2, 1, 0, 0};
    std::copy(entry1.begin(), entry1.end(), entry[1].metadata.begin());
    entry[1].nonce[11] = 2_b;
    entry[1].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    EXPECT_EQ(entry[1].size(), 32);
    EXPECT_EQ(entry[1].mdSize(), 10);
    ASSERT_TRUE(entry[1].serialize(stream, err)) << err;

    // ID-INT Entry
    static const std::array<std::byte, 10> entry2 = {
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
        0x00_b, 0x00_b, 0x00_b, 0x01_b,
        0x00_b, 0x02_b,
    };
    entry[2].dataLen = 32;
    entry[2].flags = IdIntEntry::Flags::Ingress | IdIntEntry::Flags::Encrypted;
    entry[2].hop = 2;
    entry[2].mask = IdIntInstFlags::NodeID;
    entry[2].ml = {2, 1, 0, 0};
    std::copy(entry2.begin(), entry2.end(), entry[2].metadata.begin());
    entry[2].nonce[11] = 3_b;
    entry[2].mac = {0xff_b, 0xff_b, 0xff_b, 0xff_b};
    EXPECT_EQ(entry[2].size(), 32);
    EXPECT_EQ(entry[2].mdSize(), 10);
    ASSERT_TRUE(entry[2].serialize(stream, err)) << err;

    // Telemetry Stack Padding
    padding.type = OptType::PadN;
    padding.dataLen = 38;
    ASSERT_TRUE(padding.serialize(stream, err)) << err;

    // UDP
    udp.sport = 53;
    udp.dport = 53;
    udp.len = 8;
    ASSERT_TRUE(udp.serialize(stream, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST(IdInt, Print)
{
    using namespace scion::hdr;
    static const char* expected =
        "###[ ID-INT Option ]###\n"
        " type       = 253\n"
        " dataLen    = 0\n"
        " flags      = 0x0\n"
        " agrMode    = 0\n"
        " vtype      = 1\n"
        " stackLen   = 0\n"
        " tos        = 0\n"
        " delayHops  = 0\n"
        " agrFunc1   = 0\n"
        " instr1     = 0x0\n"
        " agrFunc2   = 0\n"
        " instr2     = 0x0\n"
        " agrFunc3   = 0\n"
        " instr3     = 0x0\n"
        " agrFunc4   = 0\n"
        " instr4     = 0x0\n"
        " sourceTS   = 0\n"
        " sourcePort = 0\n"
        " verifier   = 0-0,::\n"
        "###[ ID-INT Entry ]###\n"
        "  type     = 254\n"
        "  dataLen  = 0\n"
        "  flags    = 0x0\n"
        "  hop      = 0\n"
        "  mask     = 0x0\n"
        "  ml1      = 0\n"
        "  ml2      = 0\n"
        "  ml3      = 0\n"
        "  ml4      = 0\n"
        "  metadata = 00:00\n"
        "  mac      = 00:00:00:00\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = IdIntOpt{}.print(out, 1);
    out = IdIntEntry{}.print(out, 2);
    EXPECT_EQ(str, expected);
}
