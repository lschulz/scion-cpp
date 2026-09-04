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

#include "scion/extensions/idint.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <cstdint>
#include <string>
#include <vector>

// This file tests the ID-INT application interface
// Raw headers are tested in tests/hdr/test_idint.cpp.
// Request encoding is also tested by sockets.

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::size_t;

TEST(IdIntApi, Nonce)
{
    using namespace scion::idint;

    auto n1 = randomNonce();
    auto n2 = n1;

    incrementNonce(n2);
    EXPECT_NE(n1, n2);

    n1 = Nonce{
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b,
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b
    };
    incrementNonce(n1);
    EXPECT_EQ(n1, Nonce{});

}

TEST(IdIntApi, MetadataSize)
{
    using namespace scion::idint;
    EXPECT_EQ(MetadataSize(Instr::Nop), 0);
    EXPECT_EQ(MetadataSize(Instr::Isd), 2);
    EXPECT_EQ(MetadataSize(Instr::Uptime), 4);
    EXPECT_EQ(MetadataSize(Instr::Asn), 6);
    EXPECT_EQ(MetadataSize(Instr::NodeIpv6AddrL), 8);
}

TEST(IdIntApi, IntMetadata)
{
    using namespace scion::idint;

    auto md = IntMetadata::MakeSource();
    EXPECT_TRUE(md.isSource());
    EXPECT_FALSE(md.isIngress());
    EXPECT_FALSE(md.isEgress());
    EXPECT_FALSE(md.isAggregate());
    EXPECT_EQ(md.hopIndex(), 0);

    EXPECT_FALSE(md.hasNodeId());
    md.setNodeId(1);
    EXPECT_TRUE(md.hasNodeId());
    EXPECT_EQ(md.nodeId(), 1);
    md.clearNodeId();
    EXPECT_FALSE(md.hasNodeId());

    EXPECT_FALSE(md.hasNodeCount());
    md.setNodeCount(2);
    EXPECT_TRUE(md.hasNodeCount());
    EXPECT_EQ(md.nodeCount(), 2);
    md.clearNodeCount();
    EXPECT_FALSE(md.hasNodeCount());

    EXPECT_FALSE(md.hasIngressPort());
    md.setIngressPort(3);
    EXPECT_TRUE(md.hasIngressPort());
    EXPECT_EQ(md.ingressPort(), 3);
    md.clearIngressPort();
    EXPECT_FALSE(md.hasIngressPort());

    EXPECT_FALSE(md.hasNodeId());
    md.setEgressPort(4);
    EXPECT_TRUE(md.hasEgressPort());
    EXPECT_EQ(md.egressPort(), 4);
    md.clearEgressPort();
    EXPECT_FALSE(md.hasNodeId());

    md.setMetadata(0, Instr::SoftwareVersion, 10u);
    EXPECT_EQ(md.metadataSize(0), 4);
    EXPECT_EQ(md.metadataSize(1), 0);
}

class IdIntApiFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace scion::generic;
        rawRequest = loadPackets("extensions/data/idint_request.bin").at(0);
        rawReports = loadPackets("extensions/data/idint_reports.bin");
    };

    inline static std::vector<std::byte> rawRequest;
    inline static std::vector<std::vector<std::byte>> rawReports;
};

TEST_F(IdIntApiFixture, EncodeRequest)
{
    using namespace scion;
    using namespace scion::idint;
    using scion::drkey::Key;

    IntRequest req;
    req.flags.discard = 1;
    req.agrMode = AM::AS;
    req.vtype = Verifier::Destination;
    req.bitmap = InstrFlag::NodeID;
    req.stackBytes = 384;
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

    IdInt ext;
    ext.encodeIntRequest(req, k, nullptr);

    hdr::HopByHopOpts extHdr;
    const size_t offset = 2;
    extHdr.nh = (hdr::ScionProto)0;
    extHdr.extLen = (std::uint8_t)(ext.size(offset) / 4);

    std::vector<std::byte> buffer(512);
    WriteStream stream(buffer);
    StreamError err;
    ASSERT_TRUE(extHdr.serialize(stream, err)) << err;
    ASSERT_TRUE(ext.write(stream, offset, err)) << err;

    std::span<std::byte> actual;
    ASSERT_TRUE(stream.lookback(actual, WriteStream::npos, err)) << err;
    EXPECT_TRUE(std::ranges::equal(actual, rawRequest)) << printBufferDiff(actual, rawRequest);
}

TEST_F(IdIntApiFixture, RecoverRequest)
{
    using namespace scion;
    using namespace scion::idint;
    using namespace std::chrono_literals;

    hdr::HopByHopOpts extHdr;
    IdInt ext;

    ReadStream stream(rawRequest);
    StreamError err;
    ASSERT_TRUE(extHdr.serialize(stream, err)) << err;
    ASSERT_TRUE(ext.parse(stream, err)) << err;

    IntRequest req;
    auto result = ext.recoverRequest(req);
    ASSERT_FALSE(result) << result;

    EXPECT_EQ(req.flags.discard, 1);
    EXPECT_EQ(req.agrMode, AM::AS);
    EXPECT_EQ(req.vtype, Verifier::Destination);
    EXPECT_EQ(req.skipHops, 0);
    EXPECT_EQ(req.bitmap, InstrFlag::NodeID);
    EXPECT_EQ(req.stackBytes, 384);
    EXPECT_THAT(req.agrFuncs, testing::ElementsAre(AF::Last, AF::Last, AF::First, AF::First));
    EXPECT_THAT(req.instructions, testing::ElementsAre(
        Instr::IngressTstamp, Instr::DeviceTypeRole, Instr::Nop, Instr::Nop));
}

void checkMetadata(const scion::idint::IntReport<>& report)
{
    using namespace scion::idint;

    ASSERT_THAT(report.data.size(), 4);

    // Source
    const auto* md = &report.data[0];
    EXPECT_EQ(md->isSource(), true);
    EXPECT_EQ(md->isIngress(), false);
    EXPECT_EQ(md->isEgress(), false);
    EXPECT_EQ(md->isAggregate(), false);
    EXPECT_EQ(md->hopIndex(), 0);
    EXPECT_EQ(md->hasNodeId(), false);
    EXPECT_EQ(md->hasNodeCount(), false);
    EXPECT_EQ(md->hasIngressPort(), false);
    EXPECT_EQ(md->hasEgressPort(), false);
    EXPECT_EQ(md->nodeId(), 0);
    EXPECT_EQ(md->nodeCount(), 0);
    EXPECT_EQ(md->ingressPort(), 0);
    EXPECT_EQ(md->egressPort(), 0);
    EXPECT_EQ(md->metadataSize(0), 0);
    EXPECT_EQ(md->metadataSize(1), 0);
    EXPECT_EQ(md->metadataSize(2), 0);
    EXPECT_EQ(md->metadataSize(3), 0);
    EXPECT_EQ(md->metadata<uint64_t>(0), 0);
    EXPECT_EQ(md->metadata<uint64_t>(1), 0);
    EXPECT_EQ(md->metadata<uint64_t>(2), 0);
    EXPECT_EQ(md->metadata<uint64_t>(3), 0);

    // AS 1-ff00:0:111
    md = &report.data[1];
    EXPECT_EQ(md->isSource(), false);
    EXPECT_EQ(md->isIngress(), false);
    EXPECT_EQ(md->isEgress(), true);
    EXPECT_EQ(md->isAggregate(), false);
    EXPECT_EQ(md->hopIndex(), 0);
    EXPECT_EQ(md->hasNodeId(), true);
    EXPECT_EQ(md->hasNodeCount(), true);
    EXPECT_EQ(md->hasIngressPort(), true);
    EXPECT_EQ(md->hasEgressPort(), true);
    EXPECT_EQ(md->nodeId(), 1);
    EXPECT_EQ(md->nodeCount(), 1);
    EXPECT_EQ(md->ingressPort(), 0);
    EXPECT_EQ(md->egressPort(), 41);
    EXPECT_EQ(md->metadataSize(0), 2);
    EXPECT_EQ(md->metadataSize(1), 6);
    EXPECT_EQ(md->metadataSize(2), 4);
    EXPECT_EQ(md->metadataSize(3), 4);
    EXPECT_EQ(md->metadata<uint16_t>(0), 1);
    EXPECT_EQ(md->metadata<uint64_t>(1), 0xff00'0000'0111ull);
    EXPECT_EQ(md->metadata<uint16_t>(2), 0x0201u);
    EXPECT_LT(md->metadata<uint32_t>(3), 400);

    // AS 1-ff00:0:110
    md = &report.data[2];
    EXPECT_EQ(md->isSource(), false);
    EXPECT_EQ(md->isIngress(), true);
    EXPECT_EQ(md->isEgress(), true);
    EXPECT_EQ(md->isAggregate(), true);
    EXPECT_EQ(md->hopIndex(), 1);
    EXPECT_EQ(md->hasNodeId(), true);
    EXPECT_EQ(md->hasNodeCount(), true);
    EXPECT_EQ(md->hasIngressPort(), true);
    EXPECT_EQ(md->hasEgressPort(), true);
    EXPECT_EQ(md->nodeId(), 2);
    EXPECT_EQ(md->nodeCount(), 2);
    EXPECT_EQ(md->ingressPort(), 0);
    EXPECT_EQ(md->egressPort(), 2);
    EXPECT_EQ(md->metadataSize(0), 2);
    EXPECT_EQ(md->metadataSize(1), 6);
    EXPECT_EQ(md->metadataSize(2), 4);
    EXPECT_EQ(md->metadataSize(3), 4);
    EXPECT_EQ(md->metadata<uint16_t>(0), 1);
    EXPECT_EQ(md->metadata<uint64_t>(1), 0xff00'0000'0110ull);
    EXPECT_EQ(md->metadata<uint16_t>(2), 0x0201u);
    EXPECT_LT(md->metadata<uint32_t>(3), 400);

    // AS 1-ff00:0:112
    md = &report.data[3];
    EXPECT_EQ(md->isSource(), false);
    EXPECT_EQ(md->isIngress(), true);
    EXPECT_EQ(md->isEgress(), false);
    EXPECT_EQ(md->isAggregate(), false);
    EXPECT_EQ(md->hopIndex(), 3);
    EXPECT_EQ(md->hasNodeId(), true);
    EXPECT_EQ(md->hasNodeCount(), true);
    EXPECT_EQ(md->hasIngressPort(), true);
    EXPECT_EQ(md->hasEgressPort(), true);
    EXPECT_EQ(md->nodeId(), 1);
    EXPECT_EQ(md->nodeCount(), 1);
    EXPECT_EQ(md->ingressPort(), 1);
    EXPECT_EQ(md->egressPort(), 0);
    EXPECT_EQ(md->metadataSize(0), 2);
    EXPECT_EQ(md->metadataSize(1), 6);
    EXPECT_EQ(md->metadataSize(2), 4);
    EXPECT_EQ(md->metadataSize(3), 0);
    EXPECT_EQ(md->metadata<uint16_t>(0), 1);
    EXPECT_EQ(md->metadata<uint64_t>(1), 0xff00'0000'0112ull);
    EXPECT_EQ(md->metadata<uint16_t>(2), 0x0201u);
    EXPECT_EQ(md->metadata<uint32_t>(3), 0);
}

TEST_F(IdIntApiFixture, DecodeUnverified)
{
    using namespace scion;
    using namespace scion::hdr;
    using namespace scion::idint;

    hdr::HopByHopOpts extHdr;
    IdInt ext;

    ReadStream stream(rawReports.at(0));
    StreamError err;
    ASSERT_TRUE(extHdr.serialize(stream, err)) << err;
    ASSERT_TRUE(ext.parse(stream, err)) << err;

    IntReport report;
    auto result = ext.decodeUnverified(report);
    ASSERT_FALSE(result) << result;

    EXPECT_FALSE(report.stackFull);
    EXPECT_EQ(report.identifier.timestamp, 67852596012585ull);
    EXPECT_EQ(report.identifier.port, 0);
    EXPECT_EQ(report.agrMode, AM::AS);
    EXPECT_THAT(report.agrFuncs, testing::ElementsAre(AF::Last, AF::Last, AF::Last, AF::Last));
    EXPECT_THAT(report.instructions, testing::ElementsAre(
        Instr::Isd, Instr::Asn, Instr::DeviceTypeRole, Instr::RttNextBr));
    checkMetadata(report);
}

TEST_F(IdIntApiFixture, DecodeVerified)
{
    using namespace scion;
    using namespace scion::hdr;
    using namespace scion::idint;
    using namespace std::chrono_literals;
    using time_point = std::chrono::system_clock::time_point;

    hdr::HopByHopOpts extHdr;
    IdInt ext;

    ReadStream stream(rawReports.at(0));
    StreamError err;
    ASSERT_TRUE(extHdr.serialize(stream, err)) << err;
    ASSERT_TRUE(ext.parse(stream, err)) << err;

    IntReport report;
    std::chrono::system_clock::time_point now(67852596012585ns);
    drkey::Key sourceKey;
    sourceKey.key = {
        0x51_b, 0xe4_b, 0x29_b, 0x9c_b, 0x13_b, 0x3d_b, 0x0e_b, 0x2f_b,
        0xc6_b, 0xed_b, 0xb9_b, 0xe7_b, 0x6d_b, 0x98_b, 0xad_b, 0x38_b
    };
    auto result = ext.verifyAndDecrypt(report, now, sourceKey,
        [&] (uint8_t hop, time_point time) {
            drkey::Key k;
            IsdAsn as;
            switch (hop) {
            case 0:
                k.key = {
                    0xbc_b, 0xd7_b, 0x57_b, 0xd1_b, 0x10_b, 0x34_b, 0x3c_b, 0xed_b,
                    0x1b_b, 0xeb_b, 0x37_b, 0xbe_b, 0x37_b, 0x92_b, 0x83_b, 0x79_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0111ull));
                break;
            case 1:
                k.key = {
                    0xf4_b, 0x3b_b, 0xb7_b, 0xa6_b, 0xa1_b, 0xa6_b, 0xa1_b, 0xba_b,
                    0x0a_b, 0xab_b, 0xf2_b, 0xfd_b, 0x49_b, 0x07_b, 0x92_b, 0x85_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0110ull));
                break;
            case 3:
                k.key = {
                    0xf1_b, 0x8c_b, 0xfe_b, 0x67_b, 0xb1_b, 0x94_b, 0x3d_b, 0xf5_b,
                    0x0d_b, 0xb8_b, 0xad_b, 0x5d_b, 0xe1_b, 0xe9_b, 0x5f_b, 0x63_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0112ull));
                break;
            default:
                break;
            }
            return std::make_pair(as, k);
        }
    );
    if (!result) {
        std::string expected, actual;
        hdr::details::formatBytes(std::back_inserter(expected), result.expectedMAC);
        hdr::details::formatBytes(std::back_inserter(actual), result.actualMAC);
        FAIL()
            << "Decoding INT report failed: " << result.error << '\n'
            << "expectedMAC = " << expected << '\n'
            << "actualMAC   = " << actual << '\n'
            << "isSource    = " << result.location.isSource << '\n'
            << "hopIndex    = " << result.location.hopIndex << '\n'
            << "isdAsn      = " << result.location.isdAsn << '\n';
    }

    EXPECT_FALSE(report.stackFull);
    EXPECT_EQ(report.identifier.timestamp, 67852596012585ull);
    EXPECT_EQ(report.identifier.port, 0);
    EXPECT_EQ(report.agrMode, AM::AS);
    EXPECT_THAT(report.agrFuncs, testing::ElementsAre(AF::Last, AF::Last, AF::Last, AF::Last));
    EXPECT_THAT(report.instructions, testing::ElementsAre(
        Instr::Isd, Instr::Asn, Instr::DeviceTypeRole, Instr::RttNextBr));
    checkMetadata(report);
}

TEST_F(IdIntApiFixture, DecodeEncrypted)
{
    using namespace scion;
    using namespace scion::hdr;
    using namespace scion::idint;
    using namespace std::chrono_literals;
    using time_point = std::chrono::system_clock::time_point;

    hdr::HopByHopOpts extHdr;
    IdInt ext;

    ReadStream stream(rawReports.at(1));
    StreamError err;
    ASSERT_TRUE(extHdr.serialize(stream, err)) << err;
    ASSERT_TRUE(ext.parse(stream, err)) << err;

    IntReport report;
    std::chrono::system_clock::time_point now(73299619925897ns);
    drkey::Key sourceKey;
    sourceKey.key = {
        0x51_b, 0xe4_b, 0x29_b, 0x9c_b, 0x13_b, 0x3d_b, 0x0e_b, 0x2f_b,
        0xc6_b, 0xed_b, 0xb9_b, 0xe7_b, 0x6d_b, 0x98_b, 0xad_b, 0x38_b
    };
    auto result = ext.verifyAndDecrypt(report, now, sourceKey,
        [&] (uint8_t hop, time_point time) {
            drkey::Key k;
            IsdAsn as;
            switch (hop) {
            case 0:
                k.key = {
                    0xbc_b, 0xd7_b, 0x57_b, 0xd1_b, 0x10_b, 0x34_b, 0x3c_b, 0xed_b,
                    0x1b_b, 0xeb_b, 0x37_b, 0xbe_b, 0x37_b, 0x92_b, 0x83_b, 0x79_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0111ull));
                break;
            case 1:
                k.key = {
                    0xf4_b, 0x3b_b, 0xb7_b, 0xa6_b, 0xa1_b, 0xa6_b, 0xa1_b, 0xba_b,
                    0x0a_b, 0xab_b, 0xf2_b, 0xfd_b, 0x49_b, 0x07_b, 0x92_b, 0x85_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0110ull));
                break;
            case 3:
                k.key = {
                    0xf1_b, 0x8c_b, 0xfe_b, 0x67_b, 0xb1_b, 0x94_b, 0x3d_b, 0xf5_b,
                    0x0d_b, 0xb8_b, 0xad_b, 0x5d_b, 0xe1_b, 0xe9_b, 0x5f_b, 0x63_b
                };
                as = IsdAsn(Isd(1), Asn(0xff00'0000'0112ull));
                break;
            default:
                break;
            }
            return std::make_pair(as, k);
        }
    );
    if (!result) {
        std::string expected, actual;
        hdr::details::formatBytes(std::back_inserter(expected), result.expectedMAC);
        hdr::details::formatBytes(std::back_inserter(actual), result.actualMAC);
        FAIL()
            << "Decoding INT report failed: " << result.error << '\n'
            << "expectedMAC = " << expected << '\n'
            << "actualMAC   = " << actual << '\n'
            << "isSource    = " << result.location.isSource << '\n'
            << "hopIndex    = " << result.location.hopIndex << '\n'
            << "isdAsn      = " << result.location.isdAsn << '\n';
    }

    EXPECT_FALSE(report.stackFull);
    EXPECT_EQ(report.identifier.timestamp, 73299619925897ull);
    EXPECT_EQ(report.identifier.port, 0);
    EXPECT_EQ(report.agrMode, AM::AS);
    EXPECT_THAT(report.agrFuncs, testing::ElementsAre(AF::Last, AF::Last, AF::Last, AF::Last));
    EXPECT_THAT(report.instructions, testing::ElementsAre(
        Instr::Isd, Instr::Asn, Instr::DeviceTypeRole, Instr::RttNextBr));
    checkMetadata(report);
}
