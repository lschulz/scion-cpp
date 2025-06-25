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
#include "scion/hdr/scmp.hpp"
#include "scion/hdr/udp.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <cstring>
#include <string>

using std::uint16_t;


class ScmpFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;

        pkts = loadPackets("hdr/data/scmp.bin");

        refScion.qos = 32;
        refScion.hlen = 12;
        refScion.nh = hdr::ScionProto::SCMP;
        refScion.ptype = hdr::PathType::Empty;
        refScion.fl = 0xf'ffffu;
        refScion.dst = unwrap(ScIPAddress::Parse("1-ff00:0:1,10.0.0.1"));
        refScion.src = unwrap(ScIPAddress::Parse("2-ff00:0:2,fd00::2"));

        refScionPayload.qos = 32;
        refScionPayload.hlen = 12;
        refScionPayload.nh = hdr::ScionProto::UDP;
        refScionPayload.ptype = hdr::PathType::Empty;
        refScionPayload.plen = 12;
        refScionPayload.fl = 0xf'ffffu;
        refScionPayload.dst = refScion.src;
        refScionPayload.src = refScion.dst;

        refUDP.sport = 43000;
        refUDP.dport = 1200;
        refUDP.len = 12;

        refPayload = { 0_b, 0_b, 5_b, 57_b };
    };

    static void TestEmit(const std::vector<std::byte>& expected, scion::hdr::SCMP& scmp);

    enum Case {
        DestUnreachable = 0,
        PacketTooBig,
        ParamProblem,
        ExtIfDown,
        IntConnDown,
        EchoRequest,
        EchoReply,
        TraceRequest,
        TraceReply,
        UnknownError,
        UnknownInfo,
    };

    static std::vector<std::vector<std::byte>> pkts;
    static scion::hdr::SCION refScion, refScionPayload;
    static scion::hdr::UDP refUDP;
    static std::array<std::byte, 4> refPayload;
};

std::vector<std::vector<std::byte>> ScmpFixture::pkts;
scion::hdr::SCION ScmpFixture::refScion;
scion::hdr::SCION ScmpFixture::refScionPayload;
scion::hdr::UDP ScmpFixture::refUDP;
std::array<std::byte, 4> ScmpFixture::refPayload;


TEST_F(ScmpFixture, ParseDstUnreach)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::DestUnreachable));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::DstUnreach);
    const auto& msg = std::get<ScmpDstUnreach>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::DstUnreach);
    EXPECT_EQ(msg.code, ScmpDstUnreach::Denied);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParsePacketTooBig)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::PacketTooBig));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::PacketTooBig);
    const auto& msg = std::get<ScmpPacketTooBig>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::PacketTooBig);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.mtu, 1280);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseParamProblem)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::ParamProblem));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::ParamProblem);
    const auto& msg = std::get<ScmpParamProblem>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::ParamProblem);
    EXPECT_EQ(msg.code, ScmpParamProblem::UnknownPathType);
    EXPECT_EQ(msg.pointer, 8);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseExtIfDown)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::ExtIfDown));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::ExtIfDown);
    const auto& msg = std::get<ScmpExtIfDown>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::ExtIfDown);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.sender, unwrap(scion::IsdAsn::Parse("3-ff00:0:3")));
    EXPECT_EQ(msg.iface, scion::AsInterface(20));

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseIntConnDown)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::IntConnDown));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::IntConnDown);
    const auto& msg = std::get<ScmpIntConnDown>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::IntConnDown);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.sender, unwrap(scion::IsdAsn::Parse("3-ff00:0:3")));
    EXPECT_EQ(msg.ingress, scion::AsInterface(20));
    EXPECT_EQ(msg.egress, scion::AsInterface(30));

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseEchoRequest)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::EchoRequest));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::EchoRequest);
    const auto& msg = std::get<ScmpEchoRequest>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::EchoRequest);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.id, 0xffff);
    EXPECT_EQ(msg.seq, 2);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseEchoReply)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::EchoReply));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::EchoReply);
    const auto& msg = std::get<ScmpEchoReply>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::EchoReply);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.id, 0xffff);
    EXPECT_EQ(msg.seq, 2);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseTraceRequest)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::TraceRequest));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::TraceRequest);
    const auto& msg = std::get<ScmpTraceRequest>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::TraceRequest);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.id, 0xffff);
    EXPECT_EQ(msg.seq, 2);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseTraceReply)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::TraceReply));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), ScmpType::TraceReply);
    const auto& msg = std::get<ScmpTraceReply>(scmp.msg);
    EXPECT_EQ(msg.type, ScmpType::TraceReply);
    EXPECT_EQ(msg.code, 0);
    EXPECT_EQ(msg.id, 0xffff);
    EXPECT_EQ(msg.seq, 2);
    EXPECT_EQ(msg.sender, unwrap(scion::IsdAsn::Parse("3-ff00:0:3")));
    EXPECT_EQ(msg.iface, scion::AsInterface(20));

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseUnknownError)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::UnknownError));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    ASSERT_TRUE(scmp.serialize(stream, err)) << err;
    ASSERT_EQ(scmp.getType(), (ScmpType)100);
    const auto& msg = std::get<ScmpUnknownError>(scmp.msg);
    EXPECT_EQ(msg.type, (ScmpType)100);
    EXPECT_EQ(msg.code, 1);

    std::span<const std::byte> payload;
    ASSERT_TRUE(stream.lookahead(payload, scion::ReadStream::npos, err)) << err;
    auto chksum = details::internetChecksum(payload,
        scion.checksum((uint16_t)(scmp.size() + payload.size()), ScionProto::SCMP)
        + scmp.checksum());
    EXPECT_EQ(chksum, 0xffff);
}

TEST_F(ScmpFixture, ParseUnknownInfo)
{
    using namespace scion::hdr;

    scion::ReadStream stream(pkts.at(Case::UnknownInfo));
    scion::StreamError err;
    SCION scion;
    SCMP scmp;

    ASSERT_TRUE(scion.serialize(stream, err)) << err;
    // unknown informational messages must be ignored
    ASSERT_FALSE(scmp.serialize(stream, err));
    EXPECT_STREQ(err.getMessage(), "unknown informational SCMP message");
}

void ScmpFixture::TestEmit(const std::vector<std::byte>& expected, scion::hdr::SCMP& scmp)
{
    using namespace scion::hdr;

    std::vector<std::byte> buffer(expected.size());
    scion::WriteStream stream(buffer);
    scion::StreamError err;

    refScion.plen = (std::uint16_t)(60 + scmp.size());

    ASSERT_TRUE(refScion.serialize(stream, err)) << err;
    auto [payloadBegin, bitPos] = stream.getPos();
    ASSERT_EQ(bitPos, 0);

    ASSERT_TRUE(scmp.serialize(stream, err)) << err;

    ASSERT_TRUE(refScionPayload.serialize(stream, err)) << err;
    ASSERT_TRUE(refUDP.serialize(stream, err)) << err;
    ASSERT_TRUE(stream.serializeBytes(refPayload, err)) << err;

    std::span<const std::byte> payload;
    auto lookback = stream.getPos().first - payloadBegin;
    ASSERT_TRUE(stream.lookback(payload, lookback, err)) << err;
    auto chksum = details::internetChecksum(
        payload, refScion.checksum((uint16_t)(payload.size()), ScionProto::SCMP));
    EXPECT_TRUE(stream.updateChksum(chksum, lookback - 4, err)) << err;

    EXPECT_EQ(buffer, expected) << printBufferDiff(buffer, expected);
}

TEST_F(ScmpFixture, EmitDstUnreach)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpDstUnreach{ScmpDstUnreach::Denied};

    TestEmit(pkts.at(Case::DestUnreachable), scmp);
}

TEST_F(ScmpFixture, EmitPacketTooBig)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpPacketTooBig{1280};

    TestEmit(pkts.at(Case::PacketTooBig), scmp);
}

TEST_F(ScmpFixture, EmitParamProblem)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpParamProblem{ScmpParamProblem::UnknownPathType, 8};

    TestEmit(pkts.at(Case::ParamProblem), scmp);
}

TEST_F(ScmpFixture, EmitExtIfDown)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpExtIfDown{
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20)
    };

    TestEmit(pkts.at(Case::ExtIfDown), scmp);
}

TEST_F(ScmpFixture, EmitIntConnDown)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpIntConnDown{
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20),
        scion::AsInterface(30)
    };

    TestEmit(pkts.at(Case::IntConnDown), scmp);
}

TEST_F(ScmpFixture, EmitEchoRequest)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpEchoRequest{0xffff, 2};

    TestEmit(pkts.at(Case::EchoRequest), scmp);
}

TEST_F(ScmpFixture, EmitEchoReply)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpEchoReply{0xffff, 2};

    TestEmit(pkts.at(Case::EchoReply), scmp);
}

TEST_F(ScmpFixture, EmitTraceRequest)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpTraceRequest{0xffff, 2};

    TestEmit(pkts.at(Case::TraceRequest), scmp);
}

TEST_F(ScmpFixture, EmitTraceReply)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpTraceReply{
        0xffff,
        2,
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20)
    };

    TestEmit(pkts.at(Case::TraceReply), scmp);
}

TEST_F(ScmpFixture, PrintDstUnreach)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpDstUnreach{ScmpDstUnreach::Denied};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Destination Unreachable ]###\n"
        " code = 1\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintPacketTooBig)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpPacketTooBig{1280};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Packet Too Big ]###\n"
        " code = 0\n"
        " mtu  = 1280\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintParamProblem)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpParamProblem{ScmpParamProblem::UnknownPathType, 8};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Parameter Problem ]###\n"
        " code    = 20\n"
        " pointer = 8\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintExtIfDown)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpExtIfDown{
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20)
    };

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP External Interface Down ]###\n"
        " code   = 0\n"
        " sender = 3-ff00:0:3\n"
        " iface  = 20\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintIntConnDown)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpIntConnDown{
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20),
        scion::AsInterface(30)
    };

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Internal Connectivity Down ]###\n"
        " code    = 0\n"
        " sender  = 3-ff00:0:3\n"
        " ingress = 20\n"
        " egress  = 30\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintEchoRequest)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpEchoRequest{0xffff, 2};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Echo Request ]###\n"
        " code = 0\n"
        " id   = 65535\n"
        " seq  = 2\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintEchoReply)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpEchoReply{0xffff, 2};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Echo Reply ]###\n"
        " code = 0\n"
        " id   = 65535\n"
        " seq  = 2\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintTraceRequest)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpTraceRequest{0xffff, 2};

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Traceroute Request ]###\n"
        " code = 0\n"
        " id   = 65535\n"
        " seq  = 2\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}

TEST_F(ScmpFixture, PrintTraceReply)
{
    using namespace scion::hdr;

    SCMP scmp;
    scmp.msg = ScmpTraceReply{
        0xffff,
        2,
        unwrap(scion::IsdAsn::Parse("3-ff00:0:3")),
        scion::AsInterface(20)
    };

    static const char* expected =
        "###[ SCMP ]###\n"
        " chksum = 0\n"
        "###[ SCMP Traceroute Reply ]###\n"
        " code   = 0\n"
        " id     = 65535\n"
        " seq    = 2\n"
        " sender = 3-ff00:0:3\n"
        " iface  = 20\n";

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    out = scmp.print(out, 1);
    EXPECT_EQ(str, expected);
}
