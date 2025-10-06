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

#include "scion/extensions/idint.hpp"
#include "scion/posix/udp_socket.hpp"
#include "scion/scmp/handler.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <chrono>
#include <vector>


class UdpSocketFixture : public testing::Test
{
public:
    using Socket = scion::posix::UdpSocket<scion::posix::PosixSocket<scion::posix::IPEndpoint>>;

protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace std::chrono_literals;

        ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
        ep2 = ep1;

        ASSERT_FALSE(sock1.bind(ep1));
        ep1 = sock1.localEp();
        ASSERT_FALSE(sock2.bind(ep2));
        ep2 = sock2.localEp();

        ASSERT_FALSE(sock1.setRecvTimeout(1s));
        ASSERT_FALSE(sock2.setRecvTimeout(1s));

        ASSERT_FALSE(sock1.connect(ep2));
        ASSERT_FALSE(sock2.connect(ep1));
    };

    static void TearDownTestSuite()
    {
        sock1.close();
        sock2.close();
    }

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

    inline static Socket::Endpoint ep1, ep2;
    inline static Socket sock1, sock2;
};

TEST_F(UdpSocketFixture, Measure)
{
    using namespace scion;
    ASSERT_EQ(unwrap(sock1.measure(RawPath())), 68);
}

TEST_F(UdpSocketFixture, MeasureExt)
{
    using namespace scion;
    ext::IdInt idint;
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    ASSERT_EQ(unwrap(sock1.measureExt(RawPath(), hbhExt)), 92);
}

TEST_F(UdpSocketFixture, MeasureTo)
{
    using namespace scion;
    ASSERT_EQ(unwrap(sock1.measureTo(ep2, RawPath())), 68);
}

TEST_F(UdpSocketFixture, MeasureToExt)
{
    using namespace scion;
    ext::IdInt idint;
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    ASSERT_EQ(unwrap(sock1.measureToExt(ep2, RawPath(), hbhExt)), 92);
}

TEST_F(UdpSocketFixture, SendRecv)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    auto recvd = sock2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(UdpSocketFixture, SendRecvExt)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendExt(headers, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    auto recvd = sock2.recvExt(buffer, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(UdpSocketFixture, SendToRecvFrom)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendTo(headers, ep2, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    auto recvd = sock2.recvFrom(buffer, from);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
}

TEST_F(UdpSocketFixture, SendToRecvFromExt)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendToExt(headers, ep2, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    auto recvd = sock2.recvFromExt(buffer, from, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
}

TEST_F(UdpSocketFixture, SendToRecvFromVia)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendTo(headers, ep2, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto recvd = sock2.recvFromVia(buffer, from, path, ulSource);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
    EXPECT_TRUE(path.empty());
    EXPECT_EQ(
        EndpointTraits<posix::IPEndpoint>::host(ulSource),
        unwrap(AddressTraits<posix::IPAddress>::fromString("::1")));
}

TEST_F(UdpSocketFixture, SendToRecvFromViaExt)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendToExt(headers, ep2, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto recvd = sock2.recvFromViaExt(buffer, from, path, ulSource, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
    EXPECT_TRUE(path.empty());
    EXPECT_EQ(
        EndpointTraits<posix::IPEndpoint>::host(ulSource),
        unwrap(AddressTraits<posix::IPAddress>::fromString("::1")));
}

TEST_F(UdpSocketFixture, SendCached)
{
    using namespace scion;

    HeaderCache headers;
    std::vector<std::byte> buffer(1024);
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    static const std::array<std::byte, 8> payload2 = {
        8_b, 7_b, 6_b, 5_b, 4_b, 3_b, 2_b, 1_b
    };

    // create headers from scratch
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    // send new payload with the same headers
    sent = sock1.sendCached(headers, nh, payload2);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload2));

    sent = sock1.sendToCached(headers, ep2, nh, payload2);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload2));

    // receive first packet
    auto recvd = sock2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));

    // receive second packet
    recvd = sock2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload2));

    // receive third packet
    recvd = sock2.recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload2));
}

// Test binding to an address of the wrong type.
TEST(UdpSocket, WrongBindAddr)
{
    using namespace scion;
    using namespace scion::posix;
    using Socket = UdpSocket<PosixSocket<sockaddr_in>>;

    Socket sock;
    auto local = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
    ASSERT_TRUE(sock.bind(local));
}

// Test send without a connected remote endpoint.
TEST(UdpSocket, NotConnected)
{
    using namespace scion;
    using namespace scion::posix;

    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    using Socket = UdpSocket<PosixSocket<sockaddr_in>>;

    Socket sock;
    auto local = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,127.0.0.1]:0"));
    sock.bind(local);

    HeaderCache headers;
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(local.localEp()));
    auto sent = sock.send(headers, RawPath(), nh, payload);
    ASSERT_TRUE(isError(sent));
    ASSERT_EQ(getError(sent), ErrorCode::InvalidArgument);
}

class MockSCMPHandler : public scion::ScmpHandlerImpl
{
public:
    MOCK_METHOD(bool, handleScmpCallback, (
        const scion::Address<scion::generic::IPAddress>&,
        const scion::RawPath&,
        const scion::hdr::ScmpMessage& msg,
        std::span<const std::byte>), (override));
};

// Test invoking the SCMP handler.
TEST(UdpSocket, SCMPHandler)
{
    using namespace scion;
    using namespace std::chrono_literals;
    using Socket = scion::posix::UdpSocket<scion::posix::PosixSocket<scion::posix::IPEndpoint>>;
    using testing::_;

    auto ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
    auto ep2 = ep1;

    Socket sock1, sock2;
    sock1.bind(ep1);
    ep1 = sock1.localEp();
    sock2.bind(ep2);
    ep2 = sock2.localEp();

    sock1.setRecvTimeout(1s);
    sock2.setRecvTimeout(1s);

    sock1.connect(ep2);
    sock2.connect(ep1);

    HeaderCache headers;
    std::vector<std::byte> buffer(1024);

    auto from = ep1.address();
    RawPath rp(ep1.isdAsn(), ep2.isdAsn(), hdr::PathType::SCION, std::span<std::byte>());
    hdr::ScmpMessage msg = hdr::ScmpExtIfDown{
        ep1.isdAsn(), AsInterface(1)
    };
    std::span<const std::byte> payload;

    MockSCMPHandler handler;
    EXPECT_CALL(handler, handleScmpCallback(from, rp, msg, _)).Times(1);
    sock2.setNextScmpHandler(&handler);

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendScmpTo(headers, ep2, rp, nh, msg, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    // send a normal packet so recv doesn't wait for the timeout
    sent = sock1.sendTo(headers, ep2, rp, nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);

    ASSERT_FALSE(isError(sock2.recv(buffer)));
}
