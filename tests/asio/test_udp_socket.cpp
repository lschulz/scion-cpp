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

#include "scion/asio/udp_socket.hpp"
#include "scion/extensions/idint.hpp"
#include "scion/scmp/handler.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <chrono>
#include <vector>


class AsioUdpSocketFixture : public testing::Test
{
public:
    using Socket = scion::asio::UdpSocket;

protected:
    static void SetUpTestSuite()
    {
        using namespace scion;

        ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
        ep2 = ep1;

        sock1 = std::make_unique<Socket>(ioCtx);
        sock1->bind(ep1);
        ep1 = sock1->localEp();

        sock2 = std::make_unique<Socket>(ioCtx);
        sock2->bind(ep2);
        ep2 = sock2->localEp();

        sock1->connect(ep2);
        sock2->connect(ep1);
    }

    static void TearDownTestSuite()
    {
        sock1.reset();
        sock2.reset();
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
    inline static boost::asio::io_context ioCtx;
    inline static std::unique_ptr<Socket> sock1, sock2;
};

TEST_F(AsioUdpSocketFixture, SendRecv)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    auto recvd = sock2->recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(AsioUdpSocketFixture, SendRecvAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    std::vector<std::byte> buffer(1024);
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvAsync(buffer, ulSource, receiveCompletion);
    };
    sock1->sendAsync(headers, RawPath(), nh, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendRecvExt)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendExt(headers, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    auto recvd = sock2->recvExt(buffer, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(AsioUdpSocketFixture, SendRecvExtAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    std::vector<std::byte> buffer(1024);
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvExtAsync(buffer, ulSource, hbhExt, e2eExt, receiveCompletion);
    };
    sock1->sendExtAsync(headers, RawPath(), nh, hbhExt, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendToRecvFrom)
{
    using namespace scion;
    using namespace boost::asio;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendTo(headers, ep2, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    auto recvd = sock2->recvFrom(buffer, from);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
        EXPECT_EQ(from, ep1);
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvFromAsync(buffer, from, ulSource, receiveCompletion);
    };
    sock1->sendToAsync(headers, ep2, RawPath(), nh, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendToRecvExtFrom)
{
    using namespace scion;
    using namespace boost::asio;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendToExt(headers, ep2, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    auto recvd = sock2->recvFromExt(buffer, from, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromExtAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
        EXPECT_EQ(from, ep1);
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvFromExtAsync(buffer, from, ulSource, hbhExt, e2eExt, receiveCompletion);
    };
    sock1->sendToExtAsync(headers, ep2, RawPath(), nh, hbhExt, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromVia)
{
    using namespace scion;
    using namespace boost::asio;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendTo(headers, ep2, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto recvd = sock2->recvFromVia(buffer, from, path, ulSource);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
    EXPECT_TRUE(path.empty());
    EXPECT_EQ(ulSource.address(), ip::make_address_v6("::1"));
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromViaAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
        EXPECT_EQ(from, ep1);
        EXPECT_TRUE(path.empty());
        EXPECT_EQ(ulSource.address(), ip::make_address_v6("::1"));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvFromViaAsync(buffer, from, path, ulSource, receiveCompletion);
    };
    sock1->sendToAsync(headers, ep2, RawPath(), nh, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromViaExt)
{
    using namespace scion;
    using namespace boost::asio;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendToExt(headers, ep2, RawPath(), nh, hbhExt, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto recvd = sock2->recvFromViaExt(buffer, from, path, ulSource, hbhExt, e2eExt);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from, ep1);
    EXPECT_TRUE(path.empty());
    EXPECT_EQ(ulSource.address(), ip::make_address_v6("::1"));
}

TEST_F(AsioUdpSocketFixture, SendToRecvFromViaExtAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    ext::IdInt idint;
    initIdIntExt(idint);
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(*recvd, testing::ElementsAreArray(payload));
        EXPECT_EQ(from, ep1);
        EXPECT_TRUE(path.empty());
        EXPECT_EQ(ulSource.address(), ip::make_address_v6("::1"));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(*sent, testing::ElementsAreArray(payload));
        sock2->recvFromViaExtAsync(buffer, from, path, ulSource, hbhExt, e2eExt, receiveCompletion);
    };
    sock1->sendToExtAsync(headers, ep2, RawPath(), nh, hbhExt, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioUdpSocketFixture, SendCached)
{
    using namespace scion;
    using namespace boost::asio;

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
    auto sent = sock1->send(headers, RawPath(), nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    // send new payload with the same headers
    sent = sock1->sendCached(headers, nh, payload2);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload2));

    sent = sock1->sendToCached(headers, ep2, nh, payload2);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload2));

    // receive first packet
    auto recvd = sock2->recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));

    // receive second packet
    recvd = sock2->recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload2));

    // receive third packet
    recvd = sock2->recv(buffer);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload2));
}

TEST_F(AsioUdpSocketFixture, SendCachedAsync)
{
    using namespace scion;
    using namespace boost::asio;

    HeaderCache headers;
    std::vector<std::byte> buffer(1024);
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    static const std::array<std::byte, 8> payload2 = {
        8_b, 7_b, 6_b, 5_b, 4_b, 3_b, 2_b, 1_b
    };

    constexpr auto token = boost::asio::use_awaitable;
    auto test = [&] () -> awaitable<void>
    {
        // create headers from scratch
        auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
        auto sent = co_await sock1->sendAsync(headers, RawPath(), nh, payload, token);
        EXPECT_FALSE(isError(sent)) << getError(sent);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(sent), testing::ElementsAreArray(payload));

        // send new payload with the same headers
        sent = co_await sock1->sendCachedAsync(headers, nh, payload2, token);
        EXPECT_FALSE(isError(sent)) << getError(sent);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(sent), testing::ElementsAreArray(payload2));

        sent = co_await sock1->sendToCachedAsync(headers, ep2, nh, payload2, token);
        EXPECT_FALSE(isError(sent)) << getError(sent);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(sent), testing::ElementsAreArray(payload2));

        // receive first packet
        Socket::UnderlayEp ulSource;
        auto recvd = co_await sock2->recvAsync(buffer, ulSource, token);
        EXPECT_FALSE(isError(recvd)) << getError(recvd);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(recvd), testing::ElementsAreArray(payload));

        // receive second packet
        recvd = co_await sock2->recvAsync(buffer, ulSource, token);
        EXPECT_FALSE(isError(recvd)) << getError(recvd);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(recvd), testing::ElementsAreArray(payload2));

        // receive third packet
        recvd = co_await sock2->recvAsync(buffer, ulSource, token);
        EXPECT_FALSE(isError(recvd)) << getError(recvd);
        if (isError(sent)) co_return;
        EXPECT_THAT(get(recvd), testing::ElementsAreArray(payload2));
    };

    ioCtx.restart();
    co_spawn(ioCtx, test(), detached);
    ioCtx.run();
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
TEST(AsioUdpSocket, SCMPHandler)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;
    using Socket = scion::asio::UdpSocket;
    using testing::_;

    auto ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
    auto ep2 = ep1;

    io_context ioCtx;
    Socket sock1(ioCtx), sock2(ioCtx);
    sock1.bind(ep1);
    ep1 = sock1.localEp();
    sock2.bind(ep2);
    ep2 = sock2.localEp();

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
    // send a normal packet so recv returns
    sent = sock1.sendTo(headers, ep2, rp, nh, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);

    ASSERT_FALSE(isError(sock2.recv(buffer)));
}

// Test invoking the SCMP handler from a completion handler.
TEST(AsioUdpSocket, SCMPHandlerAsync)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace std::chrono_literals;
    using Socket = scion::asio::UdpSocket;
    using testing::_;

    auto ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
    auto ep2 = ep1;

    io_context ioCtx;
    Socket sock1(ioCtx), sock2(ioCtx);
    sock1.bind(ep1);
    ep1 = sock1.localEp();
    sock2.bind(ep2);
    ep2 = sock2.localEp();

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
    Socket::UnderlayEp ulSource;
    auto recvHandler = [&] (Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
    };
    auto sentHandler = [&] (Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        // send a normal packet so recv returns
        sent = sock1.sendTo(headers, ep2, rp, nh, payload);
        ASSERT_FALSE(isError(sent)) << getError(sent);
        sock2.recvAsync(buffer, ulSource, recvHandler);
    };
    sock1.sendScmpToAsync(headers, ep2, rp, nh, msg, payload, sentHandler);

    ioCtx.run_for(1s);
}
