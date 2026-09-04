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

#include "scion/asio/scmp_socket.hpp"
#include "scion/extensions/idint.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <boost/asio/experimental/awaitable_operators.hpp>

#include <array>
#include <chrono>
#include <vector>


class AsioScmpSocketFixture : public testing::Test
{
public:
    using Socket = scion::asio::ScmpSocket;

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
    static std::error_code initIdIntExt(scion::idint::IdInt<Alloc>& idint)
    {
        using namespace scion::idint;
        using scion::drkey::Key;

        IntRequest req;
        req.flags.discard = 1;
        req.agrMode = AM::AS;
        req.vtype = Verifier::Destination;
        req.bitmap = InstrFlag::NodeID;
        req.stackBytes = 64;
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

    inline static Socket::Endpoint ep1, ep2;
    inline static boost::asio::io_context ioCtx;
    inline static std::unique_ptr<Socket> sock1, sock2;
};

TEST_F(AsioScmpSocketFixture, MeasureTo)
{
    using namespace scion;
    auto msg = hdr::ScmpEchoRequest{0, 1};
    ASSERT_EQ(unwrap(sock1->measureScmpTo(ep2, RawPath(), msg)), 68);
}

TEST_F(AsioScmpSocketFixture, MeasureToExt)
{
    using namespace scion;
    idint::IdInt idint;
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto msg = hdr::ScmpEchoRequest{0, 1};
    ASSERT_EQ(unwrap(sock1->measureScmpToExt(ep2, RawPath(), hbhExt, msg)), 92);
}

TEST_F(AsioScmpSocketFixture, SendToRecvFrom)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto msg = hdr::ScmpEchoRequest{0, 1};

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendScmpTo(headers, ep2, RawPath(), nh, msg, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto recvd = sock2->recvScmpFromVia(buffer, from, path, ulSource, scmp);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(AsioScmpSocketFixture, SendToRecvFromAsync)
{
    using namespace scion;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto msg = hdr::ScmpEchoRequest{0, 1};

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));
        sock2->recvScmpFromViaAsync(buffer, from, path, ulSource, scmp, receiveCompletion);
    };

    sock1->sendScmpToAsync(headers, ep2, RawPath(), nh, msg, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

TEST_F(AsioScmpSocketFixture, SendToRecvFromExt)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto msg = hdr::ScmpEchoRequest{0, 1};
    idint::IdInt idint;
    ASSERT_FALSE(initIdIntExt(idint));
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1->sendScmpToExt(headers, ep2, RawPath(), nh, hbhExt, msg, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto recvd = sock2->recvScmpFromViaExt(buffer, from, path, ulSource, hbhExt, e2eExt, scmp);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(AsioScmpSocketFixture, SendToRecvFromExtAsync)
{
    using namespace scion;
    using namespace std::chrono_literals;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto msg = hdr::ScmpEchoRequest{0, 1};
    idint::IdInt idint;
    ASSERT_FALSE(initIdIntExt(idint));
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto& e2eExt = ext::NoExtensions;

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto receiveCompletion = [&](Maybe<std::span<std::byte>> recvd) {
        ASSERT_FALSE(isError(recvd)) << getError(recvd);
        ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    };

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sendCompletion = [&](Maybe<std::span<const std::byte>> sent) {
        ASSERT_FALSE(isError(sent)) << getError(sent);
        ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));
        sock2->recvScmpFromViaExtAsync(buffer, from, path, ulSource, hbhExt, e2eExt, scmp,
            receiveCompletion);
    };

    sock1->sendScmpToExtAsync(headers, ep2, RawPath(), nh, hbhExt, msg, payload, sendCompletion);

    ioCtx.restart();
    ioCtx.run_for(1s);
}

// Test cancelling an SCMP receive operation with a timer.
TEST_F(AsioScmpSocketFixture, RecvScmpCancellation)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace std::chrono_literals;

    std::vector<std::byte> buffer(1024);

    auto test = [&] () -> awaitable<void>
    {
        Socket::Endpoint from;
        RawPath path;
        Socket::UnderlayEp ulSource;
        hdr::ScmpMessage scmp;
        steady_timer deadline(co_await this_coro::executor, 25ms);
        auto result = co_await (
            deadline.async_wait(use_awaitable)
            || sock2->recvScmpFromViaAsync(buffer, from, path, ulSource, scmp, use_awaitable));
        EXPECT_EQ(result.index(), 0); // cancelled by timer
    };

    ioCtx.restart();
    co_spawn(ioCtx, test(), detached);
    ioCtx.run();
}

// Cancel waiting for a STUN response.
TEST_F(AsioScmpSocketFixture, RecvStunCancellation)
{
    using namespace scion;
    using namespace boost::asio;
    using namespace boost::asio::experimental::awaitable_operators;
    using namespace std::chrono_literals;

    std::vector<std::byte> buffer(1024);

    auto test = [&] () -> awaitable<void>
    {
        steady_timer deadline(co_await this_coro::executor, 25ms);
        auto result = co_await (
            deadline.async_wait(use_awaitable)
            || sock2->recvStunResponseAsync(use_awaitable));
        EXPECT_EQ(result.index(), 0); // cancelled by timer
    };

    ioCtx.restart();
    co_spawn(ioCtx, test(), detached);
    ioCtx.run();
}
