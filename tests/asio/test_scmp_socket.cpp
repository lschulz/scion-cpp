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

TEST_F(AsioScmpSocketFixture, MeasureTo)
{
    using namespace scion;
    auto msg = hdr::ScmpEchoRequest{0, 1};
    ASSERT_EQ(unwrap(sock1->measureScmpTo(ep2, RawPath(), msg)), 68);
}

TEST_F(AsioScmpSocketFixture, MeasureToExt)
{
    using namespace scion;
    ext::IdInt idint;
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
    ext::IdInt idint;
    initIdIntExt(idint);
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
    ext::IdInt idint;
    initIdIntExt(idint);
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
