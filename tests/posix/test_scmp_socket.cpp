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
#include "scion/posix/scmp_socket.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <array>
#include <chrono>
#include <vector>


class ScmpSocketFixture : public testing::Test
{
public:
    using Socket = scion::posix::ScmpSocket<scion::posix::PosixSocket<scion::posix::IPEndpoint>>;

protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        using namespace std::chrono_literals;

        ep1 = unwrap(Socket::Endpoint::Parse("[1-ff00:0:1,::1]:0"));
        ep2 = ep1;

        sock1.bind(ep1);
        ep1 = sock1.localEp();
        sock2.bind(ep2);
        ep2 = sock2.localEp();

        sock1.setRecvTimeout(1s);
        sock2.setRecvTimeout(1s);

        sock1.connect(ep2);
        sock2.connect(ep1);
    };

    static void TearDownTestSuite()
    {
        sock1.close();
        sock2.close();
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
        req.maxStackLen = 64;
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
    inline static Socket sock1, sock2;
};

TEST_F(ScmpSocketFixture, MeasureTo)
{
    using namespace scion;
    auto msg = hdr::ScmpEchoRequest{0, 1};
    ASSERT_EQ(unwrap(sock1.measureScmpTo(ep2, RawPath(), msg)), 68);
}

TEST_F(ScmpSocketFixture, MeasureToExt)
{
    using namespace scion;
    idint::IdInt idint;
    std::array<ext::Extension*, 1> hbhExt = {&idint};
    auto msg = hdr::ScmpEchoRequest{0, 1};
    ASSERT_EQ(unwrap(sock1.measureScmpToExt(ep2, RawPath(), hbhExt, msg)), 92);
}

TEST_F(ScmpSocketFixture, SendToRecvFrom)
{
    using namespace scion;

    HeaderCache headers;
    static const std::array<std::byte, 8> payload = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b
    };
    auto msg = hdr::ScmpEchoRequest{0, 1};

    auto nh = unwrap(toUnderlay<Socket::UnderlayEp>(ep2.localEp()));
    auto sent = sock1.sendScmpTo(headers, ep2, RawPath(), nh, msg, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto recvd = sock2.recvScmpFromVia(buffer, from, path, ulSource, scmp);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
}

TEST_F(ScmpSocketFixture, SendToRecvFromExt)
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
    auto sent = sock1.sendScmpToExt(headers, ep2, RawPath(), nh, hbhExt, msg, payload);
    ASSERT_FALSE(isError(sent)) << getError(sent);
    ASSERT_THAT(get(sent), testing::ElementsAreArray(payload));

    std::vector<std::byte> buffer(1024);
    Socket::Endpoint from;
    RawPath path;
    Socket::UnderlayEp ulSource;
    hdr::ScmpMessage scmp;
    auto recvd = sock2.recvScmpFromViaExt(buffer, from, path, ulSource, hbhExt, e2eExt, scmp);
    ASSERT_FALSE(isError(recvd)) << getError(recvd);
    ASSERT_THAT(get(recvd), testing::ElementsAreArray(payload));
    EXPECT_EQ(from.address(), ep1.address());
    EXPECT_TRUE(path.empty());
    EXPECT_EQ(
        EndpointTraits<posix::IPEndpoint>::host(ulSource),
        unwrap(AddressTraits<posix::IPAddress>::fromString("::1")));
}
