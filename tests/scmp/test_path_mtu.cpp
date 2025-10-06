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

#include "scion/daemon/client.hpp"
#include "scion/path/path.hpp"
#include "scion/scmp/handler.hpp"
#include "scion/scmp/path_mtu.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"


TEST(PathMtuDiscoverer, UpdateMtu)
{
    using namespace scion;
    auto dest = unwrap(generic::IPAddress::Parse("::1"));
    RawPath path;

    PathMtuDiscoverer pmtu(1400);
    pmtu.setFirstHopMtu(1300);
    EXPECT_EQ(pmtu.getMtu(dest, path), 1300);
    EXPECT_TRUE(pmtu.updateMtu(dest, path, 1280));
    EXPECT_EQ(pmtu.getMtu(dest, path), 1280);
    EXPECT_FALSE(pmtu.updateMtu(dest, path, 1400));
    EXPECT_EQ(pmtu.getMtu(dest, path), 1280);
    pmtu.forgetMtu(dest, path);
    EXPECT_TRUE(pmtu.updateMtu(dest, path, 1300));
    EXPECT_EQ(pmtu.getMtu(dest, path), 1300);
}

TEST(PathMtuDiscoverer, GetMtuPathWithMetadata)
{
    using namespace scion;
    PathMtuDiscoverer pmtu(1400);
    auto path = makePath(
        IsdAsn(Isd(1), Asn(0xff00'0000'0001)),
        IsdAsn(Isd(2), Asn(0xff00'0000'0002)),
        hdr::PathType::SCION,
        Path::Expiry::clock::now(),
        1280,
        generic::IPEndpoint::UnspecifiedIPv4(),
        std::span<const std::byte>()
    );
    auto dest = unwrap(generic::IPAddress::Parse("::1"));
    EXPECT_EQ(pmtu.getMtu(dest, *path), 1280);
}

TEST(PathMtuDiscoverer, GetMtuRawPath)
{
    using namespace scion;
    PathMtuDiscoverer pmtu(1400);
    auto dest = unwrap(generic::IPAddress::Parse("::1"));
    EXPECT_EQ(pmtu.getMtu(dest, RawPath()), 1400);
}

TEST(PathMtuDiscoverer, HandleScmp)
{
    using namespace scion;
    using namespace scion::hdr;

    auto dest = unwrap(generic::IPAddress::Parse("::1"));
    auto quotes = loadPackets("scmp/data/scmp_packet_quotes.bin");
    RawPath path(
        IsdAsn(Isd(2), Asn(0xff00'0000'0002)),
        IsdAsn(Isd(1), Asn(0xff00'0000'0001)),
        hdr::PathType::SCION,
        quotes.at(0)
    );

    PathMtuDiscoverer pmtu;
    EXPECT_EQ(pmtu.getMtu(dest, path), 65500);

    ScIPAddress from; // not used
    RawPath rp; // not used

    ScmpParamProblem invalidSize{ScmpParamProblem::Code::InvalidSize, 0};
    EXPECT_TRUE(pmtu.handleScmpCallback(from, rp, invalidSize, quotes.at(1)));
    EXPECT_EQ(pmtu.getMtu(dest, path), 8000);

    ScmpPacketTooBig packetTooBig{1400};
    EXPECT_TRUE(pmtu.handleScmpCallback(from, rp, packetTooBig, quotes.at(2)));
    EXPECT_EQ(pmtu.getMtu(dest, path), 1400);
}
