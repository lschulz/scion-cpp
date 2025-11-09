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
#include "scion/path/path_meta.hpp"
#include "scion/path/path.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"


TEST(Path, LoadProtobuf)
{
    namespace pm = scion::path_meta;
    using namespace scion;
    using namespace std::chrono_literals;

    auto src = IsdAsn(Isd(1), Asn(0xff00'0000'0111));
    auto dst = IsdAsn(Isd(2), Asn(0xff00'0000'0222));
    auto nh = unwrap(generic::IPEndpoint::Parse("[fd00:f00d:cafe::7f00:19]:31024"));
    proto::daemon::v1::Path pb;
    PathPtr path;
    {
        auto buf = loadPackets("path/data/path_metadata_3hops.bin").at(0);
        pb.ParseFromArray(buf.data(), (int)(buf.size()));
        auto flags = daemon::PathReqFlags::AllMetadata;
        auto res = daemon::details::pathFromProtobuf(src, dst, pb, flags);
        ASSERT_TRUE(res.has_value()) << getError(res);
        path = *res;
    }

    EXPECT_EQ(path->firstAS(), src);
    EXPECT_EQ(path->lastAS(), dst);
    EXPECT_EQ(path->type(), hdr::PathType::SCION);
    EXPECT_EQ(path->expiry(), Path::Expiry(1712950886s));
    EXPECT_EQ(path->mtu(), 1472);
    EXPECT_FALSE(path->empty());
    EXPECT_EQ(path->size(), 48);
    EXPECT_EQ(path->nextHop(), nh);
    EXPECT_EQ(path->nextHop(generic::IPEndpoint()), nh);
    EXPECT_THAT(path->encoded(), testing::ElementsAreArray(
        reinterpret_cast<const std::byte*>(pb.raw().data()),  pb.raw().size()
    ));
    EXPECT_EQ(path->hopCount(), 2);
    EXPECT_FALSE(path->broken());

    static const std::array<pm::Hop, 3> expectedIfaces = {
        pm::Hop{
            .isdAsn = IsdAsn(0x1ff0000000111),
            .ingress = 0,
            .egress = 2,
        },
        pm::Hop{
            .isdAsn = IsdAsn(0x2ff0000000211),
            .ingress = 5,
            .egress = 4,
        },
        pm::Hop{
            .isdAsn = IsdAsn(0x2ff0000000222),
            .ingress = 3,
            .egress = 0,
        },
    };
    auto ifaces = path->getAttribute<pm::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
    ASSERT_NE(ifaces, nullptr);
    EXPECT_THAT(ifaces->data, testing::ElementsAreArray(expectedIfaces));

    static const std::array<pm::HopMeta, 3> expectedHopMeta = {
        pm::HopMeta{
            .ingRouter = pm::GeoCoordinates{},
            .egrRouter = pm::GeoCoordinates{},
            .internalHops = 0,
            .notes = "AS1-ff00:0:111",
        },
        pm::HopMeta{
            .ingRouter = pm::GeoCoordinates{},
            .egrRouter = pm::GeoCoordinates{},
            .internalHops = 2,
            .notes = "AS2-ff00:0:211",
        },
        pm::HopMeta{
            .ingRouter = pm::GeoCoordinates{},
            .egrRouter = pm::GeoCoordinates{},
            .internalHops = 0,
            .notes = "AS2-ff00:0:222",
        },
    };
    auto hopMeta = path->getAttribute<pm::HopMetadata>(PATH_ATTRIBUTE_HOP_META);
    ASSERT_NE(hopMeta, nullptr);
    EXPECT_THAT(hopMeta->data, testing::ElementsAreArray(expectedHopMeta));

    static const std::array<pm::LinkMeta, 3> expectedLinks = {
        pm::LinkMeta{
            .type = pm::LinkType::Direct,
            .latency = 5ms,
            .bandwidth = 10'000'000,
        },
        pm::LinkMeta{
            .type = pm::LinkType::Internal,
            .latency = 10ms,
            .bandwidth = 1'000'000,
        },
        pm::LinkMeta{
            .type = pm::LinkType::Unspecified,
            .latency = 8ms,
            .bandwidth = 5'000'000,
        },
    };
    auto links = path->getAttribute<pm::LinkMetadata>(PATH_ATTRIBUTE_LINK_META);
    ASSERT_NE(links, nullptr);
    EXPECT_THAT(links->data, testing::ElementsAreArray(expectedLinks));

    EXPECT_EQ(path->getAttribute<pm::Interfaces>(PATH_ATTRIBUTE_USER_BEGIN), nullptr);
}

TEST(Path, LoadInvalidProtobuf)
{
    namespace pm = scion::path_meta;
    using namespace scion;
    using namespace std::chrono_literals;

    auto src = IsdAsn(Isd(1), Asn(0xff00'0000'0111));
    auto dst = IsdAsn(Isd(2), Asn(0xff00'0000'0222));

    auto buf = loadPackets("path/data/path_metadata_invalid.bin").at(0);
    proto::daemon::v1::Path pb;
    pb.ParseFromArray(buf.data(), (int)(buf.size()));
    auto res = daemon::details::pathFromProtobuf(src, dst, pb, NoFlags);
    ASSERT_TRUE(isError(res));
    ASSERT_EQ(getError(res), ErrorCode::SyntaxError);
}

namespace {
class FakeAttribute : public scion::PathAttributeBase
{
public:
    int data;
};
}

TEST(Path, UserAttributes)
{
    using namespace scion;

    Path path;
    const int FAKE_ATTRIBUTE = PATH_ATTRIBUTE_USER_BEGIN + 1;
    EXPECT_NE(path.addAttribute<FakeAttribute>(FAKE_ATTRIBUTE), nullptr);
    EXPECT_NE(path.getAttribute<FakeAttribute>(FAKE_ATTRIBUTE), nullptr);
    path.removeAttribute(FAKE_ATTRIBUTE);
    EXPECT_EQ(path.getAttribute<FakeAttribute>(FAKE_ATTRIBUTE), nullptr);
}

TEST(Path, Empty)
{
    using namespace scion;
    Path path;
    EXPECT_EQ(path.type(), hdr::PathType::Empty);
    generic::IPEndpoint dst(generic::IPAddress::MakeIPv4(0x0a000001), 443);
    EXPECT_EQ(path.nextHop(dst), dst);
    EXPECT_EQ(path.hopCount(), 0);
}

class PathFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        src = IsdAsn(Isd(1), Asn(0xff00'0000'0111));
        dst = IsdAsn(Isd(2), Asn(0xff00'0000'0222));
        auto buf = loadPackets("path/data/path_metadata_3hops.bin").at(0);
        pb.ParseFromArray(buf.data(), (int)(buf.size()));
        auto flags = daemon::PathReqFlags::Interfaces;
        path = daemon::details::pathFromProtobuf(src, dst, pb, flags).value();
    };

    inline static scion::IsdAsn src, dst;
    inline static proto::daemon::v1::Path pb;
    inline static scion::PathPtr path;
};

TEST_F(PathFixture, Attributes)
{
    namespace pm = scion::path_meta;
    using namespace scion;
    EXPECT_NE(path->getAttribute<pm::Interfaces>(PATH_ATTRIBUTE_INTERFACES), nullptr);
    EXPECT_EQ(path->getAttribute<pm::HopMetadata>(PATH_ATTRIBUTE_HOP_META), nullptr);
    EXPECT_EQ(path->getAttribute<pm::LinkMetadata>(PATH_ATTRIBUTE_LINK_META), nullptr);
}

TEST_F(PathFixture, Iteration)
{
    using namespace scion;
    using Hop = std::pair<uint16_t, uint16_t>;

    static const std::array<Hop, 2> expected = {
        Hop{2, 5},
        Hop{4, 3},
    };

    std::vector<Hop> hops;
    std::ranges::copy(path->hops(), std::back_inserter(hops));
    EXPECT_THAT(hops, testing::ElementsAreArray(expected));
}

TEST_F(PathFixture, Equality)
{
    using namespace scion;

    EXPECT_EQ(*path, *path);

    proto::daemon::v1::Path pb2;
    pb2.CopyFrom(pb);
    pb2.mutable_expiration()->clear_seconds();
    auto path2 = daemon::details::pathFromProtobuf(src, dst, pb, NoFlags);
    EXPECT_NE(path, *path2);
}

TEST_F(PathFixture, Digest)
{
    using namespace scion;

    EXPECT_EQ(makeEmptyPath(path->firstAS())->digest(),
        PathDigest(0xe7cc783a3f31d342ll, 0x32437bfd0d34741aull));
    EXPECT_EQ(path->digest(), PathDigest(0x69ad8c98dbf078baull, 0x77aaf16649153a5full));
}

TEST_F(PathFixture, ContainsInterface)
{
    using namespace scion;

    IsdAsn asn(Isd(2), Asn(0xff00'0000'0211));
    EXPECT_FALSE(path->containsInterface(asn, AsInterface(101)));
    EXPECT_TRUE(path->containsInterface(asn, AsInterface(4)));
    EXPECT_TRUE(path->containsInterface(asn, AsInterface(5)));
}

TEST_F(PathFixture, ContainsHop)
{
    using namespace scion;

    EXPECT_FALSE(path->containsHop(
        IsdAsn(Isd(1), Asn(0xff00'0000'0111)), AsInterface(5), AsInterface(4)));
    EXPECT_TRUE(path->containsHop(
        IsdAsn(Isd(2), Asn(0xff00'0000'0211)), AsInterface(5), AsInterface(4)));
}

TEST_F(PathFixture, Format)
{
    using namespace scion;
    using namespace scion::daemon;

    EXPECT_EQ(std::format("{}", *path), "1-ff00:0:111 2>5 2-ff00:0:211 4>3 2-ff00:0:222");

    auto path2 = daemon::details::pathFromProtobuf(src, dst, pb, NoFlags).value();
    EXPECT_EQ(std::format("{}", *path2), "1-ff00:0:111 2>5 4>3 2-ff00:0:222");
}
