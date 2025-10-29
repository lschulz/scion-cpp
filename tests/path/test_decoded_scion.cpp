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

#include "scion/path/decoded_scion.hpp"
#include "scion/path/raw.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <cstring>
#include <ranges>

using std::uint16_t;


class DecodedScionFixture : public testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        using namespace scion;
        src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
        tgt = unwrap(IsdAsn::Parse("2-ff00:0:2"));
        paths = loadPackets("path/data/raw_path.bin");
    };

    inline static scion::IsdAsn src, tgt;
    inline static std::vector<std::vector<std::byte>> paths;
};

static const std::array<const char*, 6> PATH_NAME = {
    "Full", "Full Reverse",
    "Shortcut", "Shortcut Reverse",
    "Peering", "Peering Reverse",
};

TEST_F(DecodedScionFixture, Iteration)
{
    using namespace scion;
    using Hop = std::pair<uint16_t, uint16_t>;

    static const std::vector<std::vector<Hop>> expected = {
        // Full Path
        std::vector<Hop>{
            {4, 3},
            {2, 1},
            {5, 6},
            {7, 8},
            {9, 10},
            {11, 12},
        },
        std::vector<Hop>{
            {12, 11},
            {10, 9},
            {8, 7},
            {6, 5},
            {1, 2},
            {3, 4},
        },
        // Shortcut Path
        std::vector<Hop>{
            {4, 3},
            {9, 10},
        },
        std::vector<Hop>{
            {10, 9},
            {3, 4},
        },
        // Peering Path
        std::vector<Hop>{
            {6, 5},
            {4, 3},
            {2, 7},
            {8, 9},
            {10, 11},
        },
        std::vector<Hop>{
            {11, 10},
            {9, 8},
            {7, 2},
            {3, 4},
            {5, 6},
        }
    };

    int i = 0;
    for (const auto& [path, expectedHops] : std::views::zip(paths, expected)) {
        DecodedScionPath dp(src, tgt);
        ReadStream rs(path);
        StreamError err;
        ASSERT_TRUE(dp.serialize(rs, err)) << err;
        std::vector<Hop> hops;
        std::ranges::copy(dp.hops(), std::back_inserter(hops));
        EXPECT_THAT(hops, testing::ElementsAreArray(expectedHops)) << PATH_NAME.at(i);
    }
}

TEST_F(DecodedScionFixture, Equality)
{
    using namespace scion;

    DecodedScionPath dp1(src, tgt);
    {
        ReadStream rs(paths.at(0));
        ASSERT_TRUE(dp1.serialize(rs, NullStreamError));
    }
    DecodedScionPath dp2(tgt, src);
    {
        ReadStream rs(paths.at(1));
        ASSERT_TRUE(dp2.serialize(rs, NullStreamError));
    }

    std::hash<decltype(dp1)> h;
    EXPECT_NE(h(dp1), h(dp2));
    EXPECT_EQ(dp1, dp1);
    EXPECT_NE(dp1, dp2);
}

TEST_F(DecodedScionFixture, Digest)
{
    using namespace scion;

    DecodedScionPath dp(src, tgt);
    ReadStream rs(paths.at(0));
    ASSERT_TRUE(dp.serialize(rs, NullStreamError));

    auto d1 = dp.digest();
    dp.reverseInPlace();
    EXPECT_NE(d1, dp.digest());
}

TEST_F(DecodedScionFixture, Reverse)
{
    using namespace scion;
    using namespace std::views;

    RawPath rp;
    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto tgt = unwrap(IsdAsn::Parse("2-ff00:0:2"));

    int i = 0;
    auto makePair = [](auto chunk) { return std::make_pair(chunk.front(), chunk.back()); };
    for (auto [fwd, rev] : paths | chunk(2) | transform(makePair)) {
        DecodedScionPath dp(src, tgt);
        ReadStream rs(fwd);
        StreamError err;
        ASSERT_TRUE(dp.serialize(rs, err)) << err;
        EXPECT_FALSE(dp.reverseInPlace());
        EXPECT_EQ(dp.firstAS(), tgt);
        EXPECT_EQ(dp.lastAS(), src);
        ASSERT_TRUE(rp.encode(dp, err)) << err;
        EXPECT_TRUE(std::ranges::equal(rp.encoded(), rev))
            << "Path " << PATH_NAME.at(i) << '\n'
            << printBufferDiff(rp.encoded(), rev);
        ++i;
    }
}

TEST_F(DecodedScionFixture, Format)
{
    using namespace scion;

    DecodedScionPath dp(src, tgt);
    ReadStream rs(paths.at(0));
    ASSERT_TRUE(dp.serialize(rs, NullStreamError));

    EXPECT_EQ(std::format("{}", dp), "1-ff00:0:1 4>3 2>1 5>6 7>8 9>10 11>12 2-ff00:0:2");
}

TEST_F(DecodedScionFixture, Print)
{
    using namespace scion;
    static const char* expected =
        "###[ SCION Path ]###\n"
        "currInf = 2\n"
        "currHf  = 8\n"
        "seg0Len = 3\n"
        "seg1Len = 2\n"
        "seg2Len = 4\n"
        "###[ Info Field ]###\n"
        "flags     = 0x0\n"
        "segid     = 1\n"
        "timestamp = 1742904000\n"
        "###[ Info Field ]###\n"
        "flags     = 0x1\n"
        "segid     = 2\n"
        "timestamp = 1742907600\n"
        "###[ Info Field ]###\n"
        "flags     = 0x1\n"
        "segid     = 3\n"
        "timestamp = 1742911200\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 100\n"
        "consIngress = 4\n"
        "consEgress  = 0\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 100\n"
        "consIngress = 2\n"
        "consEgress  = 3\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 100\n"
        "consIngress = 0\n"
        "consEgress  = 1\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 20\n"
        "consIngress = 0\n"
        "consEgress  = 5\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 10\n"
        "consIngress = 6\n"
        "consEgress  = 0\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 0\n"
        "consIngress = 0\n"
        "consEgress  = 7\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 0\n"
        "consIngress = 8\n"
        "consEgress  = 9\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 0\n"
        "consIngress = 10\n"
        "consEgress  = 11\n"
        "mac         = 00:00:00:00:00:00\n"
        "###[ Hop Field ]###\n"
        "flags       = 0x0\n"
        "expTime     = 255\n"
        "consIngress = 12\n"
        "consEgress  = 0\n"
        "mac         = 00:00:00:00:00:00\n";

    DecodedScionPath dp(src, tgt);
    ReadStream rs(paths.at(0));
    ASSERT_TRUE(dp.serialize(rs, NullStreamError));

    std::string str;
    str.reserve(std::strlen(expected));
    std::back_insert_iterator out(str);
    dp.print(out, 0);
    EXPECT_EQ(str, expected);
}
