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

#include "scion/path/raw.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

using std::uint16_t;


class RawPathFixture : public testing::Test
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

TEST_F(RawPathFixture, Iteration)
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
        RawPath rp(
            unwrap(IsdAsn::Parse("1-ff00:0:1")),
            unwrap(IsdAsn::Parse("1-ff00:0:1")),
            hdr::PathType::SCION,
            path
        );
        std::vector<Hop> hops;
        std::ranges::copy(rp.hops(), std::back_inserter(hops));
        EXPECT_THAT(hops, testing::ElementsAreArray(expectedHops)) << PATH_NAME.at(i);
    }
}

TEST_F(RawPathFixture, Equality)
{
    using namespace scion;

    RawPath rp1(src, tgt, hdr::PathType::SCION, paths.at(0));
    RawPath rp2(tgt, src, hdr::PathType::SCION, paths.at(1));

    std::hash<RawPath> h;
    EXPECT_NE(h(rp1), h(rp2));
    EXPECT_EQ(rp1, rp1);
    EXPECT_NE(rp1, rp2);
}

TEST_F(RawPathFixture, Expiry)
{
    using namespace scion;

    RawPath rp(src, tgt, hdr::PathType::SCION, paths.at(0));
    EXPECT_EQ(rp.expiry(), RawPath::Expiry(std::chrono::seconds(1742911312)));
}

TEST_F(RawPathFixture, Digest)
{
    using namespace scion;

    RawPath rp(src, tgt, hdr::PathType::SCION, paths.at(0));
    auto d1 = rp.digest();
    rp.reverseInPlace();
    EXPECT_NE(d1, rp.digest());
}

TEST_F(RawPathFixture, Reverse)
{
    using namespace scion;
    using namespace std::views;

    int i = 0;
    auto makePair = [](auto chunk) { return std::make_pair(chunk.front(), chunk.back()); };
    for (auto [fwd, rev] : paths | chunk(2) | transform(makePair)) {
        RawPath rp(src, tgt, hdr::PathType::SCION, fwd);
        EXPECT_FALSE(rp.reverseInPlace());
        EXPECT_EQ(rp.firstAS(), tgt);
        EXPECT_EQ(rp.lastAS(), src);
        EXPECT_TRUE(std::ranges::equal(rp.encoded(), rev))
            << PATH_NAME.at(i) << '\n'
            << printBufferDiff(rp.encoded(), rev);
        ++i;
    }
}

TEST_F(RawPathFixture, Format)
{
    using namespace scion;

    RawPath rp(src, tgt, hdr::PathType::SCION, paths.at(0));
    EXPECT_EQ(std::format("{}", rp), "1-ff00:0:1 4>3 2>1 5>6 7>8 9>10 11>12 2-ff00:0:2");
}
