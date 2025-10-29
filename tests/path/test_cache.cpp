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

#include "scion/path/cache.hpp"
#include "scion/path/path.hpp"
#include "scion/path/shared_cache.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <chrono>


template <typename T>
class PathCacheTest : public testing::Test
{};

using PathCacheTypes = testing::Types<
    scion::PathCache,
    scion::SharedPathCache
>;
TYPED_TEST_SUITE(PathCacheTest, PathCacheTypes);

TYPED_TEST(PathCacheTest, Lookup)
{
    using namespace scion;
    using namespace std::chrono_literals;
    using testing::_;

    TypeParam cache;
    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        auto now = std::chrono::utc_clock::now();
        auto nh = unwrap(generic::IPEndpoint::Parse("10.0.0.1:31000"));
        static std::array<std::byte, 16> path = {};
        std::vector<PathPtr> paths = {
            makePath(src, dst, hdr::PathType::SCION, now + 1h, 1420, nh, path),
            makePath(src, dst, hdr::PathType::SCION, now + 1h, 1200, nh, path),
            makePath(src, dst, hdr::PathType::SCION, now + 1min, 1420, nh, path),
        };
        cache.store(src, dst, std::move(paths)); // vector&& overload
        return ErrorCode::Ok;
    };

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    auto paths = cache.lookupCached(src, dst);
    EXPECT_TRUE(paths.empty());
    auto result = cache.lookup(src, dst, queryPaths);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 2);

    auto receivePaths = [] (std::ranges::forward_range auto&& paths) {
        std::vector<PathPtr> v(paths.begin(), paths.end());
        EXPECT_EQ(v.size(), 2);
    };
    EXPECT_EQ(cache.lookup(src, dst, receivePaths, queryPaths), ErrorCode::Ok);
    cache.lookupCached(src, dst, receivePaths);

    testing::MockFunction<std::error_code(TypeParam&, IsdAsn, IsdAsn)> mockProvider;
    EXPECT_CALL(mockProvider, Call(_, src, dst)).Times(0);
    result = cache.lookup(src, dst, mockProvider.AsStdFunction());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 2);

    cache.clear(src, src);
    EXPECT_EQ(cache.lookupCached(src, dst).size(), 2);

    cache.clear(src, dst);
    EXPECT_TRUE(cache.lookupCached(src, dst).empty());
}

TYPED_TEST(PathCacheTest, Prefetch)
{
    using namespace scion;
    using namespace std::chrono_literals;

    TypeParam cache;
    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        auto now = std::chrono::utc_clock::now();
        auto nh = unwrap(generic::IPEndpoint::Parse("10.0.0.1:31000"));
        static std::array<std::byte, 16> path = {};
        std::vector<PathPtr> paths = {
            makePath(src, dst, hdr::PathType::SCION, now + 1h, 1420, nh, path),
        };
        cache.store(src, dst, std::move(paths)); // vector&& overload
        return ErrorCode::Ok;
    };

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    ASSERT_TRUE(cache.lookupCached(src, dst).empty());
    ASSERT_FALSE(cache.prefetch(src, dst, queryPaths));
    auto paths = cache.lookupCached(src, dst);
    ASSERT_EQ(paths.size(), 1);
}

// Test path refresh interval.
TYPED_TEST(PathCacheTest, Refresh)
{
    using namespace scion;
    using namespace std::chrono_literals;
    using testing::_;

    PathCacheOptions opts;
    opts.minAcceptedLifetime = 5min;
    opts.refreshAtRemaining = 10min;
    opts.refreshInterval = 0s; // always force a refresh
    TypeParam cache(opts);

    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        auto now = std::chrono::utc_clock::now();
        auto nh = unwrap(generic::IPEndpoint::Parse("10.0.0.1:31000"));
        static std::array<std::byte, 16> path = {};
        std::vector<PathPtr> paths = {
            makePath(src, dst, hdr::PathType::SCION, now + 1h, 1420, nh, path),
        };
        cache.store(src, dst, paths); // range overload
        return ErrorCode::Ok;
    };

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    auto result = cache.lookup(src, dst, queryPaths);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 1);

    testing::MockFunction<std::error_code(TypeParam&, IsdAsn, IsdAsn)> mockProvider;
    EXPECT_CALL(mockProvider, Call(_, src, dst)).WillOnce(testing::Return(ErrorCode::Ok));
    result = cache.lookup(src, dst, mockProvider.AsStdFunction());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 1);
}

// Test empty return from path query.
TYPED_TEST(PathCacheTest, NoPaths)
{
    using namespace scion;
    using namespace std::chrono_literals;
    using testing::_;

    TypeParam cache;
    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        cache.store(src, dst, std::views::empty<PathPtr>);
        return ErrorCode::Ok;
    };

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    auto result = cache.lookup(src, dst, queryPaths);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());

    // After an empty query result was stored, the cache should not immediately
    // try another query for the same ASes.
    testing::MockFunction<std::error_code(TypeParam&, IsdAsn, IsdAsn)> mockProvider;
    EXPECT_CALL(mockProvider, Call(_, src, dst)).Times(0);
    result = cache.lookup(src, dst, mockProvider.AsStdFunction());
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->empty());
}

// Test empty paths for AS-internal communication.
TYPED_TEST(PathCacheTest, EmptyPath)
{
    using namespace scion;

    TypeParam cache;
    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        cache.store(src, dst, std::views::empty<PathPtr>);
        return ErrorCode::Ok;
    };

    auto ia = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    EXPECT_TRUE(cache.lookupCached(ia, ia).empty());

    auto result = cache.lookup(ia, ia, queryPaths);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    auto path = result->at(0);
    ASSERT_TRUE(path->empty());
    ASSERT_EQ(path->firstAS(), ia);
    ASSERT_EQ(path->lastAS(), ia);
}

// Test a path callback that does not provide paths immediately.
TYPED_TEST(PathCacheTest, AsyncRefresh)
{
    using namespace scion;

    TypeParam cache;
    auto queryPaths = [] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        return ErrorCode::Pending;
    };

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    auto result = cache.lookup(src, dst, queryPaths);
    ASSERT_TRUE(isError(result));
    EXPECT_EQ(getError(result), ErrorCode::Pending);
}

// Test marking paths as broken via SCMP messages.
TYPED_TEST(PathCacheTest, SCMPHandler)
{
    using namespace scion;
    using namespace scion::path_meta;
    using namespace std::chrono_literals;

    auto src = unwrap(IsdAsn::Parse("1-ff00:0:1"));
    auto dst = unwrap(IsdAsn::Parse("2-ff00:0:2"));
    auto now = std::chrono::utc_clock::now();
    auto nh = unwrap(generic::IPEndpoint::Parse("10.0.0.1:31000"));
    static std::array<std::byte, 16> dpPath = {};
    auto path1 = makePath(src, dst, hdr::PathType::SCION, now + 1h, 1420, nh, dpPath);
    auto path2 = makePath(src, dst, hdr::PathType::SCION, now + 1h, 1420, nh, dpPath);

    auto hops = path1->addAttribute<Interfaces>(PATH_ATTRIBUTE_INTERFACES);
    hops->data = {
        Hop{IsdAsn(Isd(1), Asn(1)), AsInterface(0), AsInterface(1)},
        Hop{IsdAsn(Isd(1), Asn(2)), AsInterface(2), AsInterface(0)},
    };

    hops = path2->addAttribute<Interfaces>(PATH_ATTRIBUTE_INTERFACES);
    hops->data = {
        Hop{IsdAsn(Isd(1), Asn(1)), AsInterface(0), AsInterface(3)},
        Hop{IsdAsn(Isd(1), Asn(2)), AsInterface(4), AsInterface(0)},
    };

    std::vector<PathPtr> paths = { path1, path2 };

    auto queryPaths = [&paths] (TypeParam& cache, IsdAsn src, IsdAsn dst) -> std::error_code {
        cache.store(src, dst, paths);
        return ErrorCode::Ok;
    };

    TypeParam cache;
    auto result = cache.lookup(src, dst, queryPaths);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 2);

    // revoke path by ScmpIntConnDown
    ScIPAddress from;
    std::span<std::byte> payload;
    hdr::ScmpMessage scmp = hdr::ScmpIntConnDown{
        IsdAsn(Isd(1), Asn(1)), AsInterface(0), AsInterface(3)
    };
    cache.handleScmp(from, RawPath(), scmp, payload);
    paths = cache.lookupCached(src, dst);
    ASSERT_EQ(paths.size(), 2);
    ASSERT_FALSE(paths.at(0)->broken());
    ASSERT_TRUE(paths.at(1)->broken());

    // revoke path by ScmpExtIfDown
    scmp = hdr::ScmpExtIfDown{
        IsdAsn(Isd(1), Asn(1)), AsInterface(1)
    };
    cache.handleScmp(from, RawPath(), scmp, payload);
    paths = cache.lookupCached(src, dst);
    ASSERT_EQ(paths.size(), 2);
    ASSERT_TRUE(paths.at(0)->broken());
    ASSERT_TRUE(paths.at(1)->broken());
}
