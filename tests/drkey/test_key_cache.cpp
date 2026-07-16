// Copyright (c) 2026 Lars-Christian Schulz
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

#include "scion/drkey/key_cache.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <chrono>


TEST(DRKeyCache, ASHostKey)
{
    using namespace scion;
    using namespace scion::generic;
    using namespace scion::drkey;
    using namespace std::chrono_literals;
    using TimePoint = std::chrono::utc_clock::time_point;

    const IsdAsn dstAS(Isd(1), Asn(1));
    const ScIPAddress dstHost(dstAS, IPAddress::MakeIPv4(0x0a000001u));

    const IsdAsn src1(Isd(1), Asn(64512));
    const IsdAsn src2(Isd(1), Asn(64513));

    const TimePoint now(67852596012585ns);
    static std::byte key[16] = {};

    KeyCache cache(DRKeyProtocol::IDINT);

    auto fetchASHostKey = [](
        IsdAsn srcIA,
        const ScIPAddress& dstHost,
        DRKeyProtocol proto,
        TimePoint validAt) -> Maybe<drkey::Key>
    {
        return drkey::Key(key, validAt, validAt + 30min);
    };

    // put two keys in the cache
    auto k = cache.getASHostKey(src1, dstHost, now, fetchASHostKey);
    ASSERT_TRUE(k.has_value());
    k = cache.getASHostKey(src2, dstHost, now, fetchASHostKey);
    ASSERT_TRUE(k.has_value());

    testing::MockFunction<
        Maybe<drkey::Key>(IsdAsn, const ScIPAddress&, DRKeyProtocol, TimePoint)> mock;
    EXPECT_CALL(mock, Call(src1, dstHost, DRKeyProtocol::IDINT, now + 1h))
        .WillOnce(testing::Return(drkey::Key(key, now + 1h, now + 2h)));
    EXPECT_CALL(mock, Call(src1, dstHost, DRKeyProtocol::IDINT, now + 3h))
        .WillOnce(testing::Return(drkey::Key(key, now + 3h, now + 4h)));
    auto mockFetcher = mock.AsStdFunction();

    // returns cached key
    k = cache.getASHostKey(src1, dstHost, now, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now));

    // cached key expired, fetches a new one
    k = cache.getASHostKey(src1, dstHost, now + 1h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 1h));

    // refresh keys
    EXPECT_EQ(cache.refreshASHostKeys(now + 2h, now + 2h, fetchASHostKey), 2);
    k = cache.getASHostKey(src1, dstHost, now + 2h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 2h));
    k = cache.getASHostKey(src2, dstHost, now + 2h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 2h));
    EXPECT_EQ(cache.refreshASHostKeys(now + 2h, now + 2h, fetchASHostKey), 0);

    // clear expired
    EXPECT_EQ(cache.countASHostKeys(), 2);
    cache.clearExpired(now + 3h);
    EXPECT_EQ(cache.countASHostKeys(), 0);
    k = cache.getASHostKey(src1, dstHost, now + 3h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 3h));
}

TEST(DRKeyCache, HostHostKey)
{
    using namespace scion;
    using namespace scion::generic;
    using namespace scion::drkey;
    using namespace std::chrono_literals;
    using TimePoint = std::chrono::utc_clock::time_point;

    const IsdAsn dstAS(Isd(1), Asn(1));
    const ScIPAddress dstHost(dstAS, IPAddress::MakeIPv4(0x0a000001u));

    const auto src1 = ScIPAddress(IsdAsn(Isd(1), Asn(64512)), IPAddress::MakeIPv4(0x0a000001u));
    const auto src2 = ScIPAddress(IsdAsn(Isd(1), Asn(64513)), IPAddress::MakeIPv4(0x0a000002u));

    const TimePoint now(67852596012585ns);
    static std::byte key[16] = {};

    KeyCache cache(DRKeyProtocol::IDINT);

    auto fetchHostHostKey = [](
        const ScIPAddress& srcHost,
        const ScIPAddress& dstHost,
        DRKeyProtocol proto,
        TimePoint validAt) -> Maybe<drkey::Key>
    {
        return drkey::Key(key, validAt, validAt + 30min);
    };

    // put two keys in the cache
    auto k = cache.getHostHostKey(src1, dstHost, now, fetchHostHostKey);
    ASSERT_TRUE(k.has_value());
    k = cache.getHostHostKey(src2, dstHost, now, fetchHostHostKey);
    ASSERT_TRUE(k.has_value());

    testing::MockFunction<
        Maybe<drkey::Key>(const ScIPAddress&, const ScIPAddress&, DRKeyProtocol, TimePoint)> mock;
    EXPECT_CALL(mock, Call(src1, dstHost, DRKeyProtocol::IDINT, now + 1h))
        .WillOnce(testing::Return(drkey::Key(key, now + 1h, now + 2h)));
    EXPECT_CALL(mock, Call(src1, dstHost, DRKeyProtocol::IDINT, now + 3h))
        .WillOnce(testing::Return(drkey::Key(key, now + 3h, now + 4h)));
    auto mockFetcher = mock.AsStdFunction();

    // returns cached key
    k = cache.getHostHostKey(src1, dstHost, now, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now));

    // cached key expired, fetches a new one
    k = cache.getHostHostKey(src1, dstHost, now + 1h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 1h));

    // refresh keys
    EXPECT_EQ(cache.refreshHostHostKeys(now + 2h, now + 2h, fetchHostHostKey), 2);
    k = cache.getHostHostKey(src1, dstHost, now + 2h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 2h));
    k = cache.getHostHostKey(src2, dstHost, now + 2h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 2h));
    EXPECT_EQ(cache.refreshHostHostKeys(now + 2h, now + 2h, fetchHostHostKey), 0);

    // clear expired
    EXPECT_EQ(cache.countHostHostKeys(), 2);
    cache.clearExpired(now + 3h);
    EXPECT_EQ(cache.countHostHostKeys(), 0);
    k = cache.getHostHostKey(src1, dstHost, now + 3h, mockFetcher);
    ASSERT_TRUE(k.has_value());
    EXPECT_TRUE(k->isValid(now + 3h));
}
