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

#include "scion/extensions/idint.hpp"

#include "gtest/gtest.h"

using namespace scion::idint;
using namespace std::chrono;
using namespace std::chrono_literals;
using system_point = system_clock::time_point;
using system_duration = system_clock::duration;
using std::int64_t;
using std::uint64_t;


static void expectSourceTsSuccess(int64_t nanos, int64_t delay, int64_t expected)
{
    const auto now = system_point{duration_cast<system_duration>(nanoseconds{nanos})};
    const auto exp = system_point{duration_cast<system_duration>(nanoseconds{expected})};
    auto res = details::getSourceTimestamp(now, nanos - delay);
    EXPECT_TRUE(res);
    if (res) {
        EXPECT_EQ(*res, exp);
    }
}

static void expectSourceTsFailure(uint64_t nanos, uint64_t delay)
{
    const auto now = system_point{duration_cast<system_duration>(nanoseconds{nanos})};
    auto res = details::getSourceTimestamp(now, nanos - delay);
    EXPECT_FALSE(res);
}

TEST(IdIntDetails, getSourceTimestamp)
{
    const std::uint64_t mask = 0xffff'ffff'ffff;
    const std::int64_t sec = 1'000'000'000;
    const auto now = duration_cast<nanoseconds>(1794147815s).count();
    const auto afterWrap = (nanoseconds{mask} + 1s).count();

    // instant
    expectSourceTsSuccess(now, 0, now);

    // valid delay
    expectSourceTsSuccess(now, MAX_AGE, now - MAX_AGE);

    // valid delay + tolerance
    expectSourceTsSuccess(now, MAX_AGE + CLOCK_TOLERANCE, now - MAX_AGE - CLOCK_TOLERANCE);

    // too far in the past
    expectSourceTsFailure(now, 2 * MAX_AGE);

    // wraparound valid
    expectSourceTsSuccess(afterWrap, 5 * sec, afterWrap - 5 * sec);

    // wraparound too far in the past
    expectSourceTsFailure(afterWrap, 2 * MAX_AGE);

    // source in the future valid
    expectSourceTsSuccess(now, -CLOCK_TOLERANCE, now);

    // source in the future invalid
    expectSourceTsFailure(now, -CLOCK_TOLERANCE - sec);
}
