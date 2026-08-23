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

#include "scion/details/protobuf_time.hpp"

#include "gtest/gtest.h"


TEST(Protobuf, timepointFromProtobuf)
{
    using namespace scion;
    using namespace std::chrono;
    namespace pb = google::protobuf;

    pb::Timestamp protoTs;
    auto ts = details::timepointFromProtobuf(protoTs);
    EXPECT_EQ(ts, system_clock::time_point{});

    protoTs.set_seconds(1'712'407'990);
    protoTs.set_nanos(999'999'000);
    ts = details::timepointFromProtobuf(protoTs);
    EXPECT_EQ(
        std::chrono::duration_cast<std::chrono::nanoseconds>(ts.time_since_epoch()).count(),
        1'712'407'990'999'999'000);
}

TEST(Protobuf, durationFromProtobuf)
{
    using namespace scion;
    namespace pb = google::protobuf;

    pb::Duration protoDur;
    auto d = details::durationFromProtobuf(protoDur);
    EXPECT_EQ(d, d.zero());

    protoDur.set_seconds(1);
    protoDur.set_nanos(999'999'999);
    d = details::durationFromProtobuf(protoDur);
    EXPECT_EQ(d.count(), 1999'999'999);
}

TEST(Protobuf, timepointToProtobuf)
{
    using namespace scion;
    using namespace std::chrono;
    using namespace std::chrono_literals;

    system_clock::time_point tp(duration_cast<system_clock::duration>(1'712'407'990'999'999'000ns));

    EXPECT_EQ(details::timepointSeconds(tp), 1'712'407'990);
    EXPECT_EQ(details::timepointNanos(tp), 999'999'000);
}
