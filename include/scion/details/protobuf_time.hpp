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

#pragma once

#include <google/protobuf/timestamp.pb.h>
#include <google/protobuf/duration.pb.h>

#include <chrono>


namespace scion {
namespace details {

/// \brief Get Unix timestamp from protobuf time.
inline std::chrono::system_clock::time_point timepointFromProtobuf(google::protobuf::Timestamp ts)
{
    using namespace std::chrono;
    auto seconds = ts.seconds();
    auto nanos = ts.nanos();
    if (seconds < 0 || nanos < 0) return system_clock::time_point{};
    return system_clock::time_point(duration_cast<system_clock::duration>(nanoseconds(
        static_cast<std::uint64_t>(seconds) * std::nano::den
        + static_cast<std::uint64_t>(nanos))));
}

inline std::chrono::nanoseconds durationFromProtobuf(google::protobuf::Duration duration)
{
    using namespace std::chrono;
    auto seconds = duration.seconds();
    auto nanos = duration.nanos();
    if (seconds < 0 || nanos < 0) return nanoseconds(0);
    return nanoseconds(
        static_cast<std::uint64_t>(seconds) * std::nano::den
        + static_cast<std::uint64_t>(nanos));
}

/// \brief Get seconds since the epoch from a Unix time point.
inline std::uint64_t timepointSeconds(std::chrono::system_clock::time_point t)
{
    using namespace std::chrono;
    return duration_cast<seconds>(t.time_since_epoch()).count();
}

/// \brief Get fractional seconds since the epoch from a Unix time point.
inline std::uint64_t timepointNanos(std::chrono::system_clock::time_point t)
{
    using namespace std::chrono;
    return duration_cast<nanoseconds>(t.time_since_epoch()).count() % std::nano::den;
}

} // namespace details
} // namespace scion
