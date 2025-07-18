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

#include "proto/drkey/v1/drkey.pb.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>


namespace scion {
namespace drkey {

/// \brief A level 2 or level 3 DRKey.
class Key
{
public:
    using TimePoint = std::chrono::utc_clock::time_point;

    std::array<std::byte, 16> key;
    TimePoint epochBegin;
    TimePoint epochEnd;

public:
    Key() = default;

    Key(std::array<std::byte, 16> key, TimePoint epochBegin, TimePoint epochEnd)
        : key(std::move(key))
        , epochBegin(epochBegin)
        , epochEnd(epochEnd)
    {}

    Key(const std::byte pKey[16], TimePoint epochBegin, TimePoint epochEnd)
        : epochBegin(epochBegin)
        , epochEnd(epochEnd)
    {
        std::copy_n(pKey, key.size(), key.begin());
    }

    bool isValid(TimePoint at) const
    {
        return epochBegin <= at && at < epochEnd;
    }
};

} // namespace drkey
} // namespace scion
