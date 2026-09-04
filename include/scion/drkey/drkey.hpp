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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <span>


namespace scion {

enum class DRKeyProtocol : std::uint_fast16_t
{
    Generic = 0,
    SCMP = 1,
    IDINT = 2,
};

namespace drkey {

using TimePoint = std::chrono::system_clock::time_point;

/// \brief A level 2 or level 3 DRKey.
class Key
{
public:
    std::array<std::byte, 16> key = {};
    TimePoint epochBegin;
    TimePoint epochEnd;

public:
    Key() = default;

    Key(std::span<std::byte, 16> sKey, TimePoint epochBegin, TimePoint epochEnd)
        : epochBegin(epochBegin)
        , epochEnd(epochEnd)
    {
        std::ranges::copy(sKey, key.begin());
    }

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
