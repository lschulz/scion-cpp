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

#include "scion/hdr/details.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <array>
#include <vector>

using std::uint32_t;
using std::size_t;


TEST(Checksum, InternetChecksum)
{
    using namespace scion::hdr::details;

    static const std::array<std::byte, 4> a = { 0x00_b, 0x00_b };
    EXPECT_EQ(internetChecksum(a), 0xffff);

    static const std::array<std::byte, 4> b = { 0xff_b, 0xff_b };
    EXPECT_EQ(internetChecksum(b), 0xffff);

    static const std::array<std::byte, 3> c = { 0xff_b, 0xff_b, 0xff_b };
    EXPECT_EQ(internetChecksum(c), 0x00ff);

    std::array<std::byte, 11> d;
    for (size_t i = 0; i < d.size(); ++i) d[i] = std::byte(i % 256);
    EXPECT_EQ(internetChecksum(d, 0), 0xe1e6);
    EXPECT_EQ(internetChecksum(d, 1), 0xe1e5);
}

#if __AVX2__
TEST(Checksum, OnesComplementAVX)
{
    using namespace scion::hdr::details;
    alignas(16) std::array<std::byte, 64> d;
    for (size_t i = 0; i < d.size(); ++i) d[i] = std::byte(i % 256);

    for (size_t offset = 0; offset < 16; offset += 2) {
        for (size_t size = 0; size < (64 - offset); ++size) {
            std::span<const std::byte> span(d.data() + offset, size);
            ASSERT_EQ(
                onesComplementChecksumScalar(span, (uint32_t)offset),
                onesComplementChecksumAVX(span, (uint32_t)offset)
            ) << "offset=" << offset << " size=" << size;
        }
    }
}
#endif // __AVX2__
