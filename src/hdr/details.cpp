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

#if __AVX2__
#include <emmintrin.h>
#include <immintrin.h>
#endif

#include <algorithm>
#include <array>


namespace scion {
namespace hdr {
namespace details {

std::uint16_t onesComplementChecksumScalar(std::span<const std::byte> buffer, std::uint32_t inital)
{
    using std::uint16_t;
    using std::uint32_t;
    uint32_t sum = inital;
    auto sizeWords = buffer.size() / 2;
    std::span<const uint16_t> words(reinterpret_cast<const uint16_t*>(buffer.data()), sizeWords);
    for (auto word : words) {
        sum += std::uint32_t(scion::details::byteswapBE(word));
    }
    if (buffer.size() > 2*sizeWords) {
        sum += std::uint32_t(buffer[buffer.size()-1]) << 8;
    }
    while ((sum & ~0xffffu) != 0) {
        sum = (sum >> 16) + (sum & 0xffffu);
    }
    return std::uint16_t(sum);
}

#if __AVX2__
std::uint16_t onesComplementChecksumAVX(std::span<const std::byte> buffer, std::uint32_t inital)
{
    using std::byte;
    using std::uint16_t;
    using std::uint32_t;
    using std::uintptr_t;

    const auto size = buffer.size();
    uint32_t sum = inital;

    auto ptr = reinterpret_cast<uintptr_t>(buffer.data());
    if (ptr % 2 != 0) {
        // buffer is not word aligned, fall back to scalar implementation
        return onesComplementChecksumScalar(buffer, inital);
    }

    // Process unaligned data from beginning of the buffer
    auto align = std::min(-ptr & (uintptr_t)15, size);
    for (uintptr_t i = 0; i < (align / 2); ++i) {
        uint16_t word = reinterpret_cast<const uint16_t*>(ptr)[i];
        sum += std::uint32_t(scion::details::byteswapBE(word));
    }

    // Process aligned data in 16 byte blocks
    auto lastBlock = reinterpret_cast<const byte*>(ptr + align) + ((size - align) & ~(uintptr_t)15);
    __m256i acc = _mm256_setzero_si256();
    static const __m128i mask = _mm_set_epi8( // swap adjacent bytes
        14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1
    );
    for (auto block = reinterpret_cast<const byte*>(ptr + align); block < lastBlock; block += 16) {
        __m128i a = _mm_load_si128(reinterpret_cast<const __m128i*>(block));
        a = _mm_shuffle_epi8(a, mask);
        acc = _mm256_add_epi32(acc, _mm256_cvtepu16_epi32(a));
    }
    alignas(32) std::array<uint32_t, 8> temp;
    _mm256_store_si256(reinterpret_cast<__m256i*>(temp.data()), acc);
    sum = std::ranges::fold_left(temp, sum, [] (uint32_t a, uint32_t b) { return a + b; });

    // Process remaining data
    auto remainder = ((size - align) & (uintptr_t)15);
    std::span<const uint16_t> tail(reinterpret_cast<const uint16_t*>(lastBlock), remainder / 2);
    for (auto word : tail) {
        sum += std::uint32_t(scion::details::byteswapBE(word));
    }
    if (size & 1) {
        sum += std::uint32_t(buffer[size-1]) << 8;
    }

    // Add carry for one's complement addition
    while ((sum & ~0xffffu) != 0) {
        sum = (sum >> 16) + (sum & 0xffffu);
    }
    return std::uint16_t(sum);
}
#endif // __AVX2__

} // namespace details
} // namespace hdr
} // namespace scion
