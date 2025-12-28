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

#include "scion/details/bit.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <format>
#include <span>


namespace scion {
namespace hdr {
namespace details {

template <std::output_iterator<char> OutIter, typename... Args>
inline OutIter formatIndented(
    OutIter out, int indent, std::format_string<Args...> fmt, Args&&... args)
{
    out = std::format_to(out, "{:{}}", "", indent);
    return std::format_to(out, fmt, std::forward<Args>(args)...);
}

auto formatBytes(auto out, std::span<const std::byte> bytes)
{
    std::size_t i = 0;
    for (auto b : bytes) {
        if (i++ != 0) *(out++) = ':';
        out = std::format_to(out, "{:02x}", (unsigned char)b);
    }
    return out;
}

std::uint16_t onesComplementChecksumScalar(std::span<const std::byte> buffer, std::uint32_t inital);
#if __AVX2__
std::uint16_t onesComplementChecksumAVX(std::span<const std::byte> buffer, std::uint32_t inital);
#endif

/// \brief Calculate the one's complement sum of 16-bit words.
/// \param buffer Input data the sum is computed over.
/// \param inital Extra value added into the sum in host byte order.
/// \return Sum in host byte order.
inline std::uint16_t onesComplementChecksum(
    std::span<const std::byte> buffer, std::uint32_t inital = 0)
{
#if __AVX2__
    return onesComplementChecksumAVX(buffer, inital);
#else
    return onesComplementChecksumScalar(buffer, inital);
#endif
}

/// \brief Calculate the 16-bit one's complement of the one's complement sum of
/// the given buffer. The result is returned in host byte order. A sum of zero
/// is replaced by 0xffff.
/// \param buffer Input data the sum is computed over.
/// \param inital Extra value added into the sum in host byte order.
/// \return Checksum in host byte order.
inline std::uint16_t internetChecksum(std::span<const std::byte> buffer, std::uint32_t inital = 0)
{
    std::uint16_t sum = ~onesComplementChecksum(buffer, inital);
    if (sum == 0) sum = 0xffff;
    return sum;
}

/// \brief Update an internet checksum.
/// \param chksum Header checksum in host byte order.
/// \param add Sum of 16-bit header words that are added to the checksum.
/// \param sub Sum of 16-bit header words that are subtracted from the checksum.
/// \return Updated header checksum in host byte order.
inline std::uint16_t updateInternetChecksum(std::uint16_t chksum, std::uint32_t add, std::uint32_t sub)
{
    auto sum = (std::uint32_t)(~chksum & 0xffffu);
    if (sum == 0xffffu) sum = 0;
    sum += add;
    while ((sum & ~0xffffu) != 0) {
        sum = (sum >> 16) + (sum & 0xffffu);
    }
    sum += ~sub;
    while ((sum & ~0xffffu) != 0) {
        sum = (sum >> 16) + (sum & 0xffffu);
    }
    if (sum != 0xffff) sum = (~sum & 0xffffu);
    return (std::uint16_t)sum;
};

} // namespace details
} // namespace hdr
} // namespace scion
