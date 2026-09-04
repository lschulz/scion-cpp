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

#pragma once

#include <scion/path/decoded_scion.hpp>


namespace scion {
namespace idint {

/// \brief Returns a function that maps hop field indices to AS interfaces along
/// a standard SCION path.
/// \param path Decoded SCION path.
/// \param reverse Internally reverse the path. This is faster than reversing
/// the full decoded path.
/// \return A closure `f(std::uint8_t i) -> std::uint8_t` that maps hop field
/// indices to AS interfaces as represented by PATH_ATTRIBUTE_INTERFACES.
template <typename Alloc>
auto hopFieldToInterfaceIdx(const DecodedScionPath<Alloc>& path, bool reverse = false)
{
    using namespace scion::hdr;
    auto meta = path.metaHeader();
    auto info = path.infoFields();

    // Reversing the path permutes the indices
    std::uint32_t P[3] = {0, 1, 2};
    if (reverse) {
        if (info.size() == 2)
            std::swap(P[0], P[1]);
        else if (info.size() == 3)
            std::swap(P[0], P[2]);
    }

    // Calculate hop field indices at which a segment change occurs
    std::uint8_t segChange[3] = {meta.segLen[P[0]], meta.segLen[P[1]], meta.segLen[P[2]]};
    segChange[1] = segChange[0] + segChange[1];
    segChange[2] = segChange[1] + segChange[2];

    // Special case: Ignore peering crossover as those have one hop field less
    for (std::size_t i = 0; i < info.size() - 1; ++i) {
        if (info[P[i]].flags & InfoField::Flags::Peering)
            segChange[i] = segChange[i+1];
    }

    return [=](std::uint8_t i) -> std::uint8_t {
        if (i < segChange[0]) {
            return std::uint8_t(i);
        } else if (i < segChange[1]) {
            return std::uint8_t(i - 1);
        } else {
            return std::uint8_t(i - 2);
        }
    };
}

} // namespace idint
} // namespace scion
