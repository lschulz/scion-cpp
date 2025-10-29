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

#include "scion/details/bit.hpp"
#include "scion/murmur_hash3.h"
#include "scion/path/digest.hpp"
#include "scion/path/path.hpp"
#include "scion/path/raw.hpp"

#include <cstring>
#include <ostream>
#include <span>

using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;


namespace scion {
namespace details {

PathDigest computeDigest(IsdAsn src, std::span<std::pair<std::uint16_t, std::uint16_t>> path)
{
    uint64_t haddr[2] = {};
    uint64_t hpath[2] = {};
    auto seed = randomSeed();
    auto ia = (uint64_t)src;
    MurmurHash3_x64_128(&ia, sizeof(ia), seed, &haddr);
    MurmurHash3_x64_128(path.data(), (int)(path.size()), seed, &path);
    return PathDigest(haddr[0] ^ hpath[0], haddr[1] ^ hpath[1]);
}

std::error_code reversePathInPlace(hdr::PathType type, std::span<std::byte> path)
{
    const size_t META_SIZE = 4;
    const size_t INF_SIZE = 8;
    const size_t HF_SIZE = 12;

    if (type == hdr::PathType::Empty) return ErrorCode::Ok;
    if (type != hdr::PathType::SCION) return ErrorCode::NotImplemented;

    auto len = path.size();
    if (len < 4) return ErrorCode::InvalidArgument;

    uint32_t pathMeta = 0;
    std::memcpy(&pathMeta, path.data(), META_SIZE);
    pathMeta = byteswapBE(pathMeta);

    uint32_t seg2 = pathMeta & 0x3f;
    uint32_t seg1 = (pathMeta >> 6) & 0x3f;
    uint32_t seg0 = (pathMeta >> 12) & 0x3f;
    uint32_t res = (pathMeta >> 18) & 0x3f;
    uint32_t currHop = (pathMeta >> 24) & 0x3f;
    uint32_t currInf = (pathMeta >> 30) & 0x03;

    uint32_t numInf = (seg0 > 0) + (seg1 > 0) + (seg2 > 0);
    uint32_t numHop = seg0 + seg1 + seg2;
    if (numInf < 1) return ErrorCode::InvalidArgument;
    if (numHop < 2 || numHop > 64) return ErrorCode::InvalidArgument;
    if (len != META_SIZE + numInf * INF_SIZE + numHop * HF_SIZE) {
        return ErrorCode::InvalidArgument;
    }

    // Reverse order of info fields
    auto* inf = &path[META_SIZE];
    if (numInf > 1) {
        std::byte temp[INF_SIZE];
        memcpy(&temp, inf, INF_SIZE);
        memcpy(inf, &inf[(numInf-1) * INF_SIZE], INF_SIZE);
        memcpy(&inf[(numInf-1) * INF_SIZE], &temp, INF_SIZE);
    }

    // Reverse cons dir flag
    for (size_t i = 0; i < numInf; ++i) {
        inf[i * INF_SIZE] ^= std::byte{1};
    }

    // Reverse order of hop fields
    auto* hfs = &path[META_SIZE + numInf * INF_SIZE];
    for (size_t i = 0, j = numHop-1; i < j; ++i, --j) {
        std::byte temp[HF_SIZE];
        memcpy(&temp, &hfs[i * HF_SIZE], HF_SIZE);
        memcpy(&hfs[i * HF_SIZE], &hfs[j * HF_SIZE], HF_SIZE);
        memcpy(&hfs[j * HF_SIZE], &temp, HF_SIZE);
    }

    // Update path meta header
    currInf = numInf - currInf - 1;
    currHop = numHop - currHop - 1;

    if (numInf == 2) std::swap(seg0, seg1);
    else if (numInf == 3) std::swap(seg0, seg2);

    pathMeta = seg2 | (seg1 << 6) | (seg0 << 12) | (res << 18) | (currHop << 24) | (currInf << 30);
    pathMeta = byteswapBE(pathMeta);
    memcpy(path.data(), &pathMeta, META_SIZE);

    return ErrorCode::Ok;
}

} // namespace details

std::ostream& operator<<(std::ostream& stream, const PathDigest& pd)
{
    stream << std::format("{}", pd);
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const RawPath& rp)
{
    stream << std::format("{}", rp);
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const Path& path)
{
    stream << std::format("{}", path);
    return stream;
}

auto RawPath::expiry() const -> Expiry
{
    using namespace std::chrono;
    using namespace scion::hdr;
    PathMeta meta;
    std::array<InfoField, 3> ifs;
    HopField hop;
    auto expiry = Expiry::max();

    if (m_type != PathType::SCION)
        return expiry;

    ReadStream rs(m_path);
    if (!meta.serialize(rs, NullStreamError)) return expiry;
    auto segments = meta.segmentCount();
    for (size_t i = 0; i < segments; ++i) {
        if (!ifs[i].serialize(rs, NullStreamError)) return expiry;
    }
    auto hops = meta.hopFieldCount();
    for (size_t i = 0; i < hops; ++i) {
        if (!hop.serialize(rs, NullStreamError)) return expiry;
        if (i < meta.segLen[0]) {
            expiry = std::min(expiry, Expiry(seconds(ifs[0].timestamp + hop.relativeExpiry())));
        } else if (i < meta.segLen[0] + meta.segLen[1]) {
            expiry = std::min(expiry, Expiry(seconds(ifs[1].timestamp + hop.relativeExpiry())));
        } else {
            expiry = std::min(expiry, Expiry(seconds(ifs[2].timestamp + hop.relativeExpiry())));
        }
    }
    return expiry;
}

PathDigest RawPath::digest() const
{
    if (!m_digest) {
        std::array<std::pair<uint16_t, uint16_t>, 64> buffer;
        size_t i = 0;
        for (auto hop : hops()) {
            if (i >= buffer.size()) break;
            buffer[i++] = hop;
        }
        m_digest = details::computeDigest(m_source, buffer);
    }
    return *m_digest;
}

} // namespace scion
