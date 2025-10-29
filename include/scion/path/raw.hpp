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

#include "scion/addr/isd_asn.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/path/digest.hpp"
#include "scion/path/raw_hop_range.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <format>
#include <iterator>
#include <ranges>
#include <span>
#include <span>


namespace scion {
namespace details {
std::error_code reversePathInPlace(hdr::PathType type, std::span<std::byte> path);
} // namespace details

/// \brief Buffer holding a raw path in its data plane format. The path is
/// stored in an internal array, no memory is allocated on the heap.
class RawPath
{
public:
    using Expiry = std::chrono::utc_clock::time_point;

public:
    /// \brief Maximum path size in bytes. Calculated from the the maximum
    /// SCION header size (4 * 255 = 1020 byte) minus the mandatory common
    /// and address headers (36 byte).
    static constexpr std::size_t MAX_SIZE = 984;

private:
    IsdAsn m_source, m_destination;
    hdr::PathType m_type = hdr::PathType::Empty;
    std::size_t m_size = 0;
    mutable std::optional<PathDigest> m_digest;
    std::array<std::byte, MAX_SIZE> m_path = {};

public:
    /// \brief Construct an empty path.
    RawPath() = default;

    /// \brief Construct from raw header bytes.
    RawPath(IsdAsn source, IsdAsn destination, hdr::PathType type, std::span<const std::byte> data)
    {
        assign(source, destination, type, data);
    }

    void assign(IsdAsn source, IsdAsn destination, hdr::PathType type, std::span<const std::byte> data)
    {
        if (data.size() > MAX_SIZE) {
            throw std::logic_error("supplied path is longer than the theoretical maximum");
        }
        m_source = source;
        m_destination = destination;
        m_type = type;
        m_size = data.size();
        m_digest = std::nullopt;
        std::copy(data.begin(), data.end(), m_path.begin());
    }

    bool operator==(const RawPath& other) const
    {
        return m_source == other.m_source && m_destination == other.m_destination
            && m_type == other.m_type
            && std::ranges::equal(encoded(), other.encoded());
    }

    /// \brief Encode a path for use in the data plane.
    template <typename Path, typename Error>
    bool encode(const Path& path, Error& err)
    {
        m_source = path.firstAS();
        m_destination = path.lastAS();
        m_type = path.type();
        m_digest = std::nullopt;
        WriteStream ws(m_path);
        if (!const_cast<Path&>(path).serialize(ws, err)) err.propagate();
        m_size = ws.getPos().first;
        return true;
    }

    /// \brief Returns the path type.
    hdr::PathType type() const { return m_type; }

    /// \brief Determines the path's expiry time by parsing the raw info and hop
    /// fields.
    Expiry expiry() const;

    /// \brief Returns true is the path is an empty path for AS-internal
    /// communication.
    bool empty() const { return m_type == hdr::PathType::Empty; }

    /// \brief Returns the encoded path length in bytes.
    std::size_t size() const { return m_size; }

    /// \brief Returns the first AS on the path (the source).
    IsdAsn firstAS() const { return m_source; }

    /// \brief Returns the last AS on the path (the destination).
    IsdAsn lastAS() const { return m_destination; }

    /// \brief Iterate over hops as pairs of ingress and egress interface
    /// ID in path direction (not path construction direction).
    /// \warning Only empty and standard SCION paths are supported. If the
    /// path is not on of the supported types, an empty range is returned.
    /// \warning Might return an incomplete path if the raw data is invalid
    /// or corrupted.
    auto hops() const
    {
        return RawHopRange<RawPath>(*this);
    }

    /// \brief Returns the path digest. The value is cached making this method
    /// cheap to call repeatedly. Calling this method concurrently requires
    /// external synchronization.
    PathDigest digest() const;

    /// \brief Returns the path encoded for use in the data plane.
    std::span<const std::byte> encoded() const
    {
        return std::span<const std::byte>(m_path.data(), m_path.data() + m_size);
    }

    /// \brief Turn this path into its reverse without fully decoding it.
    /// Supported path types are Empty and SCION paths.
    std::error_code reverseInPlace()
    {
        auto err = details::reversePathInPlace(m_type,
            std::span<std::byte>(m_path.data(), m_path.data() + m_size));
        if (err) return err;
        std::swap(m_source, m_destination);
        m_digest = std::nullopt;
        return ErrorCode::Ok;
    }

    friend std::ostream& operator<<(std::ostream& stream, const RawPath& rp);
};

} // namespace scion

template <>
struct std::formatter<scion::RawPath>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::RawPath& rp, auto& ctx) const
    {
        if (rp.empty()) return std::format_to(ctx.out(), "empty");
        auto out = std::format_to(ctx.out(), "{} ", rp.firstAS());
        for (auto [egr, igr] : rp.hops()) {
            out = std::format_to(out, "{}>{} ", egr, igr);
        }
        return std::format_to(out, "{}", rp.lastAS());
    }
};

template <>
struct std::hash<scion::RawPath>
{
    std::size_t operator()(const scion::RawPath& rp) const noexcept
    {
        return std::hash<scion::PathDigest>{}(rp.digest());
    }
};
