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

#include "scion/error_codes.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/path/digest.hpp"

#include <array>
#include <ostream>
#include <ranges>
#include <system_error>
#include <vector>


namespace scion {
namespace details {
PathDigest computeDigest(IsdAsn src, std::span<std::pair<std::uint16_t, std::uint16_t>> path);
} // namespace details

class ScionHopRange;

/// \brief A standard SCION path decoded from raw headers without any metadata.
template <typename Alloc = std::allocator<std::byte>>
class DecodedScionPath
{
private:
    using InfoVec = std::vector<hdr::InfoField,
        typename std::allocator_traits<Alloc>::template rebind_alloc<hdr::InfoField>>;
    using HopVec = std::vector<hdr::HopField,
        typename std::allocator_traits<Alloc>::template rebind_alloc<hdr::HopField>>;

    IsdAsn source, destination;
    hdr::PathMeta meta;
    InfoVec ifs;
    HopVec hfs;

public:
    DecodedScionPath(IsdAsn source, IsdAsn destination, Alloc alloc = Alloc())
        : source(source), destination(destination), ifs(alloc), hfs(alloc)
    {}

    template <typename OtherAlloc>
    bool operator==(const DecodedScionPath<OtherAlloc>& other) const
    {
        return source == other.source && destination == other.destination
            && meta == other.meta
            && std::ranges::equal(ifs, other.ifs)
            && std::ranges::equal(hfs, other.hfs);
    }

    /// \brief Returns the path type.
    hdr::PathType type() const { return hdr::PathType::SCION; }

    /// \brief Returns the first AS on the path (the source).
    IsdAsn firstAS() const { return source; }

    /// \brief Returns the last AS on the path (the destination).
    IsdAsn lastAS() const { return destination; }

    /// \brief Returns the path meta header.
    const hdr::PathMeta& metaHeader() const { return meta; }

    /// \brief Gets a view of the info fields.
    auto infoFields() const { return std::views::all(ifs); }
    auto infoFields() { return std::views::all(ifs); }

    /// \brief Gets a view of the hop fields.
    auto hopFields() const { return std::views::all(hfs); }
    auto hopFields() { return std::views::all(hfs); }

    /// \brief Gets a view of the hop fields belonging to a certain segment.
    auto segment(std::size_t seg) const
    {
        return std::ranges::subrange(
            hfs.begin() + meta.segmentBegin(seg), hfs.end() + meta.segmentBegin(seg + 1));
    }

    /// \brief Iterate over hops as pairs of ingress and egress interface
    /// ID in path direction (not path construction direction).
    auto hops() const
    {
        using namespace scion::hdr;
        using namespace std::views;

        std::uint64_t hopDir = 0, segChange = 0;
        unsigned sum = 0;
        for (auto&& [i, info] : enumerate(ifs)) {
            unsigned len = meta.segLen[i];
            if (info.flags[hdr::InfoField::Flags::ConsDir])
                hopDir |= (~(~0ull << len)) << sum;
            sum += len;
        }
        // special case: keep peering segment changes
        if (!ifs.empty() && !ifs[0].flags[hdr::InfoField::Flags::Peering]) {
            segChange |= (1ull << (meta.segLen[0] - 1));
            segChange |= (1ull << (meta.segLen[0] + meta.segLen[1] - 1));
        }

        auto takeIfId = [hopDir](auto pair) {
            auto&& [index, hf] = pair;
            if (hopDir & (1ull << index))
                return std::make_pair(hf.consIngress, hf.consEgress);
            else
                return std::make_pair(hf.consEgress, hf.consIngress);
        };

        auto combine = [](auto&& first, auto&& second) {
            return std::make_pair(first.second, second.first);
        };

        return enumerate(hfs)
            | transform(takeIfId)
            | adjacent_transform<2>(combine)
            | enumerate
            | filter([segChange] (auto p) { return (segChange & (1ull << std::get<0>(p))) == 0; })
            | elements<1>;
    }

    PathDigest digest() const
    {
        std::array<std::pair<std::uint16_t, std::uint16_t>, 64> buffer;
        std::size_t i = 0;
        for (auto hop : hops()) {
            if (i >= buffer.size()) break;
            buffer[i++] = hop;
        }
        return details::computeDigest(source, buffer);
    }

    /// \brief Returns the encoded path length in bytes.
    std::size_t size() const
    {
        return meta.size()
            + ifs.size() * hdr::InfoField::staticSize
            + hfs.size() * hdr::HopField::staticSize;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!meta.serialize(stream, err)) return err.propagate();

        // Info fields
        auto segments = meta.segmentCount();
        if constexpr (Stream::IsReading) ifs.resize(segments);
        for (std::size_t i = 0; i < segments; ++i) {
            if (!ifs[i].serialize(stream, err)) return err.propagate();
        }

        // Hop fields
        auto hops = meta.hopFieldCount();
        if constexpr (Stream::IsReading) hfs.resize(hops);
        for (std::size_t i = 0; i < hops; ++i) {
            if (!hfs[i].serialize(stream, err)) return err.propagate();
        }

        return true;
    }

    /// \brief Reverse this path.
    std::error_code reverseInPlace()
    {
        if (hfs.empty()) return ErrorCode::LogicError;
        std::swap(source, destination);

        // Reverse order of info fields
        auto numInf = ifs.size();
        if (numInf > 1) {
            std::swap(ifs.front(), ifs.back());
        }

        // Reverse cons dir flag
        for (auto& info : ifs) {
            info.flags ^= hdr::InfoField::Flags::ConsDir;
        }

        // Reverse order of hop fields
        auto numHop = hfs.size();
        for (size_t i = 0, j = numHop-1; i < j; ++i, --j) {
            std::swap(hfs[i], hfs[j]);
        }

        // Update path meta header
        meta.currInf = (std::uint8_t)(numInf - meta.currInf - 1);
        meta.currHf = (std::uint8_t)(numHop - meta.currHf - 1);

        if (numInf == 2) std::swap(meta.segLen[0], meta.segLen[1]);
        else if (numInf == 3) std::swap(meta.segLen[0], meta.segLen[2]);

        return ErrorCode::Ok;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        meta.print(out, indent);
        for (const auto& info: ifs)
            info.print(out, indent);
        for (const auto& hf : hfs)
            hf.print(out, indent);
        return out;
    }

    friend std::ostream& operator<<(std::ostream& stream, const DecodedScionPath<Alloc>& dp)
    {
        stream << std::format("{}", dp);
        return stream;
    }
};

} // namespace scion

template <typename Alloc>
struct std::formatter<scion::DecodedScionPath<Alloc>>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::DecodedScionPath<Alloc>& dp, auto& ctx) const
    {
        auto out = std::format_to(ctx.out(), "{} ", dp.firstAS());
        for (auto [egr, igr] : dp.hops()) {
            out = std::format_to(out, "{}>{} ", egr, igr);
        }
        return std::format_to(out, "{}", dp.lastAS());
    }
};

template <typename Alloc>
struct std::hash<scion::DecodedScionPath<Alloc>>
{
    std::size_t operator()(const scion::DecodedScionPath<Alloc>& dp) const noexcept
    {
        return std::hash<scion::PathDigest>{}(dp.digest());
    }
};
