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

#include "scion/bit_stream.hpp"
#include "scion/details/debug.hpp"
#include "scion/error_codes.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/hdr/scmp.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>
#include <span>
#include <variant>


namespace scion {

/// \brief Dummy transport layer options for protocols like UDP that don't have
/// option headers.
template <typename L4>
struct NoL4Opts
{
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, L4& l4, Error& err)
    {
        return true;
    }
};

// Specialize this template to bind header options to a transport herader type.
template <typename L4>
struct L4Opts
{
    using type = NoL4Opts<L4>;
};

/// \brief Parser for SCION packets that decodes the main SCION header, address
/// headers, and transport header. The path header, SCION extension headers, and
/// payload are located but not parsed.
/// \tparam L4 Expected transport header type.
template <typename L4>
struct ParsedPacket
{
    hdr::SCION sci;
    std::span<const std::byte> path;
    std::span<const std::byte> hbhOpts;
    std::span<const std::byte> e2eOpts;
    std::variant<hdr::SCMP, L4> l4;
    typename L4Opts<L4>::type l4opts; // L4 options, e.g., for TCP
    std::span<const std::byte> payload;

    template <typename Error = StreamError>
    bool parse(ReadStream& rs, Error& err)
    {
        if (!sci.serialize(rs, err)) return err.propagate();
        if (!rs.lookahead(path, sci.pathSize(), err)) return err.propagate();
        if (!rs.advanceBytes(sci.pathSize(), err)) return err.propagate();
        hdr::ScionProto nh = sci.nh;
        if (nh == hdr::ScionProto::HBHOpt) {
            hdr::HopByHopOpts hbh;
            if (!hbh.serialize(rs, err)) return err.propagate();
            if (!rs.lookahead(hbhOpts, hbh.optionSize(), err)) return err.propagate();
            if (!rs.advanceBytes(hbh.optionSize(), err)) return err.propagate();
            nh = hbh.nh;
        }
        if (nh == hdr::ScionProto::E2EOpt) {
            hdr::EndToEndOpts e2e;
            if (!e2e.serialize(rs, err)) return err.propagate();
            if (!rs.lookahead(e2eOpts, e2e.optionSize(), err)) return err.propagate();
            if (!rs.advanceBytes(e2e.optionSize(), err)) return err.propagate();
            nh = e2e.nh;
        }
        if (nh == hdr::ScionProto::SCMP) {
            l4.template emplace<hdr::SCMP>();
            if (!std::get<hdr::SCMP>(l4).serialize(rs, err)) return err.propagate();
        } else if (nh == L4::PROTO) {
            l4.template emplace<L4>();
            if (!std::get<L4>(l4).serialize(rs, err)) return err.propagate();
            if (!l4opts.serialize(rs, std::get<L4>(l4), err)) return err.propagate();
        } else {
            return err.error("unexpected transport header");
        }
        if (!rs.lookahead(payload, ReadStream::npos, err)) return err.propagate();
        [[maybe_unused]] bool res = rs.seek(ReadStream::npos, 0);
        assert(res);
        return true;
    }

    /// \brief Compute the checksum of the (inner, not underlay) L4 header.
    std::uint16_t checksum() const
    {
        auto nh = hdr::ScionProto(0);
        std::uint32_t checksum = 0;
        std::visit([&](auto&& arg) -> auto {
            nh = std::remove_reference<decltype(arg)>::type::PROTO;
            checksum = arg.checksum();
        }, l4);
        auto hbhSize = (std::uint16_t)hbhOpts.size();
        auto e2eSize = (std::uint16_t)e2eOpts.size();
        auto len = (std::uint16_t)(sci.plen - hbhSize - e2eSize);
        len -= (std::uint16_t)(2 * (hbhSize > 0) + 2 * (e2eSize > 0));
        checksum += sci.checksum(len, nh);
        return hdr::details::internetChecksum(payload, checksum);
    }
};

} // namespace scion
