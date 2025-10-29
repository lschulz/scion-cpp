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

#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/flags.hpp"
#include "scion/hdr/details.hpp"
#include "scion/hdr/proto.hpp"
#include "scion/murmur_hash3.h"

#include <array>
#include <concepts>
#include <cstdint>
#include <format>


namespace scion {
namespace hdr {

/// \brief UDP header.
class UDP
{
public:
    static constexpr ScionProto PROTO = ScionProto::UDP;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint16_t len = 0;
    std::uint16_t chksum = 0;

    /// \brief Compute the UDP checksum taking the current value of the chksum
    /// field into account. To calculate the checksum from scratch, set chksum
    /// to zero before calling this method.
    std::uint32_t checksum() const
    {
        return sport + dport + len + chksum;
    }

    std::size_t size() const { return 8; }

    void setPayload(std::span<const std::byte> payload)
    {
        len = (std::uint16_t)(size() + payload.size());
    }

    /// \brief Compute this header's contribution to the flow label.
    std::uint32_t flowLabel() const
    {
        auto key = (std::uint32_t(PROTO) << 16)
        | (std::uint32_t(sport) << 8)
        | (std::uint32_t)(dport);
        std::uint32_t hash;
        scion::details::MurmurHash3_x86_32(&key, sizeof(key), 0, &hash);
        return hash;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(sport, err)) return err.propagate();
        if (!stream.serializeUint16(dport, err)) return err.propagate();
        if (!stream.serializeUint16(len, err)) return err.propagate();
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ UDP ]###\n");
        out = formatIndented(out, indent, "sport  = {}\n", sport);
        out = formatIndented(out, indent, "dport  = {}\n", dport);
        out = formatIndented(out, indent, "len    = {}\n", len);
        out = formatIndented(out, indent, "chksum = {}\n", chksum);
        return out;
    }
};

} // namespace hdr
} // namespace scion
