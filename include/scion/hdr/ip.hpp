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

#include <array>
#include <concepts>
#include <cstdint>
#include <format>


namespace scion {
namespace hdr {

enum class IPProto : std::uint8_t
{
    ICMP   = 1,
    TCP    = 6,
    UDP    = 17,
    ICMPv6 = 58,
};

/// \brief IP version 4 header without options.
class IPv4
{
public:
    enum class Flags : std::uint8_t
    {
        MoreFragments = 1 << 0,
        DontFragment  = 1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static constexpr std::uint_fast8_t version = 4;
    static constexpr std::uint_fast8_t ihl = 5; // IP without options

    FlagSet flags = Flags::DontFragment;
    std::uint8_t tos = 0;
    std::uint8_t ttl = 64;
    IPProto proto = IPProto::UDP;
    std::uint16_t len = 0;
    std::uint16_t id = 1;
    std::uint16_t frag = 0;
    generic::IPAddress src = generic::IPAddress::UnspecifiedIPv4();
    generic::IPAddress dst = generic::IPAddress::UnspecifiedIPv4();

    /// \brief Computes the pseudo header checksum for higher-level protocols
    /// that need it.
    /// \param length Length field to include in the pseudo header.
    std::uint32_t checksum(std::uint16_t length) const
    {
        std::uint32_t sum = src.checksum() + dst.checksum();
        sum += (std::uint32_t)proto;
        sum += length;
        return sum;
    }

    std::size_t size() const { return 4 * ihl; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if constexpr (Stream::IsReading) {
            std::span<const std::byte> hdr;
            if (!stream.lookahead(hdr, 20, err)) return err.propagate();
            std::uint16_t c = details::internetChecksum(hdr);
            if ((std::uint16_t)(~c)) return err.error("incorrect IP checksum");
        }
        auto ver = version;
        if (!stream.serializeBits(ver, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (ver != version) return err.error("invalid IP version");
        }
        auto hdrLen = ihl;
        if (!stream.serializeBits(hdrLen, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (hdrLen < 5) return err.error("invalid IP header");
            if (hdrLen > 5) return err.error("IP options not supported");
        }
        if (!stream.serializeByte(tos, err)) return err.propagate();
        if (!stream.serializeUint16(len, err)) return err.propagate();
        if (!stream.serializeUint16(id, err)) return err.propagate();
        if (!stream.serializeBits(flags.ref(), 3, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if ((std::uint8_t)flags & (1 << 2)) return err.error("invalid IP header");
        }
        if (!stream.serializeBits(frag, 13, err)) return err.propagate();
        if (!stream.serializeByte(ttl, err)) return err.propagate();
        if (!stream.serializeByte((std::uint8_t&)proto, err)) return err.propagate();
        std::uint16_t chksum = 0;
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        if (!src.serialize(stream, true, err)) return err.propagate();
        if (!dst.serialize(stream, true, err)) return err.propagate();
        if constexpr (Stream::IsWriting) {
            std::span<const std::byte> hdr;
            if (!stream.lookback(hdr, 20, err)) return err.propagate();
            chksum = details::internetChecksum(hdr);
            if (!stream.updateChksum(chksum, 8, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ IPv4 ]###\n");
        out = formatIndented(out, indent, "tos   = {}\n", tos);
        out = formatIndented(out, indent, "len   = {}\n", len);
        out = formatIndented(out, indent, "id    = {}\n", id);
        out = formatIndented(out, indent, "flags = {}\n", flags);
        out = formatIndented(out, indent, "ttl   = {}\n", ttl);
        out = formatIndented(out, indent, "proto = {}\n", (unsigned)proto);
        out = formatIndented(out, indent, "src   = {}\n", src);
        out = formatIndented(out, indent, "dst   = {}\n", dst);
        return out;
    }
};

inline IPv4::FlagSet operator|(IPv4::Flags lhs, IPv4::Flags rhs)
{
    return IPv4::FlagSet(lhs) | rhs;
}

/// \brief IP version 6.
class IPv6
{
public:
    static constexpr std::uint_fast8_t version = 6;

    std::uint8_t tc = 0;
    std::uint8_t hlim = 64;
    IPProto nh = IPProto::UDP;
    std::uint16_t plen = 0;
    std::uint32_t fl = 0;
    generic::IPAddress src = generic::IPAddress::UnspecifiedIPv6();
    generic::IPAddress dst = generic::IPAddress::UnspecifiedIPv6();

    /// \brief Computes the pseudo header checksum for higher-level protocols
    /// that need it.
    /// \param length Length field to include in the pseudo header.
    std::uint32_t checksum(std::uint16_t length) const
    {
        std::uint32_t sum = src.checksum() + dst.checksum() + length;
        sum += (std::uint32_t)nh;
        return sum;
    }

    std::size_t size() const { return 40; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto ver = version;
        if (!stream.serializeBits(ver, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (ver != version) return err.error("invalid IP version");
        }
        if (!stream.serializeByte(tc, err)) return err.propagate();
        if (!stream.serializeBits(fl, 20, err)) return err.propagate();
        if (!stream.serializeUint16(plen, err)) return err.propagate();
        if (!stream.serializeByte((std::uint8_t&)nh, err)) return err.propagate();
        if (!stream.serializeByte(hlim, err)) return err.propagate();
        if (!src.serialize(stream, false, err)) return err.propagate();
        if (!dst.serialize(stream, false, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ IPv6 ]###\n");
        out = formatIndented(out, indent, "tc   = {}\n", tc);
        out = formatIndented(out, indent, "fl   = {}\n", fl);
        out = formatIndented(out, indent, "plen = {}\n", plen);
        out = formatIndented(out, indent, "nh   = {}\n", (unsigned)nh);
        out = formatIndented(out, indent, "hlim = {}\n", hlim);
        out = formatIndented(out, indent, "src  = {}\n", src);
        out = formatIndented(out, indent, "dst  = {}\n", dst);
        return out;
    }
};

class ICMP
{
public:
    enum class Type : std::uint8_t
    {
        EchoReply       = 0,
        DestUnreachable = 3,
        EchoRequest     = 8,
        TimeExceeded    = 11,
        ParamProblem    = 12,
    };

    Type type = Type::EchoRequest;
    std::uint8_t code = 0;
    std::uint16_t chksum = 0;
    std::uint16_t param1 = 0;
    std::uint16_t param2 = 0;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint16_t)type) << 8;
        sum += (std::uint32_t)code;
        return sum + chksum + param1 + param2;
    }

    std::size_t size() const { return 8; }

    /// \brief Compute this header's contribution to the flow label.
    std::uint32_t flowLabel() const { return 0; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if (!stream.serializeByte(code, err)) return err.propagate();
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        if (!stream.serializeUint16(param1, err)) return err.propagate();
        if (!stream.serializeUint16(param2, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ICMP ]###\n");
        out = formatIndented(out, indent, "type   = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "code   = {}\n", code);
        out = formatIndented(out, indent, "chksum = {}\n", chksum);
        out = formatIndented(out, indent, "param1 = {}\n", param1);
        out = formatIndented(out, indent, "param2 = {}\n", param2);
        return out;
    }
};

class ICMPv6
{
public:
    enum class Type : std::uint8_t
    {
        DstUnreachable = 1,
        PacketTooBig   = 2,
        TimeExceeded   = 3,
        ParamProblem   = 4,
        EchoRequest    = 128,
        EchoReply      = 129,
    };

    Type type = Type::EchoRequest;
    std::uint8_t code = 0;
    std::uint16_t chksum = 0;
    std::uint16_t param1 = 0;
    std::uint16_t param2 = 0;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint16_t)type) << 8;
        sum += (std::uint32_t)code;
        return sum + chksum + param1 + param2;
    }

    std::size_t size() const { return 8; }

    /// \brief Compute this header's contribution to the flow label.
    std::uint32_t flowLabel() const { return 0; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if (!stream.serializeByte(code, err)) return err.propagate();
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        if (!stream.serializeUint16(param1, err)) return err.propagate();
        if (!stream.serializeUint16(param2, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ICMPv6 ]###\n");
        out = formatIndented(out, indent, "type   = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "code   = {}\n", code);
        out = formatIndented(out, indent, "chksum = {}\n", chksum);
        out = formatIndented(out, indent, "param1 = {}\n", param1);
        out = formatIndented(out, indent, "param2 = {}\n", param2);
        return out;
    }
};

} // namespace hdr
} // namespace scion
