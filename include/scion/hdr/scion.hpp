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

#include "scion/addr/address.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/flags.hpp"
#include "scion/hdr/details.hpp"
#include "scion/hdr/proto.hpp"

#include <cstdint>


namespace scion {
namespace hdr {

enum class PathType : std::uint8_t
{
    Empty   = 0,
    SCION   = 1,
    OneHop  = 2,
    EPIC    = 3,
    Colibri = 4,
};

enum class OptType : std::uint8_t
{
    Pad1       = 0,
    PadN       = 1,
    SPAO       = 2,   // SCION Packet Authentication Option
    IdInt      = 253, // ID-INT main option (testing only)
    IdIntEntry = 254, // ID-INT stack entry (testing only)

};

/// \brief SCION common and address header. Does not include the path.
class SCION
{
public:
    static const std::uint_fast8_t version = 0;
    static const std::size_t minSize = 9 * 4;

    std::uint8_t qos = 0;
    std::uint8_t hlen = 9;
    ScionProto nh = ScionProto::UDP;
    PathType ptype = PathType::Empty;

    std::uint16_t plen = 0;
    std::uint32_t fl = 0;

    ScIPAddress dst;
    ScIPAddress src;

    bool operator==(const SCION&) const = default;

    /// \brief Computes the pseudo header checksum for upper-layer protocols
    /// that need it.
    /// \param length Length field to include in the pseudo header.
    /// \param nh Protocol identifier of the upper-layer protocol the
    /// checksum is computed for.
    std::uint32_t checksum(std::uint16_t length, ScionProto nh) const
    {
        std::uint32_t sum = dst.checksum() + src.checksum();
        sum += length;
        sum += (std::uint32_t)nh;
        return sum;
    }

    /// \brief Returns the size of the path header following this header.
    std::size_t pathSize() const { return 4 * hlen - size(); };

    std::size_t size() const { return 12 + dst.size() + src.size(); }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto ver = version;
        if (!stream.serializeBits(ver, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (ver != version) return err.error("unknown SCION version");
        }
        if (!stream.serializeByte(qos, err)) return err.propagate();
        if (!stream.serializeBits(fl, 20, err)) return err.propagate();
        if (!stream.serializeByte((std::uint8_t&)nh, err)) return err.propagate();
        if (!stream.serializeByte(hlen, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (hlen < (minSize / 4)) return err.error("invalid SCION header");
        }
        if (!stream.serializeUint16(plen, err)) return err.propagate();
        if (!stream.serializeByte((std::uint8_t&)ptype, err)) return err.propagate();
        HostAddrType dstType = AddressTraits<generic::IPAddress>::type(dst.host());
        HostAddrType srcType = AddressTraits<generic::IPAddress>::type(src.host());
        if (!stream.serializeBits((std::uint8_t&)dstType, 4, err)) return err.propagate();
        if (!stream.serializeBits((std::uint8_t&)srcType, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dstType != HostAddrType::IPv4 && dstType != HostAddrType::IPv6) {
                return err.error("unsupported host address type");
            }
            if (srcType != HostAddrType::IPv4 && srcType != HostAddrType::IPv6) {
                return err.error("unsupported host address type");
            }
        }
        if (!stream.advanceBytes(2, err)) return err.propagate();
        if (!dst.isdAsn().serialize(stream, err)) return err.propagate();
        if (!src.isdAsn().serialize(stream, err)) return err.propagate();
        if (!dst.host().serialize(stream, dstType == HostAddrType::IPv4, err))
            return err.propagate();
        if (!src.host().serialize(stream, srcType == HostAddrType::IPv4, err))
            return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCION ]###\n");
        out = formatIndented(out, indent, "qos   = {}\n", qos);
        out = formatIndented(out, indent, "fl    = {}\n", fl);
        out = formatIndented(out, indent, "nh    = {}\n", (unsigned)nh);
        out = formatIndented(out, indent, "hlen  = {}\n", hlen);
        out = formatIndented(out, indent, "plen  = {}\n", plen);
        out = formatIndented(out, indent, "ptype = {}\n", (unsigned)ptype);
        out = formatIndented(out, indent, "src   = {}\n", src);
        out = formatIndented(out, indent, "dst   = {}\n", dst);
        return out;
    }
};

/// \brief "Meta" header of a common SCION path.
class PathMeta
{
public:
    std::uint8_t currInf = 0;
    std::uint8_t currHf = 0;
    std::array<std::uint8_t, 3> segLen = {0, 0, 0};

    bool operator==(const PathMeta&) const = default;

    /// \brief Gets the number of path segments.
    std::size_t segmentCount() const
    {
        return (segLen[0] > 0) + (segLen[1] > 0) + (segLen[2] > 0);
    }

    /// \brief Gets the number of hop fields over all segments.
    std::size_t hopFieldCount() const
    {
        return std::size_t(segLen[0]) + std::size_t(segLen[1]) + std::size_t(segLen[2]);
    }

    /// \brief Get the index of the first hop field belonging to the given segment.
    /// \param segment Zero-based segment index. Asking for a segment > 2
    /// returns the index one past the third segment.
    std::size_t segmentBegin(std::size_t segment) const
    {
        switch (segment) {
        case 0:
            return 0;
        case 1:
            return std::size_t(segLen[0]);
        case 2:
            return std::size_t(segLen[0]) + std::size_t(segLen[1]);
        default:
            return std::size_t(segLen[0]) + std::size_t(segLen[1]) + std::size_t(segLen[2]);
        }
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeBits(currInf, 2, err)) return err.propagate();
        if (!stream.serializeBits(currHf, 6, err)) return err.propagate();
        if (!stream.advanceBits(6, err)) return err.propagate();
        if (!stream.serializeBits(segLen[0], 6, err)) return err.propagate();
        if (!stream.serializeBits(segLen[1], 6, err)) return err.propagate();
        if (!stream.serializeBits(segLen[2], 6, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if ((segLen[2] > 0 && segLen[1] == 0) || (segLen[1] > 0 && segLen[0] == 0))
                return err.error("invalid path meta header");
            if (currInf >= segmentCount())
                return err.error("invalid path meta header");
            if (currHf >= hopFieldCount())
                return err.error("invalid path meta header");
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCION Path ]###\n");
        out = formatIndented(out, indent, "currInf = {}\n", currInf);
        out = formatIndented(out, indent, "currHf  = {}\n", currHf);
        out = formatIndented(out, indent, "seg0Len = {}\n", segLen[0]);
        out = formatIndented(out, indent, "seg1Len = {}\n", segLen[1]);
        out = formatIndented(out, indent, "seg2Len = {}\n", segLen[2]);
        return out;
    }
};

/// \brief SCION common path segment info field.
class InfoField
{
public:
    enum class Flags : std::uint8_t
    {
        ConsDir = 1 << 0,
        Peering = 1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static constexpr std::size_t staticSize = 8;
    FlagSet flags;
    std::uint16_t segid;
    std::uint32_t timestamp;

    bool operator==(const InfoField&) const = default;

    std::size_t size() const { return staticSize; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)flags, err)) return err.propagate();
        if (!stream.advanceBytes(1, err)) return err.propagate();
        if (!stream.serializeUint16(segid, err)) return err.propagate();
        if (!stream.serializeUint32(timestamp, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ Info Field ]###\n");
        out = formatIndented(out, indent, "flags     = {}\n", flags);
        out = formatIndented(out, indent, "segid     = {}\n", segid);
        out = formatIndented(out, indent, "timestamp = {}\n", timestamp);
        return out;
    }
};

inline InfoField::FlagSet operator|(InfoField::Flags lhs, InfoField::Flags rhs)
{
    return InfoField::FlagSet(lhs) | rhs;
}

class HopField
{
public:
    enum class Flags : std::uint8_t
    {
        CEgrRouterAlert = 1 << 0,
        CIngRouterAlert = 1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static constexpr std::size_t staticSize = 12;
    FlagSet flags;
    std::uint8_t expTime = 0;
    std::uint16_t consIngress = 0;
    std::uint16_t consEgress = 0;
    std::array<std::byte, 6> mac = {};

    bool operator==(const HopField&) const = default;

    /// \brief Calculate the expiration time in seconds relative to the
    /// timestamp of the corresponding info field.
    std::uint32_t relativeExpiry()
    {
        return ((1 + expTime) * 24 * 60 * 60) / 256;
    }

    std::size_t size() const { return staticSize; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte(flags.ref(), err)) return err.propagate();
        if (!stream.serializeByte(expTime, err)) return err.propagate();
        if (!stream.serializeUint16(consIngress, err)) return err.propagate();
        if (!stream.serializeUint16(consEgress, err)) return err.propagate();
        if (!stream.serializeBytes(mac, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ Hop Field ]###\n");
        out = formatIndented(out, indent, "flags       = {}\n", flags);
        out = formatIndented(out, indent, "expTime     = {}\n", expTime);
        out = formatIndented(out, indent, "consIngress = {}\n", consIngress);
        out = formatIndented(out, indent, "consEgress  = {}\n", consEgress);
        out = formatIndented(out, indent, "mac         = ");
        out = formatBytes(out, mac);
        return std::format_to(out, "\n");
    }
};

inline HopField::FlagSet operator|(HopField::Flags lhs, HopField::Flags rhs)
{
    return HopField::FlagSet(lhs) | rhs;
}

/// \brief SCION hop-by-hop options header.
class HopByHopOpts
{
public:
    static const std::size_t minSize = 2;

    ScionProto nh = ScionProto::UDP;
    std::uint8_t extLen = 0;

    /// \brief Returns the size in bytes of the options following this header.
    std::size_t optionSize() const { return 4 * extLen + 2; }

    std::size_t size() const { return 2; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)nh, err)) return err.propagate();
        if (!stream.serializeByte(extLen, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ Hop-by-Hop Options ]###\n");
        out = formatIndented(out, indent, "nh     = {}\n", (unsigned)nh);
        out = formatIndented(out, indent, "extLen = {}\n", extLen);
        return out;
    }
};

/// \brief SCION end-to-end options header.
class EndToEndOpts
{
public:
    static const std::size_t minSize = 2;

    ScionProto nh = ScionProto::UDP;
    std::uint8_t extLen = 0;

    /// \brief Returns the size in bytes of the options following this header.
    std::size_t optionSize() const { return 4 * extLen + 2; }

    std::size_t size() const { return 2; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)nh, err)) return err.propagate();
        if (!stream.serializeByte(extLen, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ End-to-End Options ]###\n");
        out = formatIndented(out, indent, "nh     = {}\n", nh);
        out = formatIndented(out, indent, "extLen = {}\n", extLen);
        return out;
    }
};

/// \brief Generic SCION option that captures type and length but not the actual
/// option data. Can be used for Pad1, PadN and unknown options.
class SciOpt
{
public:
    OptType type = OptType::Pad1;
    std::uint8_t dataLen = 0;

    std::size_t size() const
    {
        if (type == OptType::Pad1)
            return 1;
        else
            return 2 + dataLen;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if (type != OptType::Pad1) { // Pad1 options don't have a length field
            if (!stream.serializeByte(dataLen, err)) return err.propagate();
            if (!stream.advanceBytes(dataLen, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ Option ]###\n");
        out = formatIndented(out, indent, "type    = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen = {}\n", dataLen);
        return out;
    }
};

/// \brief SCION Packet Authenticator end-to-end option.
class AuthenticatorOpt : public SciOpt
{
public:
    static const std::size_t minDataLen = 12;
    static constexpr OptType type = OptType::SPAO;

    std::uint8_t dataLen = 0;
    std::uint8_t algorithm = 0;
    std::uint32_t spi = 0;
    std::uint64_t timestamp = 0; // 48 bit
    std::array<std::byte, 36> authenticator = {};

    /// \brief Retruns valid size of `authenticator`.
    std::size_t getAuthSize() const
    {
        return std::max<std::size_t>(0u, (std::size_t)dataLen - minDataLen);
    }

    /// \brief Convenience method for setting the authenticator size.
    void setAuthSize(std::size_t size)
    {
        assert(size < authenticator.size());
        dataLen = (std::uint8_t)(minDataLen + size);
    }

    /// \brief Get a view of the valid range of `authenticator`.
    std::span<const std::byte> getAuth() const
    {
        auto n = std::min(getAuthSize(), authenticator.size());
        return std::span<const std::byte>(authenticator.data(), n);
    }

    /// \brief Get a view of the valid range of `authenticator`.
    std::span<std::byte> getAuth()
    {
        auto n = std::min(getAuthSize(), authenticator.size());
        return std::span<std::byte>(authenticator.data(), n);
    }

    std::size_t size() const
    {
        return 2 + dataLen;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto type = OptType::SPAO;
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (type != OptType::SPAO) return err.error("incorrect option type");
        }
        if (!stream.serializeByte(dataLen, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dataLen < minDataLen) return err.error("invalid option");
            if (getAuthSize() > authenticator.size()) return err.error("authenticator too large");
        }
        if (!stream.serializeUint32(spi, err)) return err.propagate();
        if (!stream.serializeByte(algorithm, err)) return err.propagate();
        if (!stream.advanceBytes(1, err)) return err.propagate();
        if (!stream.serializeBits(timestamp, 48, err)) return err.propagate();
        if (!stream.serializeBytes(getAuth(), err))
            return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SPAO ]###\n");
        out = formatIndented(out, indent, "type          = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen       = {}\n", dataLen);
        out = formatIndented(out, indent, "algorithm     = {}\n", algorithm);
        out = formatIndented(out, indent, "spi           = {}\n", spi);
        out = formatIndented(out, indent, "timestamp     = {:#012x}\n", timestamp);
        out = formatIndented(out, indent, "authenticator = ");
        out = formatBytes(out, getAuth());
        return std::format_to(out, "\n");
    }
};

} // namespace hdr
} // namespace scion
