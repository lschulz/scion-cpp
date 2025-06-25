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
#include "scion/addr/isd_asn.hpp"
#include "scion/bit_stream.hpp"
#include "scion/hdr/scion.hpp"

#include <array>
#include <cstdint>


namespace scion {
namespace hdr {

/// \brief ID-INT instruction flags.
enum class IdIntInstFlags : std::uint8_t
{
    NodeID  = 1 << 3,
    NodeCnt = 1 << 2,
    IgrIf   = 1 << 1,
    EgrIf   = 1 << 0,
};
using IdIntInstBitmap = scion::details::FlagSet<IdIntInstFlags>;

inline IdIntInstBitmap operator|(IdIntInstFlags lhs, IdIntInstFlags rhs)
{
    return IdIntInstBitmap(lhs) | rhs;
}

/// \brief ID-INT telemetry instructions.
enum class IdIntInstruction : std::uint8_t
{
    Nop             = 0x00,
    Isd             = 0x01,
    BrLinkType      = 0x02,
    DeviceTypeRole  = 0x03,
    CpuMemUsage     = 0x04,
    CpuTemp         = 0x05,
    AsicTemp        = 0x06,
    FanSpeed        = 0x07,
    TotalPower      = 0x08,
    EnergyMix       = 0x09,
    DeviceVendor    = 0x41,
    DeviceModel     = 0x42,
    SoftwareVersion = 0x43,
    NodeIpv4Addr    = 0x44,
    IngressIfSpeed  = 0x45,
    EgressIfSpeed   = 0x46,
    GpsLat          = 0x47,
    GpsLong         = 0x48,
    Uptime          = 0x49,
    FwdEnergy       = 0x4a,
    Co2Emission     = 0x4b,
    IngressLinkRx   = 0x4c,
    EgressLinkTx    = 0x4d,
    QueueId         = 0x4e,
    InstQueueLen    = 0x4f,
    AvgQueueLen     = 0x50,
    BufferId        = 0x51,
    InstBufferOcc   = 0x52,
    AvgBufferOcc    = 0x53,
    Asn             = 0x81,
    IngressTstamp   = 0x82,
    EgressTstamp    = 0x83,
    IgScifPktCnt    = 0x84,
    EgScifPktCnt    = 0x85,
    IgScifPktDrop   = 0x86,
    EgScifPktDrop   = 0x87,
    IgScifBytes     = 0x88,
    EgScifBytes     = 0x89,
    IgPktCnt        = 0x8a,
    EgPktCnt        = 0x8b,
    IgPktDrop       = 0x8c,
    EgPktDrop       = 0x8d,
    IgBytes         = 0x8e,
    EgBytes         = 0x8f,
    NodeIpv6AddrH   = 0xc1,
    NodeIpv6AddrL   = 0xc2,
};

/// \brief ID-INT main hop-by-hop option.
class IdIntOpt
{
public:
    enum class Flags : std::uint8_t
    {
        InfraMode    = 1 << 4,
        Discard      = 1 << 3,
        Encrypted    = 1 << 2,
        SizeExceeded = 1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    enum class AgrMode : std::uint8_t
    {
        Off      = 0,
        AS       = 1,
        Border   = 2,
        Internal = 3,
    };

    enum class Verifier : std::uint8_t
    {
        ThirdParty,
        Destination,
        Source,
    };

    enum class AgrFunction : std::uint8_t
    {
        First   = 0,
        Last    = 1,
        Minimum = 2,
        Maximum = 3,
        Sum     = 4,
    };

    static const std::size_t minDataLen = 22;
    static constexpr OptType type = OptType::IdInt;
    static constexpr std::uint8_t version = 0;

    std::uint8_t dataLen = 0;
    FlagSet flags;
    AgrMode agrMode = AgrMode::Off;
    Verifier vtype = Verifier::Destination;
    std::uint8_t stackLen = 0;
    std::uint8_t tos = 0;
    std::uint8_t delayHops = 0;
    IdIntInstBitmap bitmap;
    std::array<AgrFunction, 4> agrFunc = {};
    std::array<IdIntInstruction, 4> instr = {};
    std::uint64_t sourceTS = 0;
    std::uint16_t sourcePort = 0;
    ScIPAddress verifier;

    /// \brief Compute the correct value for `dataLen`.
    std::size_t size() const
    {
        std::size_t size = minDataLen;
        if (vtype == Verifier::ThirdParty) size += verifier.size();
        return size;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto type = OptType::IdInt;
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (type != OptType::IdInt) return err.error("incorrect option type");
        }
        if (!stream.serializeByte(dataLen, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dataLen < minDataLen) return err.error("invalid option");
        }
        auto ver = version;
        if (!stream.serializeBits(ver, 3, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (ver != version) return err.error("unknown ID-INT version");
        }
        if (!stream.serializeBits(flags.ref(), 5, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if ((std::uint8_t)flags & 1) return err.error("invalid ID-INT header");
        }
        if (!stream.serializeBits((std::uint8_t&)agrMode, 2, err)) return err.propagate();
        if (!stream.serializeBits((std::uint8_t&)vtype, 2, err)) return err.propagate();
        auto verifAddrType = HostAddrType::IPv4;
        if constexpr (Stream::IsWriting) {
            if (vtype == Verifier::ThirdParty) {
                verifAddrType = AddressTraits<generic::IPAddress>::type(verifier.getHost());
            }
        }
        if (!stream.serializeBits((std::uint8_t&)verifAddrType, 4, err)) return err.propagate();
        if (!stream.serializeByte(stackLen, err)) return err.propagate();
        if (!stream.serializeByte(tos, err)) return err.propagate();
        if (!stream.serializeBits(delayHops, 6, err)) return err.propagate();
        if (!stream.advanceBits(10, err)) return err.propagate();
        if (!stream.serializeBits(bitmap.ref(), 4, err)) return err.propagate();
        for (auto& func : agrFunc) {
            if (!stream.serializeBits((std::uint8_t&)func, 3, err)) return err.propagate();
        }
        for (auto& inst : instr) {
            if (!stream.serializeByte((std::uint8_t&)inst, err)) return err.propagate();
        }
        if (!stream.serializeBits(sourceTS, 48, err)) return err.propagate();
        if (!stream.serializeUint16(sourcePort, err)) return err.propagate();
        if (vtype == Verifier::ThirdParty) {
            if (!verifier.getIsdAsn().serialize(stream, err)) return err.propagate();
            if (!verifier.getHost().serialize(stream, verifAddrType == HostAddrType::IPv4, err))
                return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ID-INT Option ]###\n");
        out = formatIndented(out, indent, "type       = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen    = {}\n", dataLen);
        out = formatIndented(out, indent, "flags      = {:#02x}\n", (unsigned)flags);
        out = formatIndented(out, indent, "agrMode    = {}\n", (unsigned)agrMode);
        out = formatIndented(out, indent, "vtype      = {}\n", (unsigned)vtype);
        out = formatIndented(out, indent, "stackLen   = {}\n", stackLen);
        out = formatIndented(out, indent, "tos        = {}\n", tos);
        out = formatIndented(out, indent, "delayHops  = {}\n", delayHops);
        for (int i = 0; i < 4; ++i) {
            out = formatIndented(out, indent, "agrFunc{}   = {}\n", i + 1, (unsigned)agrFunc[i]);
            out = formatIndented(out, indent, "instr{}     = {:#02x}\n", i + 1, (unsigned)instr[i]);
        }
        out = formatIndented(out, indent, "sourceTS   = {}\n", sourceTS);
        out = formatIndented(out, indent, "sourcePort = {}\n", sourcePort);
        out = formatIndented(out, indent, "verifier   = {}\n", verifier);
        return out;
    }
};

inline IdIntOpt::FlagSet operator|(IdIntOpt::Flags lhs, IdIntOpt::Flags rhs)
{
    return IdIntOpt::FlagSet(lhs) | rhs;
}

/// \brief ID-INT telemetry stack entry hop-by-hop option.
class IdIntEntry
{
public:
    enum class Flags : std::uint8_t
    {
        Source    = 1 << 4,
        Ingress   = 1 << 3,
        Egress    = 1 << 2,
        Aggregate = 1 << 1,
        Encrypted = 1 << 0,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static const std::size_t minDataLen = 12;
    static constexpr OptType type = OptType::IdIntEntry;

    std::uint8_t dataLen = 0;
    FlagSet flags;
    std::uint8_t hop = 0;
    IdIntInstBitmap mask;
    std::array<std::uint8_t, 4> ml = {};
    std::array<std::byte, 12> nonce = {};
    std::array<std::byte, 4> mac = {};
    std::array<std::byte, 44> metadata = {};

    /// \brief Get the metadata field size in bytes including necessary padding.
    std::size_t mdSize() const
    {
        std::size_t size = 0;
        if (mask[IdIntInstFlags::NodeID]) size += 4;
        if (mask[IdIntInstFlags::NodeCnt]) size += 2;
        if (mask[IdIntInstFlags::IgrIf]) size += 2;
        if (mask[IdIntInstFlags::EgrIf]) size += 2;
        for (auto& length : ml) size += std::min(length << 1, 8);
        auto padding = -(size + 2u) & 0x03ul;
        return size + padding;
    }

    /// \brief Get a view of the valid range of `metadata`.
    std::span<const std::byte> getMetadata() const
    {
        auto n = std::min(mdSize(), metadata.size());
        return std::span<const std::byte>(metadata.data(), n);
    }

    /// \brief Get a view of the valid range of `metadata`.
    std::span<std::byte> getMetadata()
    {
        auto n = std::min(mdSize(), metadata.size());
        return std::span<std::byte>(metadata.data(), n);
    }

    /// \brief Compute the correct value for `dataLen`.
    std::size_t size() const
    {
        return 10 + mdSize() + flags[Flags::Encrypted] * nonce.size();
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto type = OptType::IdIntEntry;
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (type != OptType::IdIntEntry) return err.error("incorrect option type");
        }
        if (!stream.serializeByte(dataLen, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dataLen < minDataLen) return err.error("invalid option");
        }
        if (!stream.serializeBits(flags.ref(), 5, err)) return err.propagate();
        if (!stream.advanceBits(3, err)) return err.propagate();
        if (!stream.serializeBits(hop, 6, err)) return err.propagate();
        if (!stream.advanceBits(2, err)) return err.propagate();
        if (!stream.serializeBits(mask.ref(), 4, err)) return err.propagate();
        for (auto& length : ml) {
            if (!stream.serializeBits(length, 3, err)) return err.propagate();
            if constexpr (Stream::IsReading) {
                if (length > 4) return err.error("invalid metadata length");
            }
        }
        if (flags[Flags::Encrypted]) {
            if (!stream.serializeBytes(nonce, err)) return err.propagate();
        }
        if (!stream.serializeBytes(getMetadata(), err)) return err.propagate();
        if (!stream.serializeBytes(mac, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ID-INT Entry ]###\n");
        out = formatIndented(out, indent, "type     = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen  = {}\n", dataLen);
        out = formatIndented(out, indent, "flags    = {:#02x}\n", (unsigned)flags);
        out = formatIndented(out, indent, "hop      = {}\n", hop);
        out = formatIndented(out, indent, "mask     = {:#02x}\n", (unsigned)mask);
        for (int i = 0; i < 4; ++i) {
            out = formatIndented(out, indent, "ml{}      = {}\n", i + 1, ml[i]);
        }
        if (flags[Flags::Encrypted]) {
            out = formatIndented(out, indent, "nonce    = ");
            out = formatBytes(out, nonce);
            out = std::format_to(out, "\n");
        }
        out = formatIndented(out, indent, "metadata = ");
        out = formatBytes(out, std::span(metadata.data(), mdSize()));
        out = std::format_to(out, "\n");
        out = formatIndented(out, indent, "mac      = ");
        out = formatBytes(out, mac);
        return std::format_to(out, "\n");
    }
};

inline IdIntEntry::FlagSet operator|(IdIntEntry::Flags lhs, IdIntEntry::Flags rhs)
{
    return IdIntEntry::FlagSet(lhs) | rhs;
}

} // namespace hdr
} // namespace scion
