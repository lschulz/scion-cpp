// Copyright (c) 2024-2026 Lars-Christian Schulz
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
#include "scion/extensions/idint_instr.hpp"
#include "scion/hdr/scion.hpp"

#include <array>
#include <cstdint>


namespace scion {
namespace hdr {

/// \brief ID-INT main hop-by-hop option.
class IdIntOpt
{
public:
    enum class Flags : std::uint8_t
    {
        InfraMode    = 1 << 4,
        Discard      = 1 << 3,
        Encrypt      = 1 << 2,
        SizeExceeded = 1 << 1,
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static const std::size_t minDataLen = 20;
    static constexpr OptType type = OptType::IdInt;
    static constexpr std::uint8_t version = 0;

    FlagSet flags;
    idint::AM agrMode = idint::AM::Off;
    idint::Verifier vtype = idint::Verifier::Destination;
    std::uint8_t stackLen = 0;
    std::uint8_t tos = 0;
    std::uint8_t delayHops = 0;
    idint::InstrBitmap bitmap;
    std::array<idint::AF, 4> agrFuncs = {};
    std::array<idint::Instr, 4> instr = {};
    std::uint64_t sourceTS = 0;
    std::uint16_t sourcePort = 0;
    ScIPAddress verifier;

    /// \brief Returns the size of the option including type and length fields.
    std::size_t size() const
    {
        std::size_t size = 2 + minDataLen;
        if (vtype == idint::Verifier::ThirdParty) size += verifier.size();
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
        std::uint8_t dataLen = (std::uint8_t)(size() - 2);
        if (!stream.serializeByte(dataLen, err)) return err.propagate();
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
            if (vtype == idint::Verifier::ThirdParty) {
                verifAddrType = AddressTraits<generic::IPAddress>::type(verifier.host());
            }
        }
        if (!stream.serializeBits((std::uint8_t&)verifAddrType, 4, err)) return err.propagate();
        if (!stream.serializeByte(stackLen, err)) return err.propagate();
        if (!stream.serializeByte(tos, err)) return err.propagate();
        if (!stream.serializeBits(delayHops, 6, err)) return err.propagate();
        if (!stream.advanceBits(10, err)) return err.propagate();
        if (!stream.serializeBits(bitmap.ref(), 4, err)) return err.propagate();
        for (auto& func : agrFuncs) {
            if (!stream.serializeBits((std::uint8_t&)func, 3, err)) return err.propagate();
        }
        for (auto& inst : instr) {
            if (!stream.serializeByte((std::uint8_t&)inst, err)) return err.propagate();
        }
        if (!stream.serializeBits(sourceTS, 48, err)) return err.propagate();
        if (!stream.serializeUint16(sourcePort, err)) return err.propagate();
        if (vtype == idint::Verifier::ThirdParty) {
            if (!verifier.isdAsn().serialize(stream, err)) return err.propagate();
            if (!verifier.host().serialize(stream, verifAddrType == HostAddrType::IPv4, err))
                return err.propagate();
        }
        if constexpr (Stream::IsReading) {
            if (dataLen < (size() - 2)) {
                return err.error("invalid ID-INT main option length");
            }
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ID-INT Option ]###\n");
        out = formatIndented(out, indent, "type       = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen    = {}\n", size() - 2);
        out = formatIndented(out, indent, "flags      = {:#02x}\n", (std::uint8_t)flags);
        out = formatIndented(out, indent, "agrMode    = {}\n", (unsigned)agrMode);
        out = formatIndented(out, indent, "vtype      = {}\n", (unsigned)vtype);
        out = formatIndented(out, indent, "stackLen   = {}\n", stackLen);
        out = formatIndented(out, indent, "tos        = {}\n", tos);
        out = formatIndented(out, indent, "delayHops  = {}\n", delayHops);
        for (int i = 0; i < 4; ++i) {
            out = formatIndented(out, indent, "agrFuncs{}   = {}\n", i + 1, (unsigned)agrFuncs[i]);
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

    static const std::size_t minDataLen = 10;
    static constexpr std::size_t maxDataAndMacLen = 48;
    static constexpr OptType type = OptType::IdIntEntry;

    FlagSet flags;
    std::uint8_t hop = 0;
    idint::InstrBitmap mask;
    std::array<std::uint8_t, 4> ml = {};
    std::array<std::byte, 12> nonce = {};
    std::array<std::byte, maxDataAndMacLen> dataAndMac = {};

    /// \brief Get the metadata field size in bytes including necessary padding.
    std::size_t mdSize() const
    {
        using namespace idint;
        std::size_t size = 0;
        if (mask[InstrFlag::NodeID]) size += 4;
        if (mask[InstrFlag::NodeCnt]) size += 2;
        if (mask[InstrFlag::IgPort]) size += 2;
        if (mask[InstrFlag::EgPort]) size += 2;
        for (auto& length : ml) size += std::min(length << 1, 8);
        auto padding = -(size + 2u) & 0x03ul;
        return size + padding;
    }

    /// \brief Get a view of the valid range of `metadata` including padding
    /// if applicable.
    std::span<const std::byte> metadata() const
    {
        auto n = std::min(mdSize(), dataAndMac.size());
        return std::span<const std::byte>(dataAndMac.data(), n);
    }

    /// \brief Get a view of the valid range of `metadata` including padding
    /// if applicable.
    std::span<std::byte> metadata()
    {
        auto n = std::min(mdSize(), dataAndMac.size());
        return std::span<std::byte>(dataAndMac.data(), n);
    }

    /// \brief Returns a view of the valid metadata, metadata padding, and MAC
    /// as one continuous block.
    std::span<const std::byte> metadataWithMAC() const
    {
        auto n = std::min(mdSize() + 4, dataAndMac.size());
        return std::span<const std::byte>(dataAndMac.data(), n);
    }

    /// \brief Returns a view of the valid metadata, metadata padding, and MAC
    /// as one continuous block.
    std::span<std::byte> metadataWithMAC()
    {
        auto n = std::min(mdSize() + 4, dataAndMac.size());
        return std::span<std::byte>(dataAndMac.data(), n);
    }

    /// \brief Returns a copy of the telemetry MAC.
    idint::MAC mac() const {
        const auto n = mdSize() + 4;
        if (n < 4) return idint::MAC{};
        return idint::MAC{
            dataAndMac[n-4],
            dataAndMac[n-3],
            dataAndMac[n-2],
            dataAndMac[n-1],
        };
    }

    /// \brief Set a new MAC. Must be called after the telemetry data been set.
    void setMAC(idint::MAC mac) {
        const auto m = mdSize();
        assert((m + 4) < dataAndMac.size());
        std::ranges::copy(mac, dataAndMac.begin() + m);
    }

    /// \brief Returns the size of the option including the TLV header and
    /// padding.
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
        std::uint8_t dataLen = 0;
        if constexpr (Stream::IsWriting) {
            dataLen = (std::uint8_t)(size() - 2);
        }
        if (!stream.serializeByte(dataLen, err)) return err.propagate();
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
        if (!stream.serializeBytes(metadataWithMAC(), err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dataLen < (size() - 2)) {
                return err.error("invalid ID-INT stack entry option length");
            }
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ ID-INT Entry ]###\n");
        out = formatIndented(out, indent, "type     = {}\n", (unsigned)type);
        out = formatIndented(out, indent, "dataLen  = {}\n", size() - 2);
        out = formatIndented(out, indent, "flags    = {:#02x}\n", (std::uint8_t)flags);
        out = formatIndented(out, indent, "hop      = {}\n", hop);
        out = formatIndented(out, indent, "mask     = {:#02x}\n", (std::uint8_t)mask);
        for (int i = 0; i < 4; ++i) {
            out = formatIndented(out, indent, "ml{}      = {}\n", i + 1, ml[i]);
        }
        if (flags[Flags::Encrypted]) {
            out = formatIndented(out, indent, "nonce    = ");
            out = formatBytes(out, nonce);
            out = std::format_to(out, "\n");
        }
        out = formatIndented(out, indent, "metadata = ");
        out = formatBytes(out, metadata());
        out = std::format_to(out, "\n");
        out = formatIndented(out, indent, "mac      = ");
        out = formatBytes(out, mac());
        return std::format_to(out, "\n");
    }
};

inline IdIntEntry::FlagSet operator|(IdIntEntry::Flags lhs, IdIntEntry::Flags rhs)
{
    return IdIntEntry::FlagSet(lhs) | rhs;
}

} // namespace hdr
} // namespace scion
