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
#include "scion/hdr/ip.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/hdr/scmp.hpp"
#include "scion/hdr/stun.hpp"
#include "scion/hdr/tcp.hpp"
#include "scion/hdr/udp.hpp"
#include "scion/path/raw.hpp"

#include <cassert>
#include <memory>
#include <span>
#include <vector>


namespace scion {
namespace scitra {

/// \brief Base class for function objects that determine whether a given UDP
/// packet should be parsed as SCION.
class IsScion
{
public:
    virtual bool operator()(const generic::IPEndpoint& src, const generic::IPEndpoint& dst) = 0;
};

/// \brief Holds a raw packet and exposes the packet's headers for in-place
/// packet rewriting.
/// \details The expected order of operations is:
/// 1. Prepare the buffer for a new packet with clearAndGetBuffer() and write
///    the raw data to the returned buffer.
/// 2. Load the packet headers with parsePacket().
/// 3. Modify the header contents and validity.
/// 4. Update the raw packet with emitPacket().
class PacketBuffer
{
public:
    enum class IPValidity
    {
        None = 0,
        IPv4 = 4,
        IPv6 = 6,
    };

    enum class L4Type
    {
        None = 0,
        ICMP = (int)hdr::IPProto::ICMPv6,
        SCMP = (int)hdr::ScionProto::SCMP,
        TCP = (int)hdr::IPProto::TCP,
        UDP = (int)hdr::IPProto::UDP,
    };

    /// \brief Indicated which of `ipv4` and `ipv6` holds valid data.
    IPValidity ipValid = IPValidity::None;
    /// \brief Indicates whether `outerUDP` is valid.
    bool outerUDPValid = false;
    /// \brief Indicates whether `stun` is valid.
    bool stunValid = false;
    /// \brief Indicates whether `sci` and `path` are valid.
    bool scionValid = false;
    /// \brief Indicated which of `icmp`, `scmp`, `tcp`, and `udp` holds valid data.
    L4Type l4Valid = L4Type::None;

    // Parsed packet
    hdr::IPv4 ipv4;
    hdr::IPv6 ipv6;
    hdr::UDP outerUDP;
    hdr::STUN stun;
    hdr::SCION sci;
    RawPath path;
    hdr::ICMPv6 icmp;
    hdr::SCMP scmp;
    hdr::TCP tcp;
    hdr::UDP udp;

private:
    // Raw packet
    std::pmr::vector<std::byte> buffer;
    std::span<std::byte> packet;
    std::byte* endOfHeader = nullptr;

public:
    /// \brief Initialize a packet buffer adopting `buffer` as its raw packet
    /// storage.
    explicit PacketBuffer(std::pmr::vector<std::byte>&& buffer)
        : buffer(std::move(buffer))
        , packet(buffer.data(), buffer.size())
    {
        assert(buffer.data() <= packet.data());
        assert(packet.data() + packet.size() <= buffer.data() + buffer.size());
        endOfHeader = buffer.data();
    }

    /// \brief Clear the packet buffer and invalidate all extracted headers.
    /// Returns a writeable view into the packet buffer in which a new packet
    /// can be placed. After a new packet has been written to the buffer, the
    /// packet length must be set with a call to parsePacket().
    /// \param headroom How much extra space to reserve in front of the packet
    /// to allow for growing headers.
    std::span<std::byte> clearAndGetBuffer(std::size_t headroom)
    {
        headroom = std::min(headroom, buffer.size());
        ipValid = IPValidity::None;
        outerUDPValid = false;
        stunValid = false;
        scionValid = false;
        l4Valid = L4Type::None;
        packet = std::span<std::byte>(buffer.data() + headroom, buffer.size() - headroom);
        endOfHeader = packet.data();
        return packet;
    };

    /// \brief Parse a new packet that has been placed into the span returned
    /// by clearAndGetBuffer(). If this function returns successfully, the
    /// public members of the class have been initialized to reflect the packet
    /// headers in the buffer.
    /// \param size Size if the packet placed into the buffer.
    /// \param noUnderlay If true, assume the raw packet starts directly with a
    /// SCION header without an underlay.
    /// \param isScion A function object that determines if a UDP/IP packet
    /// contains a SCION header. Only used if `noUnderlay` is false.
    /// If `noUnderlay` is false and `isScion` is null, parsing SCION is never
    /// attempted.
    std::error_code parsePacket(std::size_t size, bool noUnderlay, IsScion* isScion = nullptr)
    {
        packet = packet.subspan(0, std::min(size, packet.size()));
        ReadStream rs(packet);
        SCION_STREAM_ERROR err;
        if (!parse(rs, noUnderlay, isScion, err)) {
            SCION_DEBUG_PRINT(err);
            return ErrorCode::InvalidPacket;
        }
        return ErrorCode::Ok;
    }

    /// \brief Turn the raw packet headers currently in the buffer into payload
    /// for a new packet with a maximum payload size of `maxSize` bytes. This
    /// method should be used for quoting the original packet in an ICMP or
    /// SCMP response.
    /// \return New payload length.
    std::size_t quoteRawHeaders(std::size_t maxSize)
    {
        packet = packet.subspan(0, std::min(packet.size(), maxSize));
        endOfHeader = packet.data();
        return packet.size();
    }

    /// \brief Write updated header back into the raw packet buffer.
    /// \param noUnderlay Do not include the UDP/IP underlay headers.
    /// \returns A view of a packet with the new headers and the old payload.
    /// May return ErrorCode::BufferTooSmall if the new headers do not fit in
    /// the headroom reserved by clearAndGetBuffer().
    Maybe<std::span<const std::byte>> emitPacket(bool noUnderlay = false)
    {
        assert(packet.data() <= endOfHeader && endOfHeader <= (packet.data() + packet.size()));
        auto headroom = endOfHeader - buffer.data();
        auto hdrSize = (std::ptrdiff_t)measureHeaders(noUnderlay);
        auto payloadSize = packet.size() - (endOfHeader - packet.data());
        if (headroom < hdrSize) {
            return Error(ErrorCode::BufferTooSmall); // insufficient headroom
        }
        std::byte* pktBegin = buffer.data() + (headroom - hdrSize);
        WriteStream ws(std::span<std::byte>(pktBegin, hdrSize));
        SCION_STREAM_ERROR err;
        if (!emit(ws, noUnderlay, err)) {
            SCION_DEBUG_PRINT(err);
            return Error(ErrorCode::LogicError);
        }
        packet = std::span<std::byte>(pktBegin, hdrSize + payloadSize);
        return packet;
    }

    /// \brief Returns the size of the parsed valid packet headers.
    /// \param noUnderlay Do not include the UDP/IP underlay in the size calculation.
    std::size_t measureHeaders(bool noUnderlay = false)
    {
        std::size_t size = 0;
        if (!noUnderlay) {
            if (ipValid == IPValidity::IPv4)
                size += ipv4.size();
            else if (ipValid == IPValidity::IPv6)
                size += ipv6.size();
            if (outerUDPValid) size += outerUDP.size();
        }
        if (scionValid) {
            size += sci.size() + path.size();
        }
        size += l4Size();
        return size;
    }

    /// \brief Gets a view of the packet payload.
    std::span<const std::byte> payload() const
    {
        assert(packet.data() <= endOfHeader && endOfHeader <= (packet.data() + packet.size()));
        return std::span<const std::byte>(
            endOfHeader,
            packet.size() - (endOfHeader - packet.data())
        );
    }

    /// \brief Returns the size of the current layer 4 protocol's headers.
    std::size_t l4Size() const
    {
        using namespace hdr;
        switch (l4Valid) {
        case L4Type::ICMP:
            return icmp.size();
        case L4Type::SCMP:
            return scmp.size();
        case L4Type::TCP:
            return tcp.size();
        case L4Type::UDP:
            return udp.size();
        default:
            return 0;
        }
    }

    /// \brief Returns the source port of the layer 4 protocol or 0 if the
    /// protocol does not use ports (ICMP and SCMP).
    std::uint16_t l4SPort() const
    {
        using namespace hdr;
        switch (l4Valid) {
        case L4Type::TCP:
            return tcp.sport;
        case L4Type::UDP:
            return udp.sport;
        default:
            return 0;
        }
    }

    /// \brief Returns the source port of the layer 4 protocol or 0 if the
    /// protocol does not use ports (ICMP and SCMP).
    std::uint16_t l4DPort() const
    {
        using namespace hdr;
        switch (l4Valid) {
        case L4Type::TCP:
            return tcp.dport;
        case L4Type::UDP:
            return udp.dport;
        default:
            return 0;
        }
    }

    /// \brief Returns the layer 4 header's contribution to the flow label.
    std::uint32_t l4FlowLabel() const
    {
        using namespace hdr;
        switch (l4Valid) {
        case L4Type::ICMP:
            return icmp.flowLabel();
        case L4Type::SCMP:
            return scmp.flowLabel();
        case L4Type::TCP:
            return tcp.flowLabel();
        case L4Type::UDP:
            return udp.flowLabel();
        default:
            return 0;
        }
    }

    /// \brief Update the layer 4 protocol's checksum in place.
    /// \param add Sum of 16-bit header words that are added to the checksum.
    /// \param sub Sum of 16-bit header words that are subtracted from the checksum.
    void l4UpdateChecksum(std::uint32_t add, std::uint32_t sub)
    {
        switch (l4Valid) {
        case L4Type::TCP:
            tcp.chksum = hdr::details::updateInternetChecksum(tcp.chksum, add, sub);
            break;
        case L4Type::UDP:
            udp.chksum = hdr::details::updateInternetChecksum(udp.chksum, add, sub);
            break;
        default:
            break;
        }
    }

    /// \brief Returns the packet in human-readable form.
    std::string print() const;

private:
    bool parse(ReadStream& rs, bool noUnderlay, IsScion* isScion, SCION_STREAM_ERROR& err);
    bool parseScion(ReadStream& rs, hdr::ScionProto& proto, SCION_STREAM_ERROR& err);
    bool parseL4(ReadStream& rs, hdr::ScionProto proto, SCION_STREAM_ERROR& err);
    bool emit(WriteStream& ws, bool noUnderlay, SCION_STREAM_ERROR& err);
};

} // namespace scitra
} // namespace scion
