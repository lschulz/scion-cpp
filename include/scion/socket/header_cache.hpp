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

#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/debug.hpp"
#include "scion/error_codes.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/hdr/scmp.hpp"
#include "scion/hdr/udp.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <vector>


namespace scion {

/// \brief Returns the size of the SCION and L4 headers in a packet with the
/// given parameters.
template <
    typename Path,
    ext::extension_range ExtRange,
    typename L4>
std::size_t measureHeader(
    const ScIPEndpoint& to,
    const ScIPEndpoint& from,
    const Path& path,
    ExtRange&& extensions,
    L4&& l4)
{
    auto [hbhExtSize, e2eExtSize] = ext::computeExtSize(extensions);
    return 12 + to.address().size() + from.address().size() + path.size()
        + hbhExtSize + e2eExtSize + l4.size();
}

template <typename Alloc = std::allocator<std::byte>>
class HeaderCache
{
private:
#ifndef SCION_DISABLE_CHECKSUM
    std::uint32_t m_scionHdrChksum = 0;
#endif
    std::uint16_t m_payloadSize = 0;
    std::uint16_t m_nhOffset = 0;
    std::uint16_t m_l4Offset = 0;
    std::vector<std::byte, Alloc> m_buffer;

public:
    explicit HeaderCache(Alloc alloc = Alloc())
        : m_buffer(alloc)
    {}

    auto size() const { return m_buffer.size(); }

    auto get() const { return std::span<const std::byte>(m_buffer); }

    /// \brief Build headers from scratch.
    template <
        typename Path,
        ext::extension_range ExtRange,
        typename L4>
    std::error_code build(
        std::uint8_t tc,
        const ScIPEndpoint& to,
        const ScIPEndpoint& from,
        const Path& path,
        ExtRange&& extensions,
        L4&& l4,
        std::span<const std::byte> payload)
    {
        // Initialize SCION header
        hdr::SCION scHdr;
        scHdr.qos = tc;
        scHdr.nh = std::remove_reference<L4>::type::PROTO;
        scHdr.ptype = path.type();
        scHdr.dst = to.address();
        scHdr.src = from.address();
        m_nhOffset = 4;

        // Update transport header
        if constexpr (!std::is_convertible_v<L4, hdr::SCMP>) {
            l4.sport = from.port();
            l4.dport = to.port();
        }
        l4.setPayload(payload);

        // Compute values of remaining fields
        auto [hbhExtSize, e2eExtSize] = ext::computeExtSize(extensions);
        if (e2eExtSize > 0) scHdr.nh = hdr::ScionProto::E2EOpt;
        else if (hbhExtSize > 0) scHdr.nh = hdr::ScionProto::HBHOpt;
        scHdr.hlen = (std::uint8_t)((scHdr.size() + path.size()) / 4);
        scHdr.plen = (std::uint16_t)(hbhExtSize + e2eExtSize + l4.size() + payload.size());
        scHdr.fl = computeFlowLabel(scHdr, l4);
    #ifndef SCION_DISABLE_CHECKSUM
        l4.chksum = checksum(scHdr, l4, payload);
    #endif

        // Serialize headers
        m_buffer.resize(4*scHdr.hlen + hbhExtSize + e2eExtSize + l4.size());
        WriteStream ws(m_buffer);
        SCION_STREAM_ERROR err;
        if (!writeHeaders(ws, scHdr, path, extensions, l4, err)) {
            SCION_DEBUG_PRINT(err);
            return ErrorCode::LogicError;
        }

        m_payloadSize = (std::uint16_t)payload.size();
        return ErrorCode::Ok;
    }

    /// \brief Update headers in-place with a new payload. (won't update the flow label)
    template <typename L4>
    std::error_code updatePayload(L4&& l4, std::span<const std::byte> payload)
    {
        std::uint16_t oldLen = 0;
        auto nh = hdr::ScionProto(0);
        {
            ReadStream rs(m_buffer);
            rs.seek(4, 0);
            if (!rs.serializeByte((std::uint8_t&)nh, NullStreamError))
                return ErrorCode::LogicError;
            rs.seek(6, 0);
            if (!rs.serializeUint16(oldLen, NullStreamError))
                return ErrorCode::LogicError;
        }

        // Recompute length and checksum
        auto newLen = (std::uint16_t)(oldLen - (m_buffer.size() - m_l4Offset) - m_payloadSize);
        m_payloadSize = (std::uint16_t)(payload.size());
        newLen += (std::uint16_t)(l4.size() + m_payloadSize);
        l4.setPayload(payload);
    #ifndef SCION_DISABLE_CHECKSUM
        m_scionHdrChksum += (std::uint32_t)std::remove_reference<L4>::type::PROTO - (std::uint32_t)nh;
        m_scionHdrChksum += newLen - oldLen;
        l4.chksum = 0;
        l4.chksum = hdr::details::internetChecksum(payload, m_scionHdrChksum + l4.checksum());
    #endif

        // Update headers
        m_buffer.resize(m_l4Offset + l4.size());
        WriteStream ws(m_buffer);
        SCION_STREAM_ERROR err;
        if (!updateHeaders(ws, newLen, l4, err)) {
            SCION_DEBUG_PRINT(err);
            return ErrorCode::LogicError;
        }
        return ErrorCode::Ok;
    }

private:
    template <typename Path, ext::extension_range ExtRange, typename L4>
    bool writeHeaders(WriteStream& ws,
        const hdr::SCION& scHdr,
        const Path& path,
        ExtRange&& extensions,
        const L4& l4,
        SCION_STREAM_ERROR& err)
    {
        using namespace std::ranges::views;
        if (!const_cast<hdr::SCION&>(scHdr).serialize(ws, err)) return err.propagate();
        if (!ws.serializeBytes(path.encoded(), err)) return err.propagate();
        auto [hbhExtSize, e2eExtSize] = ext::computeExtSize(extensions);
        if (hbhExtSize > 0) {
            hdr::HopByHopOpts hbh;
            hbh.nh = e2eExtSize > 0 ? hdr::ScionProto::E2EOpt : L4::PROTO;
            hbh.extLen = (std::uint8_t)((hbhExtSize / 4) - 1);
            m_nhOffset = (std::uint16_t)(ws.getPos().first);
            if (!hbh.serialize(ws, err)) return err.propagate();
        }
        auto isHbH = [](auto ext) {
            return ext->isValid() && ext->category() == ext::Category::HopByHop;
        };
        for (auto ext : extensions | filter(isHbH)) {
            if (!ext->write(ws, ws.getPos().first, err)) return err.propagate();
        }
        if (e2eExtSize > 0) {
            hdr::EndToEndOpts e2e;
            e2e.nh = L4::PROTO;
            e2e.extLen = (std::uint8_t)((e2eExtSize / 4) - 1);
            m_nhOffset = (std::uint16_t)(ws.getPos().first);
            if (!e2e.serialize(ws, err)) return err.propagate();
        }
        auto isE2E = [](auto ext) {
            return ext->isValid() && ext->category() == ext::Category::EndToEnd;
        };
        for (auto ext : extensions | filter(isE2E)) {
            if (!ext->write(ws, ws.getPos().first, err)) return err.propagate();
        }
        m_l4Offset = (std::uint16_t)(ws.getPos().first);
        if (!const_cast<L4&>(l4).serialize(ws, err)) return err.propagate();
        return true;
    }

    template <typename L4>
    bool updateHeaders(WriteStream& ws, std::uint16_t plen, L4&& l4, SCION_STREAM_ERROR& err)
    {
        // Updated payload length
        ws.seek(6, 0);
        if (!ws.serializeUint16(plen, err)) return err.propagate();
        // Update next header type
        ws.seek(m_nhOffset, 0);
        if (!ws.serializeByte(
            (std::uint8_t)std::remove_reference<L4>::type::PROTO, err)) return err.propagate();
        // Replace L4 header
        ws.seek(m_l4Offset, 0);
        if (!l4.serialize(ws, err)) return err.propagate();
        return true;
    }

    /// \brief Deterministically compute the flow label from the source and
    /// destination addresses in the SCION header, the L4 header type, and the
    /// source and destination ports if available.
    template <typename L4>
    static std::uint32_t computeFlowLabel(const hdr::SCION& scHdr, const L4& l4)
    {
        std::hash<ScIPAddress> h1;
        return (std::uint32_t)(h1(scHdr.dst) ^ h1(scHdr.src)) ^ l4.flowLabel();
    }

    /// \brief Compute the L4 checksum.
    template <typename L4>
    std::uint16_t checksum(
        const hdr::SCION& scHdr, const L4& l4, std::span<const std::byte> payload)
    {
        auto chksum = scHdr.checksum((std::uint16_t)(l4.size() + payload.size()), L4::PROTO);
    #ifndef SCION_DISABLE_CHECKSUM
        m_scionHdrChksum = chksum;
    #endif
        chksum += l4.checksum();
        return hdr::details::internetChecksum(payload, chksum);
    }
};

} // namespace scion
