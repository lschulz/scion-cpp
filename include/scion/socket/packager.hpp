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
#include "scion/addr/endpoint.hpp"
#include "scion/addr/generic_ip.hpp"
#include "scion/bit_stream.hpp"
#include "scion/details/debug.hpp"
#include "scion/error_codes.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/hdr/details.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/hdr/scmp.hpp"
#include "scion/hdr/stun.hpp"
#include "scion/path/raw.hpp"
#include "scion/socket/header_cache.hpp"
#include "scion/socket/parsed_packet.hpp"

#include <array>
#include <concepts>
#include <functional>
#include <memory>
#include <random>
#include <span>
#include <vector>


namespace scion {

template <typename F>
concept ScmpCallback = std::invocable<F,
    const ScIPAddress&,
    const RawPath&,
    const hdr::ScmpMessage&,
    std::span<const std::byte>>;

struct DefaultScmpCallback
{
    void operator()(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload)
    {
    #ifndef NDEBUG
        std::string str;
        str.reserve(512);
        std::back_insert_iterator out(str);
        std::visit([&](auto&& arg) -> auto {
            arg.print(out, 0);
        }, msg);
        SCION_DEBUG_PRINT("Received SCMP from " << from << "\n:" << str << std::endl);
    #endif
    }
};

/// \brief Contains SCION packet processing logic.
class ScionPackager
{
public:
    using Endpoint = scion::ScIPEndpoint;

    struct ScmpResponse
    {
        hdr::SCMP hdr;
        std::span<const std::byte> payload;
    };

private:
    // Value of traffic class (aka. QoS) field in the SCION header.
    std::uint8_t m_trafficClass = 0;

    // Local bind address. The IPEndpoint must not be unspecified in IP or port.
    Endpoint m_local;

    // Mapped address that is actually used on the wire. ISD and ASN are the
    // same as in m_local, but IP and port may differ due to NAT between the
    // host and border router.
    Endpoint m_mapped;

    // "Connected" remote endpoint. If set (not unspecified), packets from
    // endpoints not matching remote are rejected.
    Endpoint m_remote;

    // True if a STUN binding request was sent and we expect a reply.
    bool m_expectStunResponse = false;

    // IP address of the STUN server we expect a reply from.
    generic::IPAddress m_expectedStunServer;

    // STUN transaction ID for matching replies with the current request.
    std::array<std::byte, 12> m_stunTx = {};

public:
    /// \brief Set the local address. Must be called before sending or receiving
    /// packets. The local address may be used directly in the data plane, or it
    /// can be overridden by a mapped address in order to facilitate NAT
    /// traversal (see setMappedIpAndPort()). The local/mapped address is used
    /// as source address for sending packets and to filter received packets.
    ///
    /// The SCION ISD-ASN part of the address may be unspecified to facilitate
    /// SCION multi-homing. If the ISD-ASN is unspecified, calls to send use the
    /// first hop ISD-ASn contained in the given path as source address. The IP
    /// address and port of the endpoint must not be unspecified. Passing and
    /// unspecified IP or port results in an `InvalidArgument` error.
    std::error_code setLocalEp(const Endpoint& ep)
    {
        if (ep.host().isUnspecified()) return ErrorCode::InvalidArgument;
        if (ep.port() == 0) return ErrorCode::InvalidArgument;
        m_local = ep;
        m_mapped = ep;
        return ErrorCode::Ok;
    }

    /// \brief Set the host address and port after SNAT. If set to a different
    /// IP address and/or port than previously specified in setLocalEp(), the
    /// mapped IP and port are used in the SCION protocol instead of the local
    /// IP and port to enable limited NAT traversal.
    void setMappedIpAndPort(const Endpoint::LocalEp& mapped)
    {
        m_mapped = Endpoint(m_local.isdAsn(), mapped);
    }

    /// \brief Get the local SCION address and port of the socket. The SCION
    /// ISD-ASN part may be unspecified. The IP address and port may differ from
    /// the ones returned by mappedEp() if the there is a NAT between the local
    /// host and the destination.
    Endpoint localEp() const { return m_local; }

    /// \brief Returns the same address as localEp() if NAT traversal isn't in
    /// use. If a NAT mapping has been learned by requesting it with
    /// prepareStunRequest() and successfully receiving a response, the IP and
    /// port of this address reflect the mapped address that the border routers
    /// see.
    Endpoint mappedEp() const { return m_mapped; }

    /// \brief Set the expected remote address. Set to an unspecified address
    /// to dissolve the association.
    std::error_code setRemoteEp(const Endpoint& ep)
    {
        m_remote = ep;
        return ErrorCode::Ok;
    }

    Endpoint remoteEp() const { return m_remote; }

    /// \brief Set the traffic class (QoS field) for outgoing SCION packets.
    void setTrafficClass(std::uint8_t tc) { m_trafficClass = tc; }

    std::uint8_t trafficClass() const { return m_trafficClass; }

    /// \brief Calculate the total size of the SCION and L4 headers on the wire
    /// if a packet would be sent with the given parameters.
    template <
        typename Path,
        ext::extension_range ExtRange,
        typename L4>
    Maybe<std::size_t> measure(
        const Endpoint* to,
        const Path& path,
        ExtRange&& extensions,
        L4&& l4)
    {
        // Determine source address
        Endpoint from;
        if (auto ec = getSourceAddress(path, from); ec) {
            return Error(ec);
        }

        // Determine destination address
        if (!to) to = &m_remote;
        if (!to->address().isFullySpecified()) {
            return Error(ErrorCode::InvalidArgument);
        }

        return measureHeader(*to, from, path,
            std::forward<ExtRange>(extensions), std::forward<L4>(l4));
    }

    /// \brief Prepare a STUN binding request packet in `buf`. The request has
    /// a random transaction ID that will be expected in replies received by the
    /// unpack() function. Calling createStunRequest() again will reset the
    /// transaction ID so replies to old requests are no longer accepted.
    ///
    /// \param buf Buffer to hold the STUN request packet. Should be at least 20
    ///     bytes in size.
    /// \param stunServer STUN server IP for matching replies with requests.
    /// \returns ErrorCode::BufferTooSmall if `buf` is too small to hold the
    ///     request.
    ///
    /// After a STUN binding request has been send, unpack() will look for the
    /// corresponding reply. One a reply with a valid transaction ID has been
    /// received, unpack() returns ErrorCode::StunReceived, updates the mapped
    /// IP and port (retrieve with mappedEp()) and disable processing of further
    /// STUN responses. To renew the mapping, createStunRequest() has to be
    /// called again.
    std::error_code createStunRequest(
        std::span<std::byte> buf, const generic::IPAddress& stunServer)
    {
        hdr::STUN stun;
        stun.type = hdr::StunMsgType::BindingRequest;

        // Pick a new random transaction ID
        std::random_device rd;
        std::uniform_int_distribution<std::uint64_t> dist;
        auto rand = dist(rd);
        std::memcpy(stun.transaction.data(), &rand, 8);
        rand = dist(rd);
        std::memcpy(stun.transaction.data() + 8, &rand, 4);

        // Prepare STUN binding request
        WriteStream ws(buf);
        SCION_STREAM_ERROR err;
        if (!stun.serialize(ws, err)) {
            SCION_DEBUG_PRINT(err);
            return ErrorCode::BufferTooSmall;
        }

        m_expectStunResponse = true;
        m_expectedStunServer = stunServer;
        m_stunTx = stun.transaction;
        return ErrorCode::Ok;
    }

    /// \brief Prepare the packet headers for sending the given payload with the
    /// given parameters. If this method returned successfully, the
    /// concatenation of `header.data()` and `payload.data()` is avalid SCION
    /// packet ready to send on the underlay.
    ///
    /// \param headers
    ///     Storage for the generated packet headers.
    /// \param to
    ///     Destination address. Should not be null if a remote endpoint is set.
    /// \param path
    ///     Path to destination.
    /// \param extensions
    ///     Extension headers to be included.
    /// \param l4
    ///     Next header after SCION.
    /// \param payload
    ///     Intended packet payload.
    template <
        typename Path,
        ext::extension_range ExtRange,
        typename L4,
        typename Alloc>
    std::error_code pack(
        HeaderCache<Alloc>& headers,
        const Endpoint* to,
        const Path& path,
        ExtRange&& extensions,
        L4&& l4,
        std::span<const std::byte> payload)
    {
        // A concrete local address must have been bound.
        if (m_local.host().isUnspecified() || m_local.port() == 0) {
            return ErrorCode::NoLocalHostAddr;
        }

        // Determine source address
        Endpoint from;
        if (auto ec = getSourceAddress(path, from); ec) {
            return ec;
        }

        // Determine destination address
        if (!to) to = &m_remote;
        if (!to->address().isFullySpecified()) return ErrorCode::InvalidArgument;

        return headers.build(m_trafficClass, *to, from, path,
            std::forward<ExtRange>(extensions), std::forward<L4>(l4), payload);
    }

    /// \brief Prepare sending by updating the packet headers in `headers` with
    /// a new L4 header and payload.
    ///
    /// Care should be taken when updating the type or ports in the L4 header,
    /// as the new values are not going to be incorporated in the flow ID.
    /// If the flow ID should not stay the same, use the full pack() instead.
    template <typename L4, typename Alloc>
    std::error_code pack(
        HeaderCache<Alloc>& headers,
        L4&& l4,
        std::span<const std::byte> payload)
    {
        return headers.updatePayload(std::forward<L4>(l4), payload);
    }

    /// \brief Parse a SCION packet received from the underlay.
    ///
    /// \param buf
    ///     Raw SCION packet as received by the underlay. In the UDP/IP underlay
    ///     this is the UDP payload.
    /// \param ulSource
    ///     Underlay source address for verification of the SCION header.
    /// \param hbhExt
    ///     Hop-by-hop extensions to be parsed if present.
    /// \param e2eExt
    ///     End-to-end extensions to be parsed if present.
    /// \param from
    ///     Optional pointer to an endpoint that receives the packet's
    ///     destination.
    /// \param path
    ///     Optional pointer to a path to store the raw path from the SCION
    ///     header in.
    /// \param scmpCallback
    ///     Optional callable that is invoked if an SCMP packet was received
    ///     instead of the expected data.
    ///
    /// \returns Returns ScmpReceived if an SCMP packet was received. All output
    ///     are still valid in this case, but the payload is only passed to
    ///     the SCMP handler.
    ///
    ///     Returns StunReceived if a STUN packets was received.
    ///
    ///     If a packet was received, but the addresses in the SCION header do
    ///     not match the bound addresses, DstAddrMismatch or SrcAddrMismatch
    ///     are returned.
    ///
    ///     ChecksumError indicates a packet was received and parsed, but the
    ///     L4 checksum is incorrect.
    template <
        typename L4,
        ext::extension_range HbHExt,
        ext::extension_range E2EExt,
        ScmpCallback ScmpHandler = DefaultScmpCallback
    >
    Maybe<std::span<const std::byte>> unpack(
        std::span<const std::byte> buf,
        const generic::IPAddress& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        Endpoint* from,
        RawPath* path,
        ScmpHandler scmpCallback = DefaultScmpCallback())
    {
        ParsedPacket<L4> pkt;
        ReadStream rs(buf);
        SCION_STREAM_ERROR err;

        // Detect STUN packets multiplexed on the same port
        if (hdr::detectStun(buf)) {
            return Error(parseStun(rs, ulSource));
        }

        if (!pkt.parse(rs, err)) {
            SCION_DEBUG_PRINT(err);
            return Error(ErrorCode::InvalidPacket);
        }

        std::error_code ec;
        if ((ec = verifyReceived(pkt, ulSource))) return Error(ec);

        if (!hbhExt.empty()) {
            ReadStream rs(pkt.hbhOpts);
            if (!ext::parseExtensions(rs, std::forward<HbHExt>(hbhExt), err)) {
                SCION_DEBUG_PRINT(err);
                return Error(ErrorCode::InvalidPacket);
            }
        }
        if (!e2eExt.empty()) {
            ReadStream rs(pkt.hbhOpts);
            if (!ext::parseExtensions(rs, std::forward<E2EExt>(e2eExt), err)) {
                SCION_DEBUG_PRINT(err);
                return Error(ErrorCode::InvalidPacket);
            }
        }

        if (from) {
            std::uint16_t sport = 0;
            if (std::holds_alternative<L4>(pkt.l4))
                sport = std::get<L4>(pkt.l4).sport;
            *from = Endpoint(pkt.sci.src, sport);
        }
        if (path) {
            path->assign(
                pkt.sci.src.isdAsn(), pkt.sci.dst.isdAsn(),
                pkt.sci.ptype, pkt.path);
        }

        if (std::holds_alternative<hdr::SCMP>(pkt.l4)) {
            if (path) {
                scmpCallback(pkt.sci.src, *path, std::get<hdr::SCMP>(pkt.l4).msg, pkt.payload);
            } else {
                invokeScmpHandler(pkt, scmpCallback);
            }
            return Error(ErrorCode::ScmpReceived);
        }
        return pkt.payload;
    }

    /// \brief Parse STUN packets received from the underlay and ignore anything
    /// else.
    ///
    /// \param buf
    ///     Raw packet as received by the underlay. In the UDP/IP underlay
    ///     this is the UDP payload.
    /// \param ulSource
    ///     Underlay source address for verification of the STUN response.
    /// \returns ErrorCode::StunReceived is the expected STUN response has been
    ///     received.
    ///     ErrorCode::Pending if the packet did not contain STUN.
    ///     Other error code if parsing or validating a STUN response failed.
    std::error_code unpackStun(
        std::span<const std::byte> buf,
        const generic::IPAddress& ulSource)
    {
        if (hdr::detectStun(buf)) {
            ReadStream rs(buf);
            return parseStun(rs, ulSource);
        }
        return ErrorCode::Pending;
    }

private:
    template <typename Path>
    std::error_code getSourceAddress(const Path& path, Endpoint& from) const
    {
        if (m_mapped.isdAsn().isUnspecified()) {
            // Take the source ISD-ASN from path
            from = Endpoint(path.firstAS(), m_mapped.localEp());
        } else {
            if (!path.empty() && path.firstAS() != m_mapped.isdAsn()) {
                return ErrorCode::InvalidArgument;
            }
            from = m_mapped;
        }
        return ErrorCode::Ok;
    }

    template <typename L4>
    std::error_code verifyReceived(
        const ParsedPacket<L4>& pkt, const generic::IPAddress& ulSource)
    {
        using namespace hdr;
        if (!m_mapped.address().matches(pkt.sci.dst)) {
            return ErrorCode::DstAddrMismatch;
        }
        if (!std::holds_alternative<SCMP>(pkt.l4) && !m_remote.address().matches(pkt.sci.src)) {
            return ErrorCode::SrcAddrMismatch;
        }
        if (pkt.sci.ptype == PathType::Empty && ulSource.unmap4in6() != pkt.sci.src.host()) {
            // For AS-internal communication with empty paths underlay address
            // of the sender must match the source host addressin the SCION
            // header.
            return ErrorCode::InvalidPacket;
        }
    #ifndef SCION_DISABLE_CHECKSUM
        if (pkt.checksum() != 0xffffu) {
            return ErrorCode::ChecksumError;
        }
    #endif
        return ErrorCode::Ok;
    }

    template <typename L4, ScmpCallback ScmpHandler>
    void invokeScmpHandler(ParsedPacket<L4> pkt, ScmpHandler handler)
    {
        RawPath rp(pkt.sci.src.isdAsn(), pkt.sci.dst.isdAsn(), pkt.sci.ptype, pkt.path);
        handler(pkt.sci.src, rp, std::get<hdr::SCMP>(pkt.l4).msg, pkt.payload);
    }

    std::error_code parseStun(ReadStream& rs, const generic::IPAddress& ulSource)
    {
        SCION_STREAM_ERROR err;
        if (m_expectStunResponse) {
            if (ulSource != m_expectedStunServer) {
                SCION_DEBUG_PRINT("Received STUN packet from unexpected source\n");
                return ErrorCode::SrcAddrMismatch;
            }
            if (!updateMappedAddressFromStun(rs, err)) {
                SCION_DEBUG_PRINT(err);
                return ErrorCode::InvalidPacket;
            }
        } else {
            SCION_DEBUG_PRINT("Unexpected STUN packet received\n");
        }
        return ErrorCode::StunReceived;
    }

    template <typename Error = StreamError>
    bool updateMappedAddressFromStun(ReadStream& rs, Error& err)
    {
        hdr::STUN stun;
        if (!stun.serialize(rs, err)) return err.propagate();
        if (stun.type != hdr::StunMsgType::BindingResponse) {
            SCION_DEBUG_PRINT("Unexpected STUN message of type " << (int)stun.type << '\n');
            return true;
        }
        if (stun.transaction != m_stunTx) {
            SCION_DEBUG_PRINT("STUN response does not match expected transaction\n");
            return true;
        }
        m_expectStunResponse = false;
        if (stun.mapped) setMappedIpAndPort(stun.mapped->address);
        return true;
    }
};

} // namespace scion
