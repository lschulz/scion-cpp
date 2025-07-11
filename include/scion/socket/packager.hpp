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
#include "scion/path/raw.hpp"
#include "scion/socket/header_cache.hpp"
#include "scion/socket/parsed_packet.hpp"

#include <array>
#include <concepts>
#include <functional>
#include <memory>
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
    std::uint8_t trafficClass = 0;
    // Local bind address. The IPEndpoint must not be unspecified in IP or port.
    Endpoint local;
    // "Connected" remote endpoint. If set (not unspecified), packets from
    // endpoints not matching remote are rejected.
    Endpoint remote;

public:
    /// \brief Set the local address. The local address is used as source
    /// address for sent packets and to filter received packets.
    ///
    /// The SCION ISD-ASN part of the address may be unspecified to facilitate
    /// SCION multi-homing. If the ISD-ASn is unspecified, calls to send use the
    /// first hop ISD-ASn contained in the given path as source address. The IP
    /// address and port of the endpoint must not be unspecified. Passing and
    /// unspecified IP or port results in an `InvalidArgument` error.
    std::error_code setLocalEp(const Endpoint& ep)
    {
        if (ep.getHost().isUnspecified()) return ErrorCode::InvalidArgument;
        if (ep.getPort() == 0) return ErrorCode::InvalidArgument;
        local = ep;
        return ErrorCode::Ok;
    }

    Endpoint getLocalEp() const { return local; }

    /// \brief Set the expected remote address. Set to an unspecified address
    /// to dissolve the association.
    std::error_code setRemoteEp(const Endpoint& ep)
    {
        remote = ep;
        return ErrorCode::Ok;
    }

    Endpoint getRemoteEp() const { return remote; }

    /// \brief Set the traffic class (QoS field) for outgoing SCION packets.
    void setTrafficClass(std::uint8_t tc) { trafficClass = tc; }

    std::uint8_t getTrafficClass() const { return trafficClass; }

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
        if (local.getHost().isUnspecified() || local.getPort() == 0) {
            return ErrorCode::NoLocalHostAddr;
        }

        // Determine source address
        Endpoint from;
        if (local.getIsdAsn().isUnspecified()) {
            // Take the source ISD-ASN from path
            from = Endpoint(path.firstAS(), local.getLocalEp());
        } else {
            if (!path.empty() && path.firstAS() != local.getIsdAsn()) {
                return ErrorCode::InvalidArgument;
            }
            from = local;
        }

        // Determine destination address
        if (!to) {
            if (!remote.getAddress().isFullySpecified()) return ErrorCode::InvalidArgument;
            to = &remote;
        } else {
            if (!to->getAddress().isFullySpecified()) return ErrorCode::InvalidArgument;
        }

        return headers.build(trafficClass, *to, from, path,
            std::forward<ExtRange>(extensions), std::forward<L4>(l4), payload);
    }

    /// \brief Prepare sending by updating the packet headers in `headers` with
    /// a new L4 header and payload.
    ///
    /// Care should be taken when updating the type or ports in the L4 header,
    /// as the new values are not going to be incorporated in the flow ID.
    /// If the flow ID should not stay the same, use the full prepareSend()
    /// instead.
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
    ///     Underlay payload, i.e., the packet starting from the SCION header.
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
    /// \param scmp
    ///     Optional callable that is invoked if an SCMP packet was received
    ///     instead of the expected data.
    ///
    /// \return Returns ScmpReceived if an SCMP packet was received. All output
    ///     are still valid in this case, but the payload is only passed to
    ///     the SCMP handler.
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
                pkt.sci.src.getIsdAsn(), pkt.sci.dst.getIsdAsn(),
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

private:
    template <typename L4>
    std::error_code verifyReceived(
        const ParsedPacket<L4>& pkt, const generic::IPAddress& ulSource)
    {
        if (!local.getAddress().matches(pkt.sci.dst)) {
            return ErrorCode::DstAddrMismatch;
        }
        if (!remote.getAddress().matches(pkt.sci.src)) {
            return ErrorCode::SrcAddrMismatch;
        }
        if (pkt.sci.ptype == hdr::PathType::Empty && ulSource != pkt.sci.src.getHost()) {
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
        RawPath rp(pkt.sci.src.getIsdAsn(), pkt.sci.dst.getIsdAsn(), pkt.sci.ptype, pkt.path);
        handler(pkt.sci.src, rp, std::get<hdr::SCMP>(pkt.l4).msg, pkt.payload);
    }
};

} // namespace scion
