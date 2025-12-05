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
#include "scion/extensions/extension.hpp"
#include "scion/path/raw.hpp"
#include "scion/posix/sockaddr.hpp"
#include "scion/posix/underlay.hpp"
#include "scion/socket/flags.hpp"
#include "scion/socket/packager.hpp"

#include <chrono>
#include <cstdint>
#include <ranges>
#include <span>


namespace scion {
namespace posix {

template <typename Underlay = PosixSocket<IPEndpoint>>
class ScmpSocket
{
public:
    using UnderlayEp = typename Underlay::SockAddr;
    using UnderlayAddr = typename EndpointTraits<UnderlayEp>::HostAddr;
    using Endpoint = scion::ScIPEndpoint;
    using Address = scion::ScIPAddress;

protected:
    Underlay socket;
    ScionPackager packager;

public:
    /// \brief Initializes the socket, but does not yet create or open the
    /// underlay socket. The socket is only opened on calling bind().
    ScmpSocket() = default;

    /// \brief Initializes the socket and takes ownership of `underlaySocket`.
    explicit ScmpSocket(Underlay&& underlaySocket)
        : socket(std::move(underlaySocket))
    {}

    /// \brief Bind to a local endpoint.
    /// \details See bind(const Endpoint&, std::uint16_t, std::uint16_t, const
    /// UnderlayAddr*) for more details.
    std::error_code bind(const Endpoint& ep, const UnderlayAddr* underlay = nullptr)
    {
        return bind(ep, 0, 65535, underlay);
    }

    /// \brief Bind to a local endpoint. If no port is specified, try to pick
    /// one from the range [`firstPort`, `lastPort`].
    /// \param ep SCION endpoint to bind to. This address is used as the source
    /// address in the SCION address header. Wildcard IP addresses (0.0.0.0,
    /// ::0) should be avoided as the implementation will have to guess an
    /// appropriate IP address to put in the SCION header. Unspecified ISD-ASN
    /// (0-0) and port (0) are supported. If the underlay socket should be bound
    /// to a different interface (including *all* interfaces) than determined by
    /// the IP specified here, use the `underlay` paramater.
    /// \param underlay Optional bind address for the underlay UDP socket. By
    /// default this is `ep.host()`. The port is determined from `ep` or if
    /// unspecified selected automatically from the range [`firstPort`,
    /// `lastPort`]. Wildcard addresses are accepted.
    std::error_code bind(
        const Endpoint& ep, std::uint16_t firstPort, std::uint16_t lastPort,
        const UnderlayAddr* underlay = nullptr)
    {
        // Bind underlay socket
        if (underlay) {
            auto underlayEp = EndpointTraits<UnderlayEp>::fromHostPort(*underlay, ep.port());
            auto err = socket.bind_range(underlayEp, firstPort, lastPort);
            if (err) return err;
        } else {
            auto underlayEp = generic::toUnderlay<UnderlayEp>(ep.localEp());
            if (isError(underlayEp)) return getError(underlayEp);
            if constexpr (std::is_same_v<UnderlayAddr, sockaddr_in6>) {
                underlayEp->sin6_scope_id = scion::details::byteswapBE(
                    ep.address().host().zoneId());
            } else if constexpr (std::is_same_v<UnderlayAddr, IPEndpoint>) {
                underlayEp->data.v6.sin6_scope_id = scion::details::byteswapBE(
                    ep.address().host().zoneId());
            }
            auto err = socket.bind_range(*underlayEp, firstPort, lastPort);
            if (err) return err;
        }

        // Find local address for SCION layer
        generic::IPAddress addr = ep.host();
        std::uint16_t port = ep.port();
        if (addr.isUnspecified() || port == 0) {
            auto local = details::findLocalAddress(socket);
            if (isError(local)) return getError(local);
            if (addr.isUnspecified())
                addr = local->host();
            if (port == 0)
                port = local->port();
        }

        // Propagate bound address and port to packet socket
        return packager.setLocalEp(Endpoint(ep.isdAsn(), addr.unmap4in6(), port));
    }

    /// \brief Set or change the local address without actually binding the
    /// underlay socket. The local address is used as source address for sent
    /// packets and to filter received packets.
    ///
    /// \copydetails ScionPackager::setLocalEp()
    ///
    /// \warning This is a low-level operation, most clients should simply call
    /// bind.
    std::error_code setLocalEp(const Endpoint& ep)
    {
        if (ep.host().is4in6()) {
            return packager.setLocalEp(Endpoint(ep.isdAsn(), ep.host().unmap4in6(), ep.port()));
        } else {
            return packager.setLocalEp(ep);
        }
    }

    /// \brief Set the host address and port after SNAT to facilitate NAT
    /// traversal. NAT traversal can be disabled by setting this address to
    /// the same IP and port as returned by localEp() again.
    void setMappedIpAndPort(const Endpoint::LocalEp& mapped)
    {
        packager.setMappedIpAndPort(mapped);
    }

    /// \brief Locally store a default remote address. Receive methods will only
    /// return packets from the "connected" address. Can be called multiple
    /// times to change the remote address or with an unspecified address to
    /// remove again receive from all possible remotes.
    std::error_code connect(const Endpoint& ep)
    {
        return packager.setRemoteEp(ep);
    }

    /// \brief Close the underlay socket.
    void close()
    {
        socket.close();
    }

    /// \brief Determine whether the socket is open.
    bool isOpen() const { return socket.isOpen(); }

    /// \brief Get the native handle of the underlay socket.
    NativeHandle underlaySocket() { return socket.underlaySocket(); }

    /// \brief Returns the full local address of the socket.
    Endpoint localEp() const { return packager.localEp(); }

    /// \brief Returns the local address after SNAT. Differs from localEp() if
    /// and only if NAT traversal is active.
    Endpoint mappedEp() const { return packager.localEp(); }

    /// \brief Returns the address of the connected remote host.
    Endpoint remoteEp() const { return packager.remoteEp(); }

    /// \brief Set the traffic class of sent packets. Only affects the SCION
    /// header, not the underlay socket.
    void setTrafficClass(std::uint8_t tc) { packager.setTrafficClass(tc); }

    /// \brief Returns the current traffic class.
    std::uint8_t trafficClass() const { return packager.trafficClass(); }

    /// \copydoc PosixSocket::setNonblocking()
    std::error_code setNonblocking(bool nonblocking)
    {
        return socket.setNonblocking(nonblocking);
    }

    /// \brief Set a timeout on receive operations. Must be called after the
    /// underlay socket was created by calling `bind()`.
    std::error_code setRecvTimeout(std::chrono::microseconds timeout)
    {
    #if _WIN32
        auto t = (DWORD)(timeout.count() / 1000);
        return socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&t), sizeof(t));
    #else
        struct timeval t;
        t.tv_sec = timeout.count() / 1'000'000;
        t.tv_usec = timeout.count() % 1'000'000;
        return socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&t), sizeof(t));
    #endif
    }

    template <typename Path>
    Maybe<std::size_t> measureScmpTo(
        const Endpoint& to,
        const Path& path,
        const hdr::ScmpMessage& message)
    {
        return packager.measure(&to, path, ext::NoExtensions, hdr::SCMP(message));
    }

    template <typename Path, ext::extension_range ExtRange>
    Maybe<std::size_t> measureScmpToExt(
        const Endpoint& to,
        const Path& path,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message)
    {
        return packager.measure(&to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message));
    }

    /// \brief Send a STUN binding request to the given router and prepare the
    /// recv* methods to expect a STUN response.
    std::error_code requestStunMapping(const UnderlayEp& router)
    {
        std::array<std::byte, 20> buffer;
        std::span<std::byte> span(buffer.data(), buffer.size());
        auto server = generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(router));
        auto ec = packager.createStunRequest(span, server);
        if (ec) return ec;
        auto res = sendUnderlay(span, std::span<std::byte>(), router);
        if (isError(res)) return res.error();
        return ErrorCode::Ok;
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_CONFIRM | SMSG_DONTWAIT | SMSG_NOSIGNAL))
            return Error(ErrorCode::InvalidArgument);
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_CONFIRM | SMSG_DONTWAIT | SMSG_NOSIGNAL))
            return Error(ErrorCode::InvalidArgument);
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    /// \brief Receive packets until a STUN response matching the last request
    /// made with requestStunMapping() is found.
    std::error_code recvStunResponse(MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~SMSG_DONTWAIT) return ErrorCode::InvalidArgument;
        std::array<std::byte, 128> buf;
        UnderlayEp ulSource;
        while (true) {
            auto recvd = socket.recvfrom(
                std::span<std::byte>(buf.data(), buf.size()), ulSource, flags);
            if (isError(recvd)) return recvd.error();
            auto server = generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(ulSource));
            auto ec = packager.unpackStun(*recvd, server);
            if (ec == ErrorCode::StunReceived) return ec;
            else if (ec != ErrorCode::Pending) return ec;
        }
    }

    Maybe<std::span<std::byte>> recvScmpFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_DONTWAIT | SMSG_PEEK | SMSG_RECV_SCMP | SMSG_RECV_STUN))
            return Error(ErrorCode::InvalidArgument);
        return recvScmpImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message, flags);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        if (flags & ~(SMSG_DONTWAIT | SMSG_PEEK | SMSG_RECV_SCMP | SMSG_RECV_STUN))
            return Error(ErrorCode::InvalidArgument);
        return recvScmpImpl(buf, &from, &path, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), message, flags);
    }

private:
    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        std::span<std::byte> payload;
        auto scmp = [&] (const Address& from, const RawPath& path,
            const hdr::ScmpMessage& msg, std::span<const std::byte> data)
        {
            message = msg;
            payload = std::span<std::byte>{
                const_cast<std::byte*>(data.data()),
                data.size()
            };
        };

        while (true) {
            auto recvd = socket.recvfrom(buf, ulSource, flags & ~SMSG_SCION_ALL);
            if (isError(recvd)) return propagateError(recvd);
            auto decoded = packager.unpack<hdr::UDP>(get(recvd),
                generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(ulSource)),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), from, path, scmp);
            if (isError(decoded)) {
                if (getError(decoded) == ErrorCode::ScmpReceived) {
                    return payload;
                } else if (getError(decoded) == ErrorCode::StunReceived) {
                    if (flags & SMSG_RECV_STUN) return propagateError(decoded);
                }
            } else if (flags & SMSG_PEEK) {
                // discard the peeked packet from the receive queue
                (void)socket.recvfrom(buf, ulSource, flags & ~(SMSG_PEEK | SMSG_SCION_ALL));
            }
        }
    }

protected:
    Maybe<std::span<const std::byte>> sendUnderlay(
        std::span<const std::byte> headers,
        std::span<const std::byte> payload,
        const UnderlayEp& nextHop,
        MsgFlags flags = SMSG_NO_FLAGS)
    {
        auto sent = socket.sendmsg(nextHop, flags, headers, payload);
        if (isError(sent)) return propagateError(sent);
        auto n = get(sent) - (std::uint64_t)headers.size();
        if (n < 0) return Error(ErrorCode::PacketTooBig);
        return payload.subspan(0, n);
    }
};

/// \brief Try to get the mapped address of this socket by sending STUN binding
/// requests to a STUN server (usually a SCION border router). This function
/// blocks until the mapping has been found or a set number of retries has been
/// exhausted. To query the STUN server without blocking, use
/// requestStunMapping() directly instead.
///
/// \note This function sets the socket to blocking mode and manipulates the
/// receive timeout. Callers should set a new receive timeout after this
/// function returns and restore to socket to non-blocking mode if desired.
///
/// \param router STUN server to query. Usually the STUN server should be
///     colocated with a border router. The default port for STUN is 3478,
///     but some ASes might use a different port.
/// \param rto Retransmission Timeout. How long to wait for a response
///     before retransmitting the request. The RTO is doubled after each
///     retransmission.
/// \param retry Maximum number of retries.
/// \returns The mapped address if a valid response was received.
///     ErrorCondition::Timeout if the maximum number of retries was
///     exhausted.
template <typename Underlay>
Maybe<ScIPEndpoint> getStunMapping(ScmpSocket<Underlay>& socket,
    const typename Underlay::SockAddr& router,
    std::chrono::milliseconds rto,
    unsigned int retry = 5)
{
    std::error_code ec;
    ec = socket.setNonblocking(false);
    if (ec) return Error(ec);
    for (unsigned int i = 0; i <= retry; ++i)
    {
        ec = socket.requestStunMapping(router);
        if (ec) return Error(ec);
        ec = socket.setRecvTimeout(rto);
        if (ec) return Error(ec);
        ec = socket.recvStunResponse();
        if (ec == ErrorCode::StunReceived) return socket.mappedEp();
        else if (ec != ErrorCondition::Timeout) return Error(ec);
        rto *= 2;
    }
    return Error(ErrorCode::Timeout);
}

/// \brief SCMP socket with IPv4/IPv6 UDP underlay.
using IpScmpSocket = ScmpSocket<PosixSocket<IPEndpoint>>;

} // namespace posix
} // namespace scion
