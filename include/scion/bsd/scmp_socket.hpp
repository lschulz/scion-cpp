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
#include "scion/bsd/sockaddr.hpp"
#include "scion/bsd/socket.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/path/raw.hpp"
#include "scion/socket/packager.hpp"

#include <chrono>
#include <cstdint>
#include <ranges>
#include <span>


namespace scion {
namespace bsd {

template <typename Underlay = BSDSocket<IPEndpoint>>
class SCMPSocket
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
    /// \brief Bind to a local endpoint.
    /// \warning Wildcard IP addresses are not well supported and should be
    /// avoided. Unspecified ISD-ASN and port are supported.
    std::error_code bind(const Endpoint& ep)
    {
        return bind(ep, 0, 65535);
    }

    /// \brief Bind to a local endpoint. If no port is specified, try to pick
    /// one from the range [`firstPort`, `lastPort`].
    /// \warning Wildcard IP addresses are not well supported and should be
    /// avoided. Unspecified ISD-ASN and port are supported.
    std::error_code bind(
        const Endpoint& ep, std::uint16_t firstPort, std::uint16_t lastPort)
    {
        // Bind underlay socket
        auto underlayEp = generic::toUnderlay<UnderlayEp>(ep.getLocalEp());
        if (isError(underlayEp)) return getError(underlayEp);
        if constexpr (std::is_same_v<UnderlayAddr, sockaddr_in6>) {
            underlayEp->sin6_scope_id = scion::details::byteswapBE(
                ep.getAddress().getHost().getZoneId());
        } else if constexpr (std::is_same_v<UnderlayAddr, IPEndpoint>) {
            underlayEp->data.v6.sin6_scope_id = scion::details::byteswapBE(
                ep.getAddress().getHost().getZoneId());
        }
        auto err = socket.bind_range(*underlayEp, firstPort, lastPort);
        if (err) return err;

        // Find local address for SCION layer
        auto local = details::findLocalAddress(socket);
        if (isError(local)) return getError(local);

        // Propagate bound address and port to packet socket
        return packager.setLocalEp(Endpoint(ep.getIsdAsn(), local->getHost(), local->getPort()));
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

    /// \brief Returns the full address of the socket.
    Endpoint getLocalEp() const { return packager.getLocalEp(); }

    /// \brief Returns the address of the connected remote host.
    Endpoint geRemoteEp() const { return packager.getRemoteEp(); }

    /// \brief Set the traffic class of sent packets. Only affects the SCION
    /// header, not the underlay socket.
    void setTrafficClass(std::uint8_t tc) { packager.setTrafficClass(tc); }

    /// \brief Returns the current traffic class.
    std::uint8_t getTrafficClass() const { return packager.getTrafficClass(); }

    /// \copydoc BSDSocket::setNonblocking()
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

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendScmpToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        const hdr::ScmpMessage& message,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::SCMP(message), payload);
        if (ec) return Error(ec);
        return sendUnderlay(headers.get(), payload, nextHop);
    }

    Maybe<std::span<std::byte>> recvScmpFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        hdr::ScmpMessage& message)
    {
        return recvScmpImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, message);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvScmpFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        hdr::ScmpMessage& message)
    {
        return recvScmpImpl(buf, &from, &path, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), message);
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
        hdr::ScmpMessage& message)
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
            auto recvd = socket.recvfrom(buf, ulSource);
            if (isError(recvd)) return propagateError(recvd);
            auto decoded = packager.unpack<hdr::UDP>(get(recvd),
                generic::toGenericAddr(EndpointTraits<UnderlayEp>::getHost(ulSource)),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), from, path, scmp);
            if (isError(decoded) && getError(decoded) == ErrorCode::ScmpReceived) {
                return payload;
            }
        }
    }

protected:
    Maybe<std::span<const std::byte>> sendUnderlay(
        std::span<const std::byte> headers,
        std::span<const std::byte> payload,
        const UnderlayEp& nextHop)
    {
        auto sent = socket.sendmsg(nextHop, 0, headers, payload);
        if (isError(sent)) return propagateError(sent);
        auto n = get(sent) - (std::uint64_t)headers.size();
        if (n < 0) return Error(ErrorCode::PacketTooBig);
        return payload.subspan(0, n);
    }
};

} // namespace bsd
} // namespace scion
