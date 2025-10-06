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

#include "scion/posix/scmp_socket.hpp"
#include "scion/scmp/handler.hpp"
#include "scion/socket/flags.hpp"

#include <cstdint>
#include <format>
#include <ranges>
#include <span>


namespace scion {
namespace posix {

/// \brief A UDP SCION socket backed by the POSIX socket interface.
template <typename Underlay = PosixSocket<IPEndpoint>>
class UdpSocket : public ScmpSocket<Underlay>
{
public:
    using UnderlayEp = typename Underlay::SockAddr;
    using UnderlayAddr = typename EndpointTraits<UnderlayEp>::HostAddr;
    using Endpoint = scion::ScIPEndpoint;
    using Address = scion::ScIPAddress;

protected:
    ScmpHandler* scmpHandler = nullptr;

private:
    using ScmpSocket<Underlay>::socket;
    using ScmpSocket<Underlay>::packager;

public:
    using ScmpSocket<Underlay>::ScmpSocket;

    ScmpHandler* setNextScmpHandler(ScmpHandler* handler)
    {
        scmpHandler = handler;
        return handler;
    }

    ScmpHandler* nextScmpHandler() const { return scmpHandler; }

    template <typename Path>
    Maybe<std::size_t> measure(const Path& path)
    {
        return packager.measure(nullptr, path, ext::NoExtensions, hdr::UDP{});
    }

    template <typename Path, ext::extension_range ExtRange>
    Maybe<std::size_t> measureExt(
        const Path& path,
        ExtRange&& extensions)
    {
        return packager.measure(nullptr, path, std::forward<ExtRange>(extensions), hdr::UDP{});
    }

    template <typename Path>
    Maybe<std::size_t> measureTo(
        const Endpoint& to,
        const Path& path)
    {
        return packager.measure(&to, path, ext::NoExtensions, hdr::UDP{});
    }

    template <typename Path, ext::extension_range ExtRange>
    Maybe<std::size_t> measureToExt(
        const Endpoint& to,
        const Path& path,
        ExtRange&& extensions)
    {
        return packager.measure(&to, path, std::forward<ExtRange>(extensions), hdr::UDP{});
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> send(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        auto ec = packager.pack(
            headers, nullptr, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendExt(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        auto ec = packager.pack(
            headers, nullptr, path, std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendCached(
        HeaderCache<Alloc>& headers,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        hdr::UDP udp;
        udp.sport = packager.localEp().port();
        udp.dport = packager.remoteEp().port();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendToCached(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload,
        int flags = 0)
    {
        hdr::UDP udp;
        udp.sport = packager.localEp().port();
        udp.dport = to.port();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return ScmpSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop, flags);
    }

    Maybe<std::span<std::byte>> recv(std::span<std::byte> buf, int flags = 0)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource,
            ext::NoExtensions, ext::NoExtensions, flags);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvExt(
        std::span<std::byte> buf,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        int flags = 0)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), flags);
    }

    Maybe<std::span<std::byte>> recvFrom(
        std::span<std::byte> buf,
        Endpoint& from,
        int flags = 0)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource,
            ext::NoExtensions, ext::NoExtensions, flags);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvFromExt(
        std::span<std::byte> buf,
        Endpoint& from,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        int flags = 0)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt), flags);
    }

    Maybe<std::span<std::byte>> recvFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        int flags = 0)
    {
        return recvImpl(buf, &from, &path, ulSource,
            ext::NoExtensions, ext::NoExtensions, flags);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        int flags = 0)
    {
        return recvImpl(buf, &from, &path, ulSource, hbhExt, e2eExt, flags);
    }

private:
    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt,
        int flags = 0)
    {
        auto scmpCallback = [this] (
            const scion::ScIPAddress& from,
            const RawPath& path,
            const hdr::ScmpMessage& msg,
            std::span<const std::byte> payload)
        {
            if (scmpHandler) scmpHandler->handleScmp(from, path, msg, payload);
        };
        while (true) {
            auto recvd = socket.recvfrom(buf, ulSource, flags & ~MSG_RECV_SCMP);
            if (isError(recvd)) return propagateError(recvd);
            auto payload = packager.template unpack<hdr::UDP>(get(recvd),
                generic::toGenericAddr(EndpointTraits<UnderlayEp>::host(ulSource)),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt),
                from, path, scmpCallback);
            if (payload.has_value()) {
                return std::span<std::byte>{
                    const_cast<std::byte*>(payload->data()),
                    payload->size()
                };
            } else if (flags & MSG_PEEK) {
                // discard the peeked packet from the receive queue
                (void)socket.recvfrom(buf, ulSource, flags & ~MSG_PEEK);
            }
            if (getError(payload) == ErrorCode::ScmpReceived) {
                if (flags & MSG_RECV_SCMP) return propagateError(payload);
            } else {
                SCION_DEBUG_PRINT((std::format("Received invalid packet from {}: {}\n",
                    ulSource, fmtError(getError(payload)))));
            }
        }
    }
};

/// \brief SCION UDP socket with IPv4/IPv6 UDP underlay.
using IpUdpSocket = UdpSocket<PosixSocket<IPEndpoint>>;

} // namespace posix
} // namespace scion
