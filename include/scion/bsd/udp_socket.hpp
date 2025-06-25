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

#include "scion/bsd/scmp_socket.hpp"
#include "scion/scmp/handler.hpp"

#include <cstdint>
#include <format>
#include <ranges>
#include <span>


namespace scion {
namespace bsd {

/// \brief A UDP SCION socket backed by the BSD socket interface.
template <typename Underlay = bsd::BSDSocket<IPEndpoint>>
class UDPSocket : public SCMPSocket<Underlay>
{
public:
    using UnderlayEp = typename Underlay::SockAddr;
    using UnderlayAddr = typename EndpointTraits<UnderlayEp>::HostAddr;
    using Endpoint = scion::ScIPEndpoint;
    using Address = scion::ScIPAddress;

protected:
    ScmpHandler* scmpHandler;

private:
    using SCMPSocket<Underlay>::socket;
    using SCMPSocket<Underlay>::packager;

public:
    void setNextScmpHandler(ScmpHandler* handler) { scmpHandler = handler; }
    ScmpHandler* nextScmpHandler() const { return scmpHandler; }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> send(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, nullptr, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendExt(
        HeaderCache<Alloc>& headers,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, nullptr, path, std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, typename Alloc>
    Maybe<std::span<const std::byte>> sendTo(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, ext::NoExtensions, hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Path, ext::extension_range ExtRange, typename Alloc>
    Maybe<std::span<const std::byte>> sendToExt(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const Path& path,
        const UnderlayEp& nextHop,
        ExtRange&& extensions,
        std::span<const std::byte> payload)
    {
        auto ec = packager.pack(
            headers, &to, path, std::forward<ExtRange>(extensions), hdr::UDP{}, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendCached(
        HeaderCache<Alloc>& headers,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        hdr::UDP udp;
        udp.sport = packager.getLocalEp().getPort();
        udp.dport = packager.getRemoteEp().getPort();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    template <typename Alloc>
    Maybe<std::span<const std::byte>> sendToCached(
        HeaderCache<Alloc>& headers,
        const Endpoint& to,
        const UnderlayEp& nextHop,
        std::span<const std::byte> payload)
    {
        hdr::UDP udp;
        udp.sport = packager.getLocalEp().getPort();
        udp.dport = to.getPort();
        auto ec = packager.pack(headers, udp, payload);
        if (ec) return Error(ec);
        return SCMPSocket<Underlay>::sendUnderlay(headers.get(), payload, nextHop);
    }

    Maybe<std::span<std::byte>> recv(std::span<std::byte> buf)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvExt(
        std::span<std::byte> buf,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, nullptr, nullptr, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt));
    }

    Maybe<std::span<std::byte>> recvFrom(
        std::span<std::byte> buf,
        Endpoint& from)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvFromExt(
        std::span<std::byte> buf,
        Endpoint& from,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt)
    {
        UnderlayEp ulSource;
        return recvImpl(buf, &from, nullptr, ulSource,
            std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt));
    }

    Maybe<std::span<std::byte>> recvFromVia(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource)
    {
        return recvImpl(buf, &from, &path, ulSource, ext::NoExtensions, ext::NoExtensions);
    }

    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvFromViaExt(
        std::span<std::byte> buf,
        Endpoint& from,
        RawPath& path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt)
    {
        return recvImpl(buf, &from, &path, ulSource, hbhExt, e2eExt);
    }

private:
    template <ext::extension_range HbHExt, ext::extension_range E2EExt>
    Maybe<std::span<std::byte>> recvImpl(
        std::span<std::byte> buf,
        Endpoint* from,
        RawPath* path,
        UnderlayEp& ulSource,
        HbHExt&& hbhExt,
        E2EExt&& e2eExt)
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
            auto recvd = socket.recvfrom(buf, ulSource);
            if (isError(recvd)) return propagateError(recvd);
            auto payload = packager.template unpack<hdr::UDP>(get(recvd),
                generic::toGenericAddr(EndpointTraits<UnderlayEp>::getHost(ulSource)),
                std::forward<HbHExt>(hbhExt), std::forward<E2EExt>(e2eExt),
                from, path, scmpCallback);
            if (payload.has_value()) {
                return std::span<std::byte>{
                    const_cast<std::byte*>(payload->data()),
                    payload->size()
                };
            }
            if (getError(payload) != ErrorCode::ScmpReceived) {
                SCION_DEBUG_PRINT((std::format(
                    "Received invalid packet from {}: {}\n", ulSource, fmtError(getError(payload)))));
            }
        }
    }
};

} // namespace bsd
} // namespace scion
