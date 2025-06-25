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

#include <concepts>
#include <cstdint>
#include <format>
#include <ostream>
#include <ranges>
#include <system_error>
#include <variant>


namespace scion {

template <typename Ep> struct EndpointTraits
{
    static_assert(sizeof(Ep) < 0, "EndpointTraits is not specialized for this type");
};

namespace details {
Maybe<std::pair<std::string_view, std::uint16_t>> splitHostPort(std::string_view text);
}

/// \brief Global UDP or TCP endpoint address consisting of ISD-ASN, host
/// address, and port.
/// \tparam T Type of AS-local endpoints.
template <typename T>
class Endpoint
{
public:
    /// \brief Type of underlying AS-local endpoint.
    using LocalEp = T;

    /// \brief Type of AS-local host addresses.
    using HostAddr = EndpointTraits<LocalEp>::HostAddr;

    /// \brief Corresponding SCION host address type.
    using ScionAddr = EndpointTraits<LocalEp>::ScionAddr;

private:
    IsdAsn ia;
    LocalEp ep;

public:
    Endpoint() = default;

    Endpoint(IsdAsn isdAsn, LocalEp endpoint)
        : ia(isdAsn), ep(std::move(endpoint))
    {}

    Endpoint(const ScionAddr& addr, std::uint16_t port)
        : ia(addr.getIsdAsn())
        , ep(EndpointTraits<LocalEp>::fromHostPort(addr.getHost(), port))
    {}

    Endpoint(IsdAsn isdAsn, const HostAddr& host, std::uint16_t port)
        : ia(isdAsn)
        , ep(EndpointTraits<LocalEp>::fromHostPort(host, port))
    {}

    IsdAsn getIsdAsn() const { return ia; }
    LocalEp getLocalEp() const { return ep; }
    ScionAddr getAddress() const { return ScionAddr(getIsdAsn(), getHost()); }
    HostAddr getHost() const { return EndpointTraits<LocalEp>::getHost(ep); }
    std::uint16_t getPort() const { return EndpointTraits<LocalEp>::getPort(ep); }

    std::strong_ordering operator<=>(const Endpoint<T>&) const = default;

    /// \brief Returns true if this endpoint does not contain an unspecified
    /// ISD-ASN, IP, or port.
    bool isFullySpecified() const
    {
        return !ia.isUnspecified()
            && !AddressTraits<HostAddr>::isUnspecified(getHost())
            && getPort() != 0;
    }

    /// \brief Parse a SCION endpoint with optional port. If no port is given, the
    /// port is set to 0.
    static Maybe<Endpoint<T>> Parse(std::string_view text)
    {
        auto split = details::splitHostPort(text);
        if (isError(split)) return propagateError(split);
        auto [addr, port] = *split;

        auto sc = ScionAddr::Parse(addr);
        if (isError(sc)) return propagateError(sc);
        return Endpoint<T>(get(sc), port);
    }

    friend struct std::formatter<Endpoint<T>>;
};

template <typename T>
std::ostream& operator<<(std::ostream& stream, const scion::Endpoint<T>& ep)
{
    stream << std::format("{}", ep);
    return stream;
}

} // namespace scion

template<typename T>
struct std::formatter<scion::Endpoint<T>>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::Endpoint<T>& ep, auto& ctx) const
    {
        using AddressTraits = scion::AddressTraits<typename scion::Endpoint<T>::HostAddr>;
        if (AddressTraits::type(ep.getHost()) == scion::HostAddrType::IPv4) {
            return std::format_to(ctx.out(), "{},{}:{}", ep.ia, ep.getHost(), ep.getPort());
        } else {
            return std::format_to(ctx.out(), "[{},{}]:{}", ep.ia, ep.getHost(), ep.getPort());
        }
    }
};
template <typename T>
struct std::hash<scion::Endpoint<T>>
{
    std::size_t operator()(const scion::Endpoint<T>& ep) const noexcept
    {
        std::size_t h = 0;
        h ^= hash<scion::IsdAsn>{}(ep.getIsdAsn());
        h ^= hash<T>{}(ep.getLocalEp());
        return h;
    }
};
