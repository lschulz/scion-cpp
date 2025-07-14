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

#include "scion/addr/isd_asn.hpp"

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <format>
#include <ostream>
#include <system_error>
#include <variant>


namespace scion {

enum class HostAddrType : std::uint8_t
{
    IPv4 = 0x0,
    IPv6 = 0x3,
};

template <typename Host> struct AddressTraits
{
    static_assert(sizeof(Host) < 0, "AddressTraits is not specialized for this type");
};

/// \brief Global SCION address consisting of an ISD-ASN and a host address.
/// \tparam T Type of AS-local host address.
template <typename T>
class Address
{
public:
    /// \brief Type of AS-local host addresses.
    using HostAddr = T;

private:
    IsdAsn m_ia;
    HostAddr m_host;

public:
    Address() = default;
    Address(IsdAsn isdAsn, HostAddr addr)
        : m_ia(isdAsn), m_host(std::move(addr))
    {}

    IsdAsn isdAsn() const { return m_ia; }
    IsdAsn& isdAsn() { return m_ia; }

    HostAddr host() const { return m_host; };
    HostAddr& host() { return m_host; };

    std::strong_ordering operator<=>(const Address<T>&) const = default;

    /// \brief Returns true if this endpoint does not contain an unspecified
    /// ISD-ASN or IP.
    bool isFullySpecified() const
    {
        return !m_ia.isUnspecified()
            && !AddressTraits<HostAddr>::isUnspecified(host());
    }

    /// \brief Returns true if this address is equal to `other`. Also returns
    /// true if the ISD-ASN or host address part does not match `other` but
    /// is unspecified (a wildcard address) in this address.
    bool matches(const Address<T>& other) const
    {
        if (!m_ia.matches(other.m_ia)) return false;
        return AddressTraits<HostAddr>::isUnspecified(m_host) || m_host == other.m_host;
    }

    /// \brief Parse SCION and host address separated by a comma.
    static Maybe<Address<T>> Parse(std::string_view text)
    {
        auto comma = text.find(',');
        if (comma == text.npos)
            return Error(ErrorCode::SyntaxError);

        auto m_ia = IsdAsn::Parse(text.substr(0, comma));
        if (isError(m_ia)) return propagateError(m_ia);

        auto m_host = AddressTraits<T>::fromString(text.substr(comma + 1));
        if (isError(m_host)) return propagateError(m_host);

        return Address<T>(get(m_ia), get(m_host));
    }

    std::uint32_t checksum() const
    {
        return m_ia.checksum() + AddressTraits<HostAddr>::checksum(m_host);
    }

    std::size_t size() const { return m_ia.size() + AddressTraits<HostAddr>::size(m_host); }

    friend std::formatter<scion::Address<T>>;
};

} // namespace scion

template<typename T>
struct std::formatter<scion::Address<T>>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::Address<T>& addr, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{},{}", addr.m_ia, addr.m_host);
    }
};

namespace scion {
template <typename T>
inline std::ostream& operator<<(std::ostream& stream, const Address<T>& addr)
{
    stream << std::format("{}", addr);
    return stream;
}
} // namespace scion

template <typename T>
struct std::hash<scion::Address<T>>
{
    std::size_t operator()(const scion::Address<T>& addr) const noexcept
    {
        std::size_t h = 0;
        h ^= hash<scion::IsdAsn>{}(addr.isdAsn());
        h ^= hash<T>{}(addr.host());
        return h;
    }
};
