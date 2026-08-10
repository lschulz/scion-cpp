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
#include "scion/addr/generic_ip.hpp"

#include <cstdint>
#include <optional>


namespace scion {

/// \brief Prefix of all SCION-mapped IPv6 addresses
constexpr std::uint64_t SCION_IP_PREFIX = 0xfcull << 56;

/// \brief Types/formats of SCION-mapped IPv6 addresses.
enum class ScionIPv6Class
{
    /// Not a SCION-mapped IPv6 address
    INVALID = 0,
    /// 19-bit BGP ASN with IPv4 host address
    BGP_IPV4 = 1,
    /// 19-bit BGP ASN with 24-bit local prefix and 64-bit interface ID
    BGP_IPV6 = 2,
    /// 19-bit BGP ASN with 24-bit local prefix and no host address
    BGP_WILDCARD = 3,
    /// Wildcard ASN
    WILDCARD_ASN = 4,
    /// 32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with IPv4 host address
    PUBLIC_SCION_IPV4 = 13,
    /// 32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with 8-bit local prefix
    /// and 64-bit interface ID
    PUBLIC_SCION_IPV6 = 14,
    /// 32-bit SCION ASN between 2:0:0 and 2:ffff:ffff with no host address
    PUBLIC_SCION_WILDCARD = 15,
    /// Reserved SCION-mapped IPv6 address
    RESERVED = 255,
};

/// \brief Returns what type of SCION-mapped IPv6 address `ip` is, or INVALID
/// if `ip` is not a SCION-mapped IPv6 address.
inline ScionIPv6Class classifyScionMappedIP(const generic::IPAddress& ip)
{
    auto [prefix, iid] = ip.getIPv6();
    if ((prefix & (0xffull << 56)) != SCION_IP_PREFIX)
        return ScionIPv6Class::INVALID;

    auto flags = ((prefix >> 40) & 0xf);
    if ((flags & 0x8) == 0) {
        auto asn = ((prefix >> 24) & 0xfffff);
        if (asn == 0) return ScionIPv6Class::WILDCARD_ASN;
        if ((prefix & ~(~0 << 24)) == 0) {
            if (iid == 0)
                return ScionIPv6Class::BGP_WILDCARD;
            else if ((iid >> 32) == 0xffff)
                return ScionIPv6Class::BGP_IPV4;
        }
        return ScionIPv6Class::BGP_IPV6;
    } else if (flags == 0xe) {
        if ((prefix & ~(~0 << 8)) == 0) {
            if (iid == 0)
                return ScionIPv6Class::PUBLIC_SCION_WILDCARD;
            else if ((iid >> 32) == 0xffff)
                return ScionIPv6Class::PUBLIC_SCION_IPV4;
        }
        return ScionIPv6Class::PUBLIC_SCION_IPV6;
    } else {
        return ScionIPv6Class::RESERVED;
    }
}

/// \brief Extracts the ISD-ASN from a SCION-mapped IPv6 address.
/// \param ip Input address.
/// \param localPrefix If not NULL, localPrefix is set to the AS-local routing
/// prefix extracted from the IPv6 address. The length of this prefix depends
/// on the specific address.
/// \return The extracted ISD-ASN or any empty optional, if the address format
/// is of a reserved type.
inline std::optional<IsdAsn> unmapIsdAsn(
    const generic::IPAddress& ip, std::uint32_t* localPrefix = nullptr)
{
    auto [hi, lo] = ip.getIPv6();
    std::uint_fast16_t isd = ((hi >> 44) & 0xfff);
    std::uint64_t asn = 0;
    auto flags = ((hi >> 40) & 0xf);
    if ((flags & 0x8) == 0) {
        asn = ((hi >> 24) & 0xfffff);
        if (localPrefix) *localPrefix = hi & ~(~0 << 24);
    } else if (flags == 0xe) {
        asn = (2ull << 32) | ((hi >> 8) & 0xffff'ffff);
        if (localPrefix) *localPrefix = hi & ~(~0 << 8);
    } else {
        return std::nullopt; // reserved address
    }
    return IsdAsn(Isd(isd), Asn(asn));
}

/// \brief Statically map a full SCION address to an IPv6 address if such a
/// mapping is reversible without any additional information.
///
/// The mapping is only possible iff the ISD is smaller than 2^12, and the ASN
/// is either a BGP ASN < 2^19 or a SCION ASN in the range [2:0:0, 2:ffff:ffff].
/// Since the static mapping must be reversible without additional information
/// about the network, the host part must either be an IPv4 address or an IPv6
/// address that already is the SCION-mapped IPv6 itself.
///
/// \return The SCION-mapped IPv6 address if the conditions outlined above are
/// met and ErrorCode::InvalidArgument otherwise.
inline Maybe<generic::IPAddress> mapToIPv6(const ScIPAddress& addr)
{
    auto host = addr.host();
    if (host.is6()) {
        if (host.is4in6()) {
            // unmap v4-mapped IPv6 before mapping to SCION
            host = host.unmap4in6();
        } else if (!host.isScion()) {
            // can't map IPv6 without loosing parts of the address
            return Error(ErrorCode::InvalidArgument);
        } else if (auto isdAsn = unmapIsdAsn(host); !isdAsn || *isdAsn != addr.isdAsn()) {
            // host part is mapped address, but not the right one
            return Error(ErrorCode::InvalidArgument);
        } else {
            return host; // host part is already the mapped address
        }
    }

    std::uint64_t isd = addr.isdAsn().isd();
    if (!(isd < (1 << 12))) return Error(ErrorCode::InvalidArgument);

    std::uint64_t asn = addr.isdAsn().asn();
    std::uint64_t prefix = 0;
    if (asn < (1ull << 19)) {
        prefix = SCION_IP_PREFIX | (isd << 44) | (asn << 24);
    } else if (0x2'0000'0000ull <= asn && asn <= 0x2'ffff'ffffull) {
        prefix = SCION_IP_PREFIX | (isd << 44) | (0xeull << 40) | ((asn & 0xffff'ffff) << 8);
    } else {
        return Error(ErrorCode::InvalidArgument);
    }
    return generic::IPAddress::MakeIPv6(prefix, (0xffffull << 32) | host.getIPv4());
}

/// \brief The inverse of mapToIPv6(). Fails with ErrorCode::InvalidArgument
/// if `ip` is not a SCION-mapped IPv6. Fails with ErrorCode::NotImplemented
/// if `ip` is a SCION-mapped IPv6 if a reserved format.
inline Maybe<ScIPAddress> unmapFromIPv6(const generic::IPAddress& ip)
{
    using generic::IPAddress;
    auto [prefix, iid] = ip.getIPv6();
    if ((prefix & (0xffull << 56)) != SCION_IP_PREFIX)
        return Error(ErrorCode::InvalidArgument); // not the right prefix

    std::uint32_t localPrefix = 0;
    auto isdAsn = unmapIsdAsn(ip, &localPrefix);
    if (!isdAsn) return Error(ErrorCode::NotImplemented); // reserved address

    if (localPrefix == 0 && iid != 0 && (iid >> 32) == 0xffff) { // IPv4 host
        return ScIPAddress(*isdAsn, IPAddress::MakeIPv4((std::uint32_t)iid));
    } else { // IPv6 host
        return ScIPAddress(*isdAsn, ip);
    }
}

} // namespace scion
