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

/// \brief Extracts the ISD-ASN from a SCION-mapped IPv6 address.
inline IsdAsn unmapIsdAsn(const generic::IPAddress& ip)
{
    auto [hi, lo] = ip.getIPv6();
    std::uint_fast16_t isd = ((hi >> 44) & 0xfffull);
    std::uint64_t asn = ((hi >> 24) & 0xfffff);
    if (asn & (1ull << 19)) asn = 0x2'0000'0000ull | (asn & 0x7ffffull);
    return IsdAsn(Isd(isd), Asn(asn));
}

/// \brief Statically map a full SCION address to an IPv6 address if such a
/// mapping is reversible without any additional information.
///
/// The mapping is only possible iff the ISD is smaller than 2^12, and the ASN
/// is either a BGP ASN < 2^19 or a SCION ASN in the range [2:0:0, 2:7:ffff].
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
        } else if (unmapIsdAsn(host) != addr.isdAsn()) {
            // host part is mapped address, but not the right one
            return Error(ErrorCode::InvalidArgument);
        } else {
            return host; // host part is already the mapped address
        }
    }

    std::uint64_t isd = addr.isdAsn().isd();
    if (!(isd < (1 << 12))) return Error(ErrorCode::InvalidArgument);

    std::uint64_t asn = addr.isdAsn().asn();
    std::uint64_t encodedAsn = 0;
    if (asn < (1ull << 19)) {
        encodedAsn = asn;
    } else if (0x2'0000'0000ull <= asn && asn <= 0x2'0007'ffffull) {
        encodedAsn = (1ull << 19) | (asn & 0x7ffffull);
    } else {
        return Error(ErrorCode::InvalidArgument);
    }

    std::uint64_t hi = (0xfcull << 56) | (isd << 44) | (encodedAsn << 24);
    std::uint64_t lo = 0xffffull << 32 | host.getIPv4();
    return generic::IPAddress::MakeIPv6(hi, lo);
}

/// \brief The inverse of mapToIPv6(). Fails with ErrorCode::InvalidArgument
/// if `ip` is not a SCION-mapped IPv6.
inline Maybe<ScIPAddress> unmapFromIPv6(const generic::IPAddress& ip)
{
    using generic::IPAddress;
    auto [prefix, interface] = ip.getIPv6();
    if ((prefix & (0xffull << 56)) != (0xfcull << 56))
        return Error(ErrorCode::InvalidArgument); // not the right prefix

    auto isdAsn = unmapIsdAsn(ip);
    auto localPrefix = prefix & 0xff'ffff;

    if (localPrefix == 0 && (interface >> 32) == 0xffffllu) { // IPv4 host
        return ScIPAddress(isdAsn, IPAddress::MakeIPv4(interface & 0xffff'ffffull));
    } else { // IPv6 host
        return ScIPAddress(isdAsn, ip);
    }
}

} // namespace scion
