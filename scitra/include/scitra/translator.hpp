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

#include "scitra/packet.hpp"
#include "scion/addr/mapping.hpp"
#include "scion/error_codes.hpp"
#include "scion/path/path.hpp"

#include <concepts>
#include <cstdint>
#include <optional>


namespace scion {
namespace scitra {

/// \brief IPv6 requires a minimum link MTU of 1280 bytes (RFC 8200).
constexpr std::size_t IPV6_MIN_LINK_MTU = 1280;

/// \brief Size of a TCP header without options.
constexpr std::size_t TCP_HDR_SIZE = 20;

/// \brief UDP port of the SCION dispatcher. Packets that can't be addressed to
/// a specific application should be sent to the dispatcher port instead (e.g.
/// SCMP echo requests).
constexpr std::size_t DISPATCHER_PORT = 30041;

enum class Verdict
{
    Abort, ///< Error during translation
    Drop,  ///< Drop the packet
    Pass,  ///< Pass packet to egress port
    Return ///< Return on the same interface the packet was received on
};

template <typename F>
concept GetPathCallback = std::invocable<F,
    const ScIPAddress&, const ScIPAddress&,
    std::uint16_t, std::uint16_t,
    hdr::ScionProto, std::uint8_t>;

template <typename F>
concept GetMtuCallback = std::invocable<F, const hdr::SCION&, const RawPath&>;

namespace details {

inline std::uint32_t computeScionFlowLabel(const hdr::SCION& sci, std::uint32_t l4FlowLabel)
{
    std::hash<ScIPAddress> h;
    return (std::uint32_t)(h(sci.dst) ^ h(sci.src)) ^ l4FlowLabel;
}

inline std::uint32_t computeIPv6FlowLabel(const hdr::IPv6& ip, std::uint32_t l4FlowLabel)
{
    std::hash<generic::IPAddress> h;
    return (std::uint32_t)(h(ip.dst) ^ h(ip.src)) ^ l4FlowLabel;
}

Verdict translateIcmpToScmp(PacketBuffer& pkt);
Verdict translateScmpToIcmp(PacketBuffer& pkt);
void makeIcmpDestUnreachable(PacketBuffer& pkt, std::uint8_t code);
void makeIcmpPacketTooBig(PacketBuffer& pkt, std::uint16_t mtu);

} // namespace details

/// \brief Constant that causes translateIPv6Prefix() to replace the entire
/// address, even if the replacement address is IPv4.
const unsigned REPLACE_ADDRESS = 128;

/// \brief Replaces The first `prefixLen` bits of `addr` with the corresponding
/// bits in `prefix`. `addr` and `prefix` must be IPv6 addresses except if
/// `prefixLen` is REPLACE_ADDRESS.
inline generic::IPAddress translateIPv6Prefix(
    const generic::IPAddress& addr, const generic::IPAddress& prefix, unsigned prefixLen)
{
    if (prefixLen == REPLACE_ADDRESS) return prefix;
    assert(addr.is6() && prefix.is6());

    auto [addrHi, addrLo] = addr.getIPv6();
    auto [prefixHi, prefixLo] = prefix.getIPv6();

    auto shift = 64 - std::min(prefixLen, 64u);
    std::uint64_t maskHi = shift > 63 ? 0 : ~0ull << shift;
    std::uint64_t maskLo = 0;
    if (prefixLen > 64) {
        shift = 64 - (prefixLen - 64);
        maskLo = shift > 63 ? 0 : ~0ull << shift;
    }
    return generic::IPAddress::MakeIPv6(
        (addrHi & ~maskHi) | (prefixHi & maskHi),
        (addrLo & ~maskLo) | (prefixLo & maskLo)
    );
}

/// \brief Translate a packet leaving the local host or network from IPv6 to
/// SCION.
///
/// \param sourcePrefix Either an IPv4 address or an IPv6 address prefix. If an
/// IPv4 address is passed, `prefixLen` must be set to REPLACE_ADDRESS. The IPv4
/// address will be used as the source host address in the generated SCION
/// header. If an IPv6 prefix is passed, it will be combined with the host part
/// of the source address in the input IPv6 header to form the source address in
/// the generated SCION header. The prefix length is determined by `prefixLen`.
/// A prefix length of 0 is legal and causes the IPv6 source address to be
/// copied to the SCION header verbatim. An IPv6 prefix can also be combined
/// with REPLACE_ADDRESS to completely overwrite the source address.
///
/// \param prefixLen Length of the address prefix in `translatedPrefix` or the
/// special constant REPLACE_ADDRESS.
///
/// \param getPath A callable that produces a SCION path and the expected SCION
/// MTU for that path. The callable's parameters are the 5-tuple of the
/// translated SCION packet. If getPath returns an error or null, an appropriate
/// ICMP error is returned to the packet's sender.
/// Signature:
/// ~~~
/// std::tuple<Maybe<PathPtr>, std::uint16_t> getPath(
///     const ScIPAddress& src, const ScIPAddress& dst,
///     std::uint16_t sport, std::uint16_t dport,
///     hdr::ScionProto proto);
/// ~~~
///
/// \return A tuple of the verdict, the UDP port to send the packet from, and
/// the next hop ot send to. The verdict indicates whether the packet should be
/// forwarded (Verdict::Pass) from the returned UDP port to the next hop
/// address, or whether it should bre returned to the original sender
/// (Verdict::Return). Verdict::Abort and Verdict::Drop both mean that the
/// packet should be dropped, but Verdict::Abort additional alerts the caller
/// of an unexpected problem during translation (i.e. the headers where
/// invalid).
template <GetPathCallback GetPath>
std::tuple<Verdict, std::uint16_t, generic::IPEndpoint>
translateEgress(
    PacketBuffer& pkt, const generic::IPAddress& sourcePrefix, unsigned prefixLen,
    GetPath getPath)
{
    using namespace scion::hdr;

    generic::IPEndpoint nextHop;
    if (pkt.ipValid != PacketBuffer::IPValidity::IPv6) {
        return std::make_tuple(Verdict::Abort, 0, nextHop);
    }

    // Translate source host address
    auto srcHost = translateIPv6Prefix(pkt.ipv6.src, sourcePrefix, prefixLen);

    // Translate ICMP to SCMP
    ScionProto nextHeader;
    if (pkt.l4Valid == PacketBuffer::L4Type::ICMP) {
        auto verdict = details::translateIcmpToScmp(pkt);
        if (verdict == Verdict::Abort || verdict == Verdict::Drop) {
            return std::make_tuple(verdict, 0, nextHop);
        }
        nextHeader = ScionProto::SCMP;
    } else {
        nextHeader = static_cast<ScionProto>(pkt.l4Valid);
    }

    // Find SCION destination address
    auto dst = unmapFromIPv6(pkt.ipv6.dst);
    if (isError(dst)) {
        details::makeIcmpDestUnreachable(pkt, 3); // address unreachable
        return std::make_tuple(Verdict::Return, 0, nextHop);
    }

    // Retrieve path to SCION destination
    auto [path, mtu] = getPath(
        ScIPAddress(IsdAsn(), srcHost), *dst, pkt.l4SPort(), pkt.l4DPort(), nextHeader,
        pkt.ipv6.tc >> 2);
    if (isError(path)) {
        if (path.error() == ErrorCondition::Pending) {
            return std::make_tuple(Verdict::Drop, 0, nextHop);
        } else {
            details::makeIcmpDestUnreachable(pkt, 0); // no route to destination
            return std::make_tuple(Verdict::Return, 0, nextHop);
        }
    } else if (*path == nullptr) {
        details::makeIcmpDestUnreachable(pkt, 0); // no route to destination
        return std::make_tuple(Verdict::Return, 0, nextHop);
    }
    nextHop = (*path)->nextHop(generic::IPEndpoint(dst->host(), pkt.l4DPort(DISPATCHER_PORT)));

    // Construct SCION header
    pkt.sci.qos = pkt.ipv6.tc;
    pkt.sci.nh = nextHeader;
    pkt.sci.ptype = (*path)->type();
    pkt.sci.dst = *dst;
    pkt.sci.src = ScIPAddress((*path)->firstAS(), srcHost);
    pkt.sci.hlen = (std::uint8_t)((pkt.sci.size() + (*path)->size()) / 4);
    pkt.sci.plen = (std::uint16_t)(pkt.l4Size() + pkt.payload().size());
    pkt.sci.fl = details::computeScionFlowLabel(pkt.sci, pkt.l4FlowLabel());
    pkt.path.assign((*path)->firstAS(), (*path)->lastAS(), (*path)->type(), (*path)->encoded());

    // Check Path MTU
    // The SCION MTU is the maximum size of a SCION packet over the UDP/IP
    // underlay. The IPv6 MTU is the maximum size of an IPv6 packet over the
    // link layer. Here we calculate the effective IPv6 MTU before the
    // translation to SCION from the SCION MTU associated with the path.
    // MTU(SCION) = size(SCION) + size(path) + size(L4) + size(payload)
    // MTU(IPv6)  = size(IPv6) + size(L4) + size(payload)
    // MTU(IPv6)  = MTU(SCION) + size(IPv6) - size(SCION) - size(path)
    if (pkt.sci.size() + (*path)->size() + pkt.l4Size() + pkt.payload().size() > mtu) {
        std::size_t ipMtu = mtu + pkt.ipv6.size() - pkt.sci.size() - (*path)->size();
        if (ipMtu >= IPV6_MIN_LINK_MTU) {
            details::makeIcmpPacketTooBig(pkt, (std::uint16_t)std::min<std::size_t>(ipMtu, 65535u));
            return std::make_tuple(Verdict::Return, 0, nextHop);
        } else {
            return std::make_tuple(Verdict::Drop, 0, nextHop);
        }
    }

    // TCP MSS Clamping
    // MSS(IPv6) = MTU(IPv6) - size(IPv6) - size(TCP)
    // MSS(SCION) = MTU(SCION) - size(SCION) - size(path) - size(TCP)
    std::uint32_t mss = 0, clampedMSS = 0;
    if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
        if (pkt.tcp.optMask.MSS) {
            int scionMSS = (int)mtu - (int)(pkt.sci.size() + (*path)->size()) - (int)TCP_HDR_SIZE;
            if (scionMSS <= 0) return std::make_tuple(Verdict::Abort, 0, nextHop);
            mss = pkt.tcp.options.mss.mss;
            clampedMSS = std::min(
                pkt.tcp.options.mss.mss, (std::uint16_t)std::min(scionMSS, 65535));
            pkt.tcp.options.mss.mss = (std::uint16_t)clampedMSS;
        }
    }

    // Update L4 checksum
    if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
        auto payload = pkt.payload();
        pkt.scmp.chksum = hdr::details::internetChecksum(payload,
            pkt.sci.checksum((std::uint16_t)(pkt.scmp.size() + payload.size()), ScionProto::SCMP)
            + pkt.scmp.checksum());
    } else {
        pkt.l4UpdateChecksum(
            pkt.sci.checksum((std::uint16_t)pkt.l4Size(), (ScionProto)pkt.l4Valid) + clampedMSS,
            pkt.ipv6.checksum((std::uint16_t)pkt.l4Size()) + mss
        );
    }

    // Construct underlay
    pkt.outerUDP.sport = pkt.l4SPort();
    if (pkt.outerUDP.sport == 0) pkt.outerUDP.sport = DISPATCHER_PORT;
    pkt.outerUDP.dport = nextHop.port();
    pkt.outerUDP.len = (std::uint16_t)(pkt.outerUDP.size()
        + pkt.sci.size() + pkt.path.size() + pkt.sci.plen);
    pkt.outerUDP.chksum = 0;
    pkt.outerUDPValid = true;

    if (nextHop.host().is4()) {
        pkt.ipv4.flags = IPv4::Flags::DontFragment;
        pkt.ipv4.tos = pkt.ipv6.tc;
        pkt.ipv4.ttl = 64;
        pkt.ipv4.proto = IPProto::UDP;
        pkt.ipv4.len = (std::uint16_t)(pkt.ipv4.size() + pkt.outerUDP.len);
        pkt.ipv4.id = 0;
        pkt.ipv4.frag = 0;
        pkt.ipv4.src = srcHost;
        pkt.ipv4.dst = nextHop.host();
        pkt.ipValid = PacketBuffer::IPValidity::IPv4;
    } else {
        pkt.ipv6.tc = pkt.ipv6.tc;
        pkt.ipv6.hlim = 64;
        pkt.ipv6.nh = IPProto::UDP;
        pkt.ipv6.plen = pkt.outerUDP.len;
        pkt.ipv6.fl = details::computeIPv6FlowLabel(pkt.ipv6, pkt.l4FlowLabel());
        pkt.ipv6.src = srcHost;
        pkt.ipv6.dst = nextHop.host();
        pkt.ipValid = PacketBuffer::IPValidity::IPv6;
    }
    pkt.scionValid = true;

    return std::make_tuple(Verdict::Pass, pkt.outerUDP.sport, nextHop);
};

/// \brief Translate a packet destined for the local host or network from SCION
/// to IPv6.
///
/// \param acceptPrefix SCION-mapped IPv6 address or prefix for which packets
/// are accepted. The prefix length is passed in `prefixLen`.
/// \param dstPrefix IPv6 prefix that is combined with the destination address
/// from the SCION header (after SCION to IPv6 address translation) to form the
/// destinaion address of the translated IPv6 packet. The prefix length is
/// passed in `prefixLen`. If no prefix translation is desired, set to the same
/// value as `acceptedPrefix`.
/// \param prefixLen Prefix length of `publicIP` and `translatedPrefix`.
/// \param getMTU A callable that should provide an MTU usable with the path in
/// the packet buffer.
/// Signature:
/// ~~~
/// std::uint16_t getMTU(const hdr::SCION& sci, const RawPath& rp);
/// ~~~
///
/// \return Whether the packet should be accepted (Verdict:Pass) or dropped
/// (Verdict::Abort, Verdict::Drop).
template <GetMtuCallback GetMTU>
Verdict translateIngress(
    PacketBuffer& pkt, const generic::IPAddress& acceptPrefix,
    const generic::IPAddress& dstPrefix, unsigned prefixLen, GetMTU getMTU)
{
    using namespace scion::hdr;
    if (!pkt.scionValid) return Verdict::Abort;

    // Translate addresses
    if (auto src = mapToIPv6(pkt.sci.src); src.has_value())
        pkt.ipv6.src = *src;
    else
        return Verdict::Drop;
    if (auto dst = mapToIPv6(pkt.sci.dst); dst.has_value()) {
        // Only accept SCION packets addressed to our public IP or subnet.
        if (!samePrefix(acceptPrefix, *dst, prefixLen)) {
            return Verdict::Drop;
        }
        pkt.ipv6.dst = translateIPv6Prefix(*dst, dstPrefix, prefixLen);
    } else {
        return Verdict::Drop;
    }

    // Translate SCMP to ICMP
    IPProto nextHeader;
    if (pkt.l4Valid == PacketBuffer::L4Type::SCMP) {
        auto verdict = details::translateScmpToIcmp(pkt);
        if (verdict == Verdict::Abort || verdict == Verdict::Drop) {
            return verdict;
        }
        nextHeader = IPProto::ICMPv6;
    } else {
        nextHeader = static_cast<IPProto>(pkt.sci.nh);
    }

    // TCP MSS Clamping
    // Clamp MSS on ingress as well in case the remote SCION host does not
    // calculate the MSS correctly.
    std::uint32_t mss = 0, clampedMSS = 0;
    if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
        if (pkt.tcp.optMask.MSS) {
            auto mtu = getMTU(pkt.sci, pkt.path);
            int scionMSS = (int)mtu - (int)(pkt.sci.size() + pkt.path.size()) - (int)TCP_HDR_SIZE;
            if (scionMSS <= 0) return Verdict::Abort;
            mss = pkt.tcp.options.mss.mss;
            clampedMSS = std::min(
                pkt.tcp.options.mss.mss, (std::uint16_t)std::min(scionMSS, 65535));
            pkt.tcp.options.mss.mss = (std::uint16_t)clampedMSS;
        }
    }

    // Build IPv6 header
    pkt.ipv6.tc = pkt.sci.qos;
    pkt.ipv6.hlim = 64;
    pkt.ipv6.nh = nextHeader;
    pkt.ipv6.plen = (std::uint16_t)(pkt.l4Size() + pkt.payload().size());
    pkt.ipv6.fl = details::computeIPv6FlowLabel(pkt.ipv6, pkt.l4FlowLabel());
    pkt.ipValid = PacketBuffer::IPValidity::IPv6;
    pkt.outerUDPValid = false;
    pkt.scionValid = false;

    // Update L4 checksum
    if (pkt.l4Valid == PacketBuffer::L4Type::ICMP) {
        auto payload = pkt.payload();
        pkt.icmp.chksum = hdr::details::internetChecksum(payload,
            pkt.ipv6.checksum((std::uint16_t)(pkt.icmp.size() + payload.size()))
            + pkt.icmp.checksum());
    } else {
        pkt.l4UpdateChecksum(
            pkt.ipv6.checksum((std::uint16_t)pkt.l4Size()) + clampedMSS,
            pkt.sci.checksum((std::uint16_t)pkt.l4Size(), (ScionProto)pkt.l4Valid) + mss
        );
    }

    return Verdict::Pass;
}

} // namespace scitra
} // namespace scion
