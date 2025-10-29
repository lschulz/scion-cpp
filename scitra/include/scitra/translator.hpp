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
void makeIcmpDestUnreachable(PacketBuffer& pkt, int code);
void makeIcmpPacketTooBig(PacketBuffer& pkt, std::uint16_t mtu);

} // namespace details

/// \brief Translate a packet leaving the local host or network from IPv6 to
/// SCION.
/// \param hostIP The SCION-mapped IPv6 address of the local host. If empty, the
/// source address of outgoing packet is taken from the original IPv6 header.
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
translateEgress(PacketBuffer& pkt, std::optional<generic::IPAddress> hostIP, GetPath getPath)
{
    using namespace scion::hdr;

    generic::IPEndpoint nextHop;
    if (pkt.ipValid != PacketBuffer::IPValidity::IPv6) {
        return std::make_tuple(Verdict::Abort, 0, nextHop);
    }

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

    if (!hostIP) {
        // Router Mode: Take source address from the translated packet
        hostIP = pkt.ipv6.src;
    }

    // Find SCION destination address
    auto dst = unmapFromIPv6(pkt.ipv6.dst);
    if (isError(dst)) {
        details::makeIcmpDestUnreachable(pkt, 3); // address unreachable
        return std::make_tuple(Verdict::Return, 0, nextHop);
    }

    // Retrieve path to SCION destination
    auto [path, mtu] = getPath(
        ScIPAddress(IsdAsn(), *hostIP), *dst, pkt.l4SPort(), pkt.l4DPort(), nextHeader,
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
    nextHop = (*path)->nextHop(generic::IPEndpoint(dst->host(), pkt.l4DPort()));

    // Construct SCION header
    pkt.sci.qos = pkt.ipv6.tc;
    pkt.sci.nh = nextHeader;
    pkt.sci.ptype = (*path)->type();
    pkt.sci.dst = *dst;
    pkt.sci.src = ScIPAddress((*path)->firstAS(), *hostIP);
    pkt.sci.hlen = (std::uint8_t)((pkt.sci.size() + (*path)->size()) / 4);
    pkt.sci.plen = (std::uint16_t)(pkt.l4Size() + pkt.payload().size());
    pkt.sci.fl = details::computeScionFlowLabel(pkt.sci, pkt.l4FlowLabel());
    pkt.path.assign((*path)->firstAS(), (*path)->lastAS(), (*path)->type(), (*path)->encoded());

    // Check Path MTU
    // The SCION MTU is the maximum size of a SCION packet over the UDP/IP
    // underlay. The IPv6 MTU is the maximum size of an IPv6 packet over the
    // link layer. To conservatively calculate the IPv6 MTU from the SCION MTU,
    // we add the size of an UDP/IPv6 underlay and subtract the size of the
    // SCION headers.
    if (pkt.sci.size() + (*path)->size() + pkt.l4Size() + pkt.payload().size() > mtu) {

        std::size_t ipMtu = mtu
            + (pkt.ipv6.size() + pkt.outerUDP.size())
            - (pkt.sci.size() + (*path)->size());
        if (ipMtu >= IPV6_MIN_LINK_MTU) {
            details::makeIcmpPacketTooBig(pkt, mtu);
            return std::make_tuple(Verdict::Return, 0, nextHop);
        } else {
            return std::make_tuple(Verdict::Drop, 0, nextHop);
        }
    }

    // TCP MSS Clamping
    // MSS is the SCION MTU minus the size of all underlay and SCION headers.
    // The TCP MSS takes the IP and TCP header into account, the SCION MTU the
    // underlay IP and UDP headers, so we need to subtract the size difference
    // between TCP and UDP in addition to the SCION header size.
    std::uint32_t mss = 0, clampedMSS = 0;
    if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
        if (pkt.tcp.optMask.MSS) {
            int scionMSS = (int)mtu - (int)(pkt.sci.size() + (*path)->size()) - TCP_HDR_SIZE;
            if (scionMSS <= 0) return std::make_tuple(Verdict::Abort, 0, nextHop);
            mss = pkt.tcp.options.mss.mss;
            clampedMSS = std::min<std::uint16_t>(pkt.tcp.options.mss.mss, scionMSS);
            pkt.tcp.options.mss.mss = clampedMSS;
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
        pkt.ipv4.src = *hostIP;
        pkt.ipv4.dst = nextHop.host();
        pkt.ipValid = PacketBuffer::IPValidity::IPv4;
    } else {
        pkt.ipv6.tc = pkt.ipv6.tc;
        pkt.ipv6.hlim = 64;
        pkt.ipv6.nh = IPProto::UDP;
        pkt.ipv6.plen = pkt.outerUDP.len;
        pkt.ipv6.fl = details::computeIPv6FlowLabel(pkt.ipv6, pkt.l4FlowLabel());
        pkt.ipv6.src = *hostIP;
        pkt.ipv6.dst = nextHop.host();
        pkt.ipValid = PacketBuffer::IPValidity::IPv6;
    }
    pkt.scionValid = true;

    return std::make_tuple(Verdict::Pass, pkt.outerUDP.sport, nextHop);
};

/// \brief Translate a packet destined for the local host or network from SCION
/// to IPv6.
/// \param publicIP The SCION-mapped IPv6 or IPv4 underlay address of the host.
/// Must be an empty optional is Router Mode.
/// \param getMTU A callable that should provide an MTU usable with the path in
/// the packet buffer.
/// Signature:
/// ~~~
/// std::uint16_t getMTU(const hdr::SCION& sci, const RawPath& rp);
/// ~~~
/// \return Whether the packet should be accepted (Verdict:Pass) or dropped
/// (Verdict::Abort, Verdict::Drop).
template <GetMtuCallback GetMTU>
Verdict translateIngress(
    PacketBuffer& pkt, std::optional<generic::IPAddress> publicIP, GetMTU getMTU)
{
    using namespace scion::hdr;
    if (!pkt.scionValid) return Verdict::Abort;

    // Translate addresses
    if (auto src = mapToIPv6(pkt.sci.src); src.has_value())
        pkt.ipv6.src = *src;
    else
        return Verdict::Drop;
    if (auto dst = mapToIPv6(pkt.sci.dst); dst.has_value())
        pkt.ipv6.dst = *dst;
    else
        return Verdict::Drop;

    // Host Mode: Effective destination address must match the host's public
    // SCION-mapped IPv6.
    if (publicIP) {
        if (pkt.ipv6.dst != *publicIP) return Verdict::Drop;
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
    // Get a Path MTU to the sender from the path selector. If the path used by
    // the sender is longer than the path picked by the path selector, use the
    // longer path in the MSS calculation.
    std::uint32_t mss = 0, clampedMSS = 0;
    if (pkt.l4Valid == PacketBuffer::L4Type::TCP) {
        if (pkt.tcp.optMask.MSS) {
            auto mtu = getMTU(pkt.sci, pkt.path);
            int scionMSS = (int)mtu - (int)(pkt.sci.size() + pkt.path.size()) - TCP_HDR_SIZE;
            if (scionMSS <= 0) return Verdict::Abort;
            mss = pkt.tcp.options.mss.mss;
            clampedMSS = std::min<std::uint16_t>(pkt.tcp.options.mss.mss, scionMSS);
            pkt.tcp.options.mss.mss = clampedMSS;
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
