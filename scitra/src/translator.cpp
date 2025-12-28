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

#include "scitra/translator.hpp"

#include <cassert>


namespace scion {
namespace scitra {
namespace details {

Verdict translateIcmpToScmp(PacketBuffer& pkt)
{
    using namespace scion::hdr;
    switch (pkt.icmp.type) {
    case ICMPv6::Type::DstUnreachable:
        pkt.scmp.msg = ScmpDstUnreach{
            pkt.icmp.code, // ICMP and SCMP codes match
        };
        pkt.l4Valid = PacketBuffer::L4Type::SCMP;
        return Verdict::Pass;

    case ICMPv6::Type::PacketTooBig:
    {
        const auto underlaySize = pkt.ipv6.size() + pkt.outerUDP.size();
        if (pkt.icmp.param1 != 0 || pkt.icmp.param2 < underlaySize)
            return Verdict::Drop;
        pkt.scmp.msg = ScmpPacketTooBig{
            (std::uint16_t)(pkt.icmp.param2 - underlaySize)
        };
        pkt.l4Valid = PacketBuffer::L4Type::SCMP;
        return Verdict::Pass;
    }

    case ICMPv6::Type::TimeExceeded:
        // hop limit reached in the local AS, must be handled by the translator
        // itself
        return Verdict::Drop;

    case ICMPv6::Type::ParamProblem:
        // paramater problem in a translated packet, indicates a bug in the
        // translator
        assert(false);
        return Verdict::Drop;

    case ICMPv6::Type::EchoRequest:
    {
        // SCION uses the ID field to encode the underlay port expecting
        // the reply packets. However, the sender of the ICMP echo request
        // expects the original ID to match replays with responses. Here we
        // store the original ID in byte 16 and 17 of the payload if possible.
        // The first 16 bytes of the payload are avoided as they are sometimes
        // used by ping utilities to store extra information.
        auto payload = pkt.payload();
        if (payload.size() >= 18)
            std::memcpy(const_cast<std::byte*>(payload.data()) + 16, &pkt.icmp.param1, 2);
        pkt.scmp.msg = ScmpEchoRequest{
            DISPATCHER_PORT,
            pkt.icmp.param2
        };
        pkt.l4Valid = PacketBuffer::L4Type::SCMP;
        return Verdict::Pass;
    }

    case ICMPv6::Type::EchoReply:
        pkt.scmp.msg = ScmpEchoReply{
            pkt.icmp.param1, pkt.icmp.param2
        };
        pkt.l4Valid = PacketBuffer::L4Type::SCMP;
        return Verdict::Pass;

    default:
        return Verdict::Drop;
    }
}

Verdict translateScmpToIcmp(PacketBuffer& pkt)
{
    using namespace scion::hdr;
    switch (pkt.scmp.getType()) {
    case ScmpType::DstUnreach:
    case ScmpType::ParamProblem:
    case ScmpType::ExtIfDown:
    case ScmpType::IntConnDown:
        // connectivity problems must be handled by the translator
        return Verdict::Drop;
    case ScmpType::PacketTooBig:
        // handle in translator
        return Verdict::Drop;
    case ScmpType::EchoRequest:
        pkt.icmp.type = ICMPv6::Type::EchoRequest;
        pkt.icmp.code = 0;
        pkt.icmp.chksum = 0;
        pkt.icmp.param1 = std::get<ScmpEchoRequest>(pkt.scmp.msg).id;
        pkt.icmp.param2 = std::get<ScmpEchoRequest>(pkt.scmp.msg).seq;
        pkt.l4Valid = PacketBuffer::L4Type::ICMP;
        return Verdict::Pass;
    case ScmpType::EchoReply:
    {
        pkt.icmp.type = ICMPv6::Type::EchoReply;
        pkt.icmp.code = 0;
        pkt.icmp.chksum = 0;
        pkt.icmp.param1 = std::get<ScmpEchoReply>(pkt.scmp.msg).id;
        pkt.icmp.param2 = std::get<ScmpEchoReply>(pkt.scmp.msg).seq;
        pkt.l4Valid = PacketBuffer::L4Type::ICMP;
        // Try to restore the original ID from the payload.
        auto payload = pkt.payload();
        if (payload.size() >= 18)
            std::memcpy(&pkt.icmp.param1, const_cast<std::byte*>(payload.data()) + 16, 2);
        return Verdict::Pass;
    }
    default:
        return Verdict::Abort;
    }
}

void makeIcmpDestUnreachable(PacketBuffer& pkt, std::uint8_t code)
{
    pkt.ipv6.dst = pkt.ipv6.src;
    pkt.ipv6.src = scion::generic::IPAddress::MakeIPv6(0xfcull << 56, 1);
    pkt.ipv6.nh = scion::hdr::IPProto::ICMPv6;
    pkt.icmp.type = scion::hdr::ICMPv6::Type::DstUnreachable;
    pkt.icmp.code = code;
    pkt.icmp.chksum = 0;
    pkt.icmp.param1 = 0;
    pkt.icmp.param2 = 0;
    pkt.l4Valid = PacketBuffer::L4Type::ICMP;
    auto payloadLen = pkt.quoteRawHeaders(IPV6_MIN_LINK_MTU - pkt.measureHeaders());
    pkt.ipv6.plen = (std::uint16_t)(pkt.icmp.size() + payloadLen);
    pkt.icmp.chksum = hdr::details::internetChecksum(pkt.payload(),
        pkt.ipv6.checksum((std::uint16_t)(pkt.icmp.size() + payloadLen))
        + pkt.icmp.checksum());
}

void makeIcmpPacketTooBig(PacketBuffer& pkt, std::uint16_t mtu)
{
    pkt.ipv6.dst = pkt.ipv6.src;
    pkt.ipv6.src = scion::generic::IPAddress::MakeIPv6(0xfcull << 56, 1);
    pkt.ipv6.nh = scion::hdr::IPProto::ICMPv6;
    pkt.icmp.type = scion::hdr::ICMPv6::Type::PacketTooBig;
    pkt.icmp.code = 0;
    pkt.icmp.chksum = 0;
    pkt.icmp.param1 = 0;
    pkt.icmp.param2 = mtu;
    pkt.l4Valid = PacketBuffer::L4Type::ICMP;
    auto payloadLen = pkt.quoteRawHeaders(IPV6_MIN_LINK_MTU - pkt.measureHeaders());
    pkt.ipv6.plen = (std::uint16_t)(pkt.icmp.size() + payloadLen);
    pkt.icmp.chksum = hdr::details::internetChecksum(pkt.payload(),
        pkt.ipv6.checksum((std::uint16_t)(pkt.icmp.size() + payloadLen))
        + pkt.icmp.checksum());
}

} // namespace details
} // namespace scitra
} // namespace scion
