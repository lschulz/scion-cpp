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

#include "scitra/packet.hpp"
#include "scion/path/decoded_scion.hpp"


namespace scion {
namespace scitra {

std::string PacketBuffer::print() const
{
    std::string str;
    str.reserve(2048);
    std::back_insert_iterator out(str);
    int indent = 2;

    if (ipValid == IPValidity::IPv4) {
        out = ipv4.print(out, indent);
        indent += 2;
    } else if (ipValid == IPValidity::IPv6) {
        out = ipv6.print(out, indent);
        indent += 2;
    }
    if (outerUDPValid) {
        out = outerUDP.print(out, indent);
        indent += 2;
    }
    if (scionValid) {
        out = sci.print(out, indent);
        DecodedScionPath decoded(path.firstAS(), path.lastAS());
        ReadStream rs(path.encoded());
        if (decoded.serialize(rs, NullStreamError)) {
            out = decoded.print(out, indent);
        } else {
            out = std::format_to(out, "<error decoding path>\n");
        }
        indent += 2;
    }
    if (l4Valid == L4Type::ICMP) {
        out = icmp.print(out, indent);
    } else if (l4Valid == L4Type::SCMP) {
        out = scmp.print(out, indent);
    } else if (l4Valid == L4Type::TCP) {
        out = tcp.print(out, indent);
    } else if (l4Valid == L4Type::UDP) {
        out = udp.print(out, indent);
    }

    auto payloadSize = payload().size();
    if (payloadSize > 0) {
        out = std::format_to(out, "###[ Payload ]###\n");
        std::format_to(out, "  <{} bytes payload>\n", payloadSize);
    }

    return str;
}

bool PacketBuffer::parse(ReadStream& rs, bool noUnderlay, IsScion* isScion, SCION_STREAM_ERROR& err)
{
    using namespace scion::hdr;
    using namespace scion::generic;

    // IP
    auto ipProto = IPProto(0);
    generic::IPAddress srcIP, dstIP;
    if (!noUnderlay) {
        std::uint8_t ipVer = 0;
        if (!rs.serializeBits(ipVer, 4, err)) return err.propagate();
        if (ipVer == 4) {
            rs.seek(0, 0);
            if (!ipv4.serialize(rs, err)) return err.propagate();
            srcIP = ipv4.src;
            dstIP = ipv4.dst;
            ipProto = ipv4.proto;
            ipValid = IPValidity::IPv4;
        } else if (ipVer == 6) {
            rs.seek(0, 0);
            if (!ipv6.serialize(rs, err)) return err.propagate();
            srcIP = ipv6.src;
            dstIP = ipv4.dst;
            ipProto = ipv6.nh;
            ipValid = IPValidity::IPv6;
        } else {
            return err.error("invalid IP version");
        }
    }

    // STUN
    std::span<const std::byte> header;
    if (rs.lookahead(header, STUN::stunHeaderSize, NullStreamError)) {
        if (detectStun(header)) {
            if (!stun.serialize(rs, err)) return err.propagate();
            stunValid = true;
            return true;
        }
    }

    // SCION and/or L4
    auto proto = ScionProto(0);
    if (noUnderlay) {
        if (!parseScion(rs, proto, err)) return err.propagate();
        if (!parseL4(rs, proto, err)) return err.propagate();
    } else if (ipProto == IPProto::UDP) {
        if (!outerUDP.serialize(rs, err)) return err.propagate();
        if (isScion && (*isScion)(IPEndpoint(srcIP, outerUDP.sport), IPEndpoint(srcIP, outerUDP.dport))) {
            outerUDPValid = true;
            if (!parseScion(rs, proto, err)) return err.propagate();
            if (!parseL4(rs, proto, err)) return err.propagate();
        } else {
            udp = outerUDP;
            outerUDPValid = false;
            l4Valid = L4Type::UDP;
        }
    } else {
        if (!parseL4(rs, static_cast<ScionProto>(ipProto), err)) return err.propagate();
    }

    // Payload
    endOfHeader = const_cast<std::byte*>(rs.getPtr());
    return true;
}

bool PacketBuffer::parseScion(ReadStream& rs, hdr::ScionProto& proto, SCION_STREAM_ERROR& err)
{
    if (!sci.serialize(rs, err)) return err.propagate();
    std::span<const std::byte> pdata;
    if (!rs.lookahead(pdata, sci.pathSize(), err)) return err.propagate();
    path.assign(sci.src.isdAsn(), sci.dst.isdAsn(), sci.ptype, pdata);
    if (!rs.advanceBytes(sci.pathSize(), err)) return err.propagate();
    proto = sci.nh;
    if (proto == hdr::ScionProto::HBHOpt) {
        hdr::HopByHopOpts hbh;
        if (!hbh.serialize(rs, err)) return err.propagate();
        if (!rs.advanceBytes(hbh.optionSize(), err)) return err.propagate();
        proto = hbh.nh;
    }
    if (proto == hdr::ScionProto::E2EOpt) {
        hdr::EndToEndOpts e2e;
        if (!e2e.serialize(rs, err)) return err.propagate();
        if (!rs.advanceBytes(e2e.optionSize(), err)) return err.propagate();
        proto = e2e.nh;
    }
    scionValid = true;
    return true;
}

bool PacketBuffer::parseL4(ReadStream& rs, hdr::ScionProto proto, SCION_STREAM_ERROR& err)
{
    using namespace scion::hdr;
    if (proto == ScionProto::SCMP) {
        if (!scmp.serialize(rs, err)) return err.propagate();
        l4Valid = L4Type::SCMP;
    } else if (static_cast<IPProto>(proto) == IPProto::ICMPv6) {
        if (!icmp.serialize(rs, err)) return err.propagate();
        l4Valid = L4Type::ICMP;
    } else if (proto == ScionProto::TCP) {
        if (!tcp.serialize(rs, err)) return err.propagate();
        l4Valid = L4Type::TCP;
    } else if (proto == ScionProto::UDP) {
        if (!udp.serialize(rs, err)) return err.propagate();
        l4Valid = L4Type::UDP;
    } else {
        return err.error("protocol not supported");
    }
    return true;
}

bool PacketBuffer::emit(WriteStream& ws, bool noUnderlay, SCION_STREAM_ERROR& err)
{
    std::size_t outerUdpPos = 0;
    if (!noUnderlay) {
        if (ipValid == IPValidity::IPv4) {
            if (!ipv4.serialize(ws, err)) return err.propagate();
        } else if (ipValid == IPValidity::IPv6) {
            if (!ipv6.serialize(ws, err)) return err.propagate();
        }
        if (outerUDPValid) {
            outerUdpPos = ws.getPos().first;
            if (!outerUDP.serialize(ws, err)) return err.propagate();
        }
    }
    if (stunValid) {
        if (!stun.serialize(ws, err)) return err.propagate();
    }
    if (scionValid) {
        if (!sci.serialize(ws, err)) return err.propagate();
        if (!ws.serializeBytes(path.encoded(), err)) return err.propagate();
    }
    switch (l4Valid) {
    case L4Type::ICMP:
        if (!icmp.serialize(ws, err)) return err.propagate();
        break;
    case L4Type::SCMP:
        if (!scmp.serialize(ws, err)) return err.propagate();
        break;
    case L4Type::TCP:
        if (!tcp.serialize(ws, err)) return err.propagate();
        break;
    case L4Type::UDP:
        if (!udp.serialize(ws, err)) return err.propagate();
        break;
    default:
        break;
    }
    if (!noUnderlay && outerUDPValid) {
        // Calculate outer UDP checksum
        auto offset = ws.getPos().first - outerUdpPos - 8;
        std::span<const std::byte> data;
        if (!ws.lookback(data, offset, err)) return err.propagate();
        std::uint32_t hdrChksum = outerUDP.checksum();
        if (ipValid == IPValidity::IPv4) {
            hdrChksum += ipv4.checksum(outerUDP.len);
        } else if (ipValid == IPValidity::IPv6) {
            hdrChksum += ipv6.checksum(outerUDP.len);
        }
        auto chksum = hdr::details::internetChecksum(data,
            hdr::details::onesComplementChecksum(payload(), hdrChksum));
        ws.updateChksum(chksum, offset, err);
    }
    return true;
}

} // namespace scitra
} // namespace scion
