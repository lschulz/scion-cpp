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
#include "scion/as_interface.hpp"
#include "scion/bit_stream.hpp"
#include "scion/hdr/scion.hpp"

#include <cstdint>
#include <format>
#include <variant>


namespace scion {
namespace hdr {

enum class ScmpType : std::uint8_t
{
    DstUnreach   = 1,
    PacketTooBig = 2,
    ParamProblem = 4,
    ExtIfDown    = 5,
    IntConnDown  = 6,
    EchoRequest  = 128,
    EchoReply    = 129,
    TraceRequest = 130,
    TraceReply   = 131,
};

class ScmpUnknownError
{
public:
    ScmpType type = (ScmpType)0;
    std::uint8_t code = 0;

    bool operator==(const ScmpUnknownError&) const = default;

    std::uint32_t checksum() const
    {
        return ((std::uint32_t)type << 8) + (std::uint8_t)code;
    }

    std::size_t size() const { return 0; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Unknown Error ]###\n");
        out = formatIndented(out, indent, "code = {}\n", code);
        return out;
    }
};

class ScmpDstUnreach
{
public:
    enum Code : std::uint8_t
    {
        NoRoute     = 0,
        Denied      = 1,
        BeyondScope = 2,
        AddrUnreach = 3,
        PortUnreach = 4,
        Policy      = 5,
        RejectRoute = 6,
    };

    static constexpr ScmpType type = ScmpType::DstUnreach;
    Code code = NoRoute;

    ScmpDstUnreach() = default;
    explicit ScmpDstUnreach(std::uint8_t code) : code((Code)code) {};

    bool operator==(const ScmpDstUnreach&) const = default;

    std::uint32_t checksum() const
    {
        return ((std::uint32_t)type << 8) + (std::uint8_t)code;
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.advanceBytes(4, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Destination Unreachable ]###\n");
        out = formatIndented(out, indent, "code = {}\n", (unsigned)code);
        return out;
    }
};

class ScmpPacketTooBig
{
public:
    static constexpr ScmpType type = ScmpType::PacketTooBig;
    static constexpr std::uint8_t code = 0;
    std::uint16_t mtu = 0;

    bool operator==(const ScmpPacketTooBig&) const = default;

    std::uint32_t checksum() const
    {
        return ((std::uint32_t)type << 8) + (std::uint8_t)code + mtu;
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.advanceBytes(2, err)) return err.propagate();
        if (!stream.serializeUint16(mtu, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Packet Too Big ]###\n");
        out = formatIndented(out, indent, "code = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "mtu  = {}\n", mtu);
        return out;
    }
};

class ScmpParamProblem
{
public:
    enum Code : std::uint8_t
    {
        ErrHdrField      = 0,
        UnknownNextHdr   = 1,
        InvalComHdr      = 16,
        UnknownScionVer  = 17,
        FlowIdReq        = 18,
        InvalidSize      = 19,
        UnknownPathType  = 20,
        UnknownAddress   = 21,
        InvalAddrHdr     = 32,
        InvalSrcAddr     = 33,
        InvalDstAddr     = 34,
        NonLocalDelivery = 35,
        InvalidPath      = 48,
        UnknownIgrIf     = 49,
        UnknownEgrIf     = 50,
        InvalidHfMac     = 51,
        PathExpired      = 52,
        InvalSegChange   = 53,
        InvalExtHdr      = 64,
        UnknownHBHOpt    = 65,
        UnknownE2ROpt    = 66,
    };

    static constexpr ScmpType type = ScmpType::ParamProblem;
    Code code = ErrHdrField;
    std::uint16_t pointer = 0;

    ScmpParamProblem() = default;
    explicit ScmpParamProblem(std::uint8_t code, std::uint16_t pointer = 0)
        : code((Code)code), pointer(pointer)
    {};

    bool operator==(const ScmpParamProblem&) const = default;

    std::uint32_t checksum() const
    {
        return ((std::uint32_t)type << 8) + (std::uint8_t)code + pointer;
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.advanceBytes(2, err)) return err.propagate();
        if (!stream.serializeUint16(pointer, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Parameter Problem ]###\n");
        out = formatIndented(out, indent, "code    = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "pointer = {}\n", pointer);
        return out;
    }
};

class ScmpExtIfDown
{
public:
    static constexpr ScmpType type = ScmpType::ExtIfDown;
    static constexpr std::uint8_t code = 0;
    IsdAsn sender;
    AsInterface iface;

    bool operator==(const ScmpExtIfDown&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += sender.checksum();
        sum += iface.checksum();
        return sum;
    }

    std::size_t size() const { return 16; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!sender.serialize(stream, err)) return err.propagate();
        if (!iface.serialize(stream, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP External Interface Down ]###\n");
        out = formatIndented(out, indent, "code   = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "sender = {}\n", sender);
        out = formatIndented(out, indent, "iface  = {}\n", iface);
        return out;
    }
};

class ScmpIntConnDown
{
public:
    static constexpr ScmpType type = ScmpType::IntConnDown;
    static constexpr std::uint8_t code = 0;
    IsdAsn sender;
    AsInterface ingress;
    AsInterface egress;

    bool operator==(const ScmpIntConnDown&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += sender.checksum();
        sum += ingress.checksum() + egress.checksum();
        return sum;
    }

    std::size_t size() const { return 24; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!sender.serialize(stream, err)) return err.propagate();
        if (!ingress.serialize(stream, err)) return err.propagate();
        if (!egress.serialize(stream, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Internal Connectivity Down ]###\n");
        out = formatIndented(out, indent, "code    = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "sender  = {}\n", sender);
        out = formatIndented(out, indent, "ingress = {}\n", ingress);
        out = formatIndented(out, indent, "egress  = {}\n", egress);
        return out;
    }
};

class ScmpEchoRequest
{
public:
    static constexpr ScmpType type = ScmpType::EchoRequest;
    static constexpr std::uint8_t code = 0;
    std::uint16_t id = 0;
    std::uint16_t seq = 0;

    bool operator==(const ScmpEchoRequest&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += (std::uint32_t)id + (std::uint32_t)seq;
        return sum;
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(id, err)) return err.propagate();
        if (!stream.serializeUint16(seq, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Echo Request ]###\n");
        out = formatIndented(out, indent, "code = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "id   = {}\n", id);
        out = formatIndented(out, indent, "seq  = {}\n", seq);
        return out;
    }
};

class ScmpEchoReply
{
public:
    static constexpr ScmpType type = ScmpType::EchoReply;
    static constexpr std::uint8_t code = 0;
    std::uint16_t id = 0;
    std::uint16_t seq = 0;

    bool operator==(const ScmpEchoReply&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += (std::uint32_t)id + (std::uint32_t)seq;
        return sum;
    }

    std::size_t size() const { return 4; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(id, err)) return err.propagate();
        if (!stream.serializeUint16(seq, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Echo Reply ]###\n");
        out = formatIndented(out, indent, "code = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "id   = {}\n", id);
        out = formatIndented(out, indent, "seq  = {}\n", seq);
        return out;
    }
};

class ScmpTraceRequest
{
public:
    static constexpr ScmpType type = ScmpType::TraceRequest;
    static constexpr std::uint8_t code = 0;
    std::uint16_t id = 0;
    std::uint16_t seq = 0;

    bool operator==(const ScmpTraceRequest&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += (std::uint32_t)id + (std::uint32_t)seq;
        return sum;
    }

    std::size_t size() const { return 20; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(id, err)) return err.propagate();
        if (!stream.serializeUint16(seq, err)) return err.propagate();
        if (!stream.advanceBytes(16, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Traceroute Request ]###\n");
        out = formatIndented(out, indent, "code = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "id   = {}\n", id);
        out = formatIndented(out, indent, "seq  = {}\n", seq);
        return out;
    }
};

class ScmpTraceReply
{
public:
    static constexpr ScmpType type = ScmpType::TraceReply;
    static constexpr std::uint8_t code = 0;
    std::uint16_t id = 0;
    std::uint16_t seq = 0;
    IsdAsn sender;
    AsInterface iface;

    bool operator==(const ScmpTraceReply&) const = default;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)type << 8) + (std::uint8_t)code;
        sum += (std::uint32_t)id + (std::uint32_t)seq;
        sum += sender.checksum() + iface.checksum();
        return sum;
    }

    std::size_t size() const { return 20; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(id, err)) return err.propagate();
        if (!stream.serializeUint16(seq, err)) return err.propagate();
        if (!sender.serialize(stream, err)) return err.propagate();
        if (!iface.serialize(stream, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP Traceroute Reply ]###\n");
        out = formatIndented(out, indent, "code   = {}\n", (unsigned)code);
        out = formatIndented(out, indent, "id     = {}\n", id);
        out = formatIndented(out, indent, "seq    = {}\n", seq);
        out = formatIndented(out, indent, "sender = {}\n", sender);
        out = formatIndented(out, indent, "iface  = {}\n", iface);
        return out;
    }
};

using ScmpMessage = std::variant<
    ScmpUnknownError,
    ScmpDstUnreach,
    ScmpPacketTooBig,
    ScmpParamProblem,
    ScmpExtIfDown,
    ScmpIntConnDown,
    ScmpEchoRequest,
    ScmpEchoReply,
    ScmpTraceRequest,
    ScmpTraceReply
>;

/// \brief SCION Control Message Protocol.
class SCMP
{
public:
    static constexpr ScionProto PROTO = ScionProto::SCMP;
    std::uint16_t chksum = 0;
    ScmpMessage msg;

    SCMP() = default;
    explicit SCMP(const ScmpMessage& message) : msg(message) {}

    ScmpType getType() const
    {
        return std::visit([](auto&& arg) -> auto { return arg.type; }, msg);
    }

    std::uint32_t checksum() const
    {
        std::uint32_t sum = chksum;
        sum += std::visit([](auto&& arg) -> auto {
            return arg.checksum();
        }, msg);
        return sum;
    }

    std::size_t size() const
    {
        return 4 + std::visit([](auto&& arg) -> auto { return arg.size(); }, msg);
    }

    void setPayload(std::span<const std::byte> payload) {}

    /// \brief Compute this header's contribution to the flow label.
    std::uint32_t flowLabel() const { return 0; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        ScmpType type;
        std::uint8_t code;
        if constexpr (Stream::IsWriting) {
            type = getType();
            code = std::visit([](auto&& arg) -> auto {
                return (std::uint8_t)arg.code;
            }, msg);
        }
        if (!stream.serializeByte((std::uint8_t&)type, err)) return err.propagate();
        if (!stream.serializeByte(code, err)) return err.propagate();
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        switch (type) {
        case ScmpType::DstUnreach:
            if constexpr (Stream::IsReading) msg = ScmpDstUnreach{code};
            if (!std::get<ScmpDstUnreach>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::PacketTooBig:
            if constexpr (Stream::IsReading) msg = ScmpPacketTooBig{};
            if (!std::get<ScmpPacketTooBig>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::ParamProblem:
            if constexpr (Stream::IsReading) msg = ScmpParamProblem{code};
            if (!std::get<ScmpParamProblem>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::ExtIfDown:
            if constexpr (Stream::IsReading) msg = ScmpExtIfDown{};
            if (!std::get<ScmpExtIfDown>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::IntConnDown:
            if constexpr (Stream::IsReading) msg = ScmpIntConnDown{};
            if (!std::get<ScmpIntConnDown>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::EchoRequest:
            if constexpr (Stream::IsReading) msg = ScmpEchoRequest{};
            if (!std::get<ScmpEchoRequest>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::EchoReply:
            if constexpr (Stream::IsReading) msg = ScmpEchoReply{};
            if (!std::get<ScmpEchoReply>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::TraceRequest:
            if constexpr (Stream::IsReading) msg = ScmpTraceRequest{};
            if (!std::get<ScmpTraceRequest>(msg).serialize(stream, err))
                return err.propagate();
            break;
        case ScmpType::TraceReply:
            if constexpr (Stream::IsReading) msg = ScmpTraceReply{};
            if (!std::get<ScmpTraceReply>(msg).serialize(stream, err))
                return err.propagate();
            break;
        default:
            if constexpr (Stream::IsReading) {
                if ((unsigned)type < 128) {
                    // unknown SCMP error messages must be passed up the stack
                    msg = ScmpUnknownError{type, code};
                    return true;
                } else {
                    // unknown informational messages must be dropped
                    return err.error("unknown informational SCMP message");
                }
            }
            return err.error("programming error");
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ SCMP ]###\n");
        out = formatIndented(out, indent, "chksum = {}\n", chksum);
        return std::visit([&](auto&& arg) -> auto {
            return arg.print(out, indent);
        }, msg);
    }
};

} // namespace hdr
} // namespace scion
