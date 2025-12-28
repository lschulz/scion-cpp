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

#include "scion/details/flags.hpp"
#include "scion/hdr/details.hpp"
#include "scion/hdr/proto.hpp"
#include "scion/murmur_hash3.h"

#include <algorithm>
#include <cstdint>
#include <format>


namespace scion {
namespace hdr {

enum class TcpOptKind : std::uint8_t
{
    EndOfList = 0, // end of option list (padding after the last option)
    NoOp      = 1, // no-operation (padding in between options)
    MSS       = 2, // maximum segment size
    WS        = 3, // window scale option
    SAckPerm  = 4, // selective acknowledgement permitted
    SAck      = 5, // selective acknowledgement
    TS        = 8, // timestamps
};

/// \brief Unknown TCP option
class TcpUnknownOpt
{
public:
    TcpOptKind kind = (TcpOptKind)255;
    std::uint8_t length = 2;

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeByte((std::uint8_t&)kind, err)) return err.propagate();
        if (!stream.serializeByte(length, err)) return err.propagate();
        if (!stream.advanceBytes(std::max<std::size_t>(length, 2) - 2, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP Opt ]###\n");
        out = formatIndented(out, indent, "kind   = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length = {}\n", length);
        return out;
    }
};

/// \brief TCP Maximum Segment Size Option
class TcpMssOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::MSS;
    static constexpr std::uint8_t length = 4;
    std::uint16_t mss = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        return (((std::uint32_t)kind << 8) | length) + mss;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        std::uint8_t temp = (std::uint8_t)kind;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)kind) return err.error("incorrect TCP option kind");
        }
        temp = length;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != length) return err.error("incorrect TCP MSS option length");
        }
        if (!stream.serializeUint16(mss, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MSS Opt ]###\n");
        out = formatIndented(out, indent, "kind   = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length = {}\n", length);
        out = formatIndented(out, indent, "mss    = {}\n", mss);
        return out;
    }
};

/// \brief TCP Window Scale Option (RFC 7323)
class TcpWsOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::WS;
    static constexpr std::uint8_t length = 3;
    static constexpr std::uint8_t maxWndShift = 14; // max window size is 1 GiB (RFC 7323)
    std::uint8_t wndShift = 0;

    /// \brief Compute checksum including a NoOp option aligning the headers to
    /// a 2 byte boundary.
    std::uint32_t checksum() const
    {
        std::uint32_t sum = (0x01 << 8) | (std::uint32_t)kind;
        sum += ((std::uint32_t)length << 8) | wndShift;
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        std::uint8_t temp = (std::uint8_t)kind;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)kind) return err.error("incorrect TCP option kind");
        }
        temp = length;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != length) return err.error("incorrect TCP WS option length");
        }
        if (!stream.serializeByte(wndShift, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (wndShift > maxWndShift) return err.error("TCP window shift too large");
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP WS Opt ]###\n");
        out = formatIndented(out, indent, "kind   = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length = {}\n", length);
        out = formatIndented(out, indent, "shift  = {}\n", wndShift);
        return out;
    }
};

/// \brief TCP Selective Acknowledge Permitted Option (RFC 2018)
class TcpSAckPermOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::SAckPerm;
    static constexpr std::uint8_t length = 2;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        return ((std::uint32_t)kind << 8) | length;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        std::uint8_t temp = (std::uint8_t)kind;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)kind) return err.error("incorrect TCP option kind");
        }
        temp = length;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != length) return err.error("incorrect TCP SAckPerm option length");
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP SAckPerm Opt ]###\n");
        out = formatIndented(out, indent, "kind   = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length = {}\n", length);
        return out;
    }
};

/// \brief TCP Selective Acknowledge Option (RFC 2018)
class TcpSAckOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::SAck;
    static constexpr std::size_t maxBlocks = 3;
    std::uint_fast8_t blocks = 0; // number of blocks (0, 1, 2, or 3)
    std::array<std::uint32_t, maxBlocks> left = {};  // left edges
    std::array<std::uint32_t, maxBlocks> right = {}; // right edges

    /// \brief Compute checksum including two NoOp options aligning the headers
    /// to a 4 byte boundary.
    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)kind << 8) | (std::uint32_t)size();
        for (std::size_t i = 0; i < std::min<std::size_t>(blocks, maxBlocks); ++i) {
            sum += (left[i] >> 16) + (left[i] & 0xffff);
            sum += (right[i] >> 16) + (right[i] & 0xffff);
        }
        return sum + 0x0101;
    }

    std::size_t size() const
    {
        return 8 * blocks + 2;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        std::uint8_t temp = (std::uint8_t)kind;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)kind) return err.error("incorrect TCP option kind");
        }
        temp = (std::uint8_t)size();
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != 10 && temp != 18 && temp != 26)
                return err.error("invalid TCP SAck option");
            blocks = (std::uint_fast8_t)((temp - 2) / 8);
        }
        for (std::size_t i = 0; i < std::min<std::size_t>(blocks, maxBlocks); ++i) {
            if (!stream.serializeUint32(left[i], err)) return err.propagate();
            if (!stream.serializeUint32(right[i], err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP SAck Opt ]###\n");
        out = formatIndented(out, indent, "kind     = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length   = {}\n", size());
        for (std::size_t i = 0; i < std::min<std::size_t>(blocks, maxBlocks); ++i) {
            out = formatIndented(out, indent, "left[{}]  = {}\n", i, left[i]);
            out = formatIndented(out, indent, "right[{}] = {}\n", i, right[i]);
        }
        return out;
    }
};

/// \brief TCP Timestamps Option (RFC 7323)
class TcpTsOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::TS;
    static constexpr std::uint8_t length = 10;
    std::uint32_t TSval = 0;
    std::uint32_t TSecr = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        std::uint32_t sum = ((std::uint32_t)kind << 8) | length;
        sum += (TSval >> 16) + (TSval & 0xffff);
        sum += (TSecr >> 16) + (TSecr & 0xffff);
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        std::uint8_t temp = (std::uint8_t)kind;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)kind) return err.error("incorrect TCP option kind");
        }
        temp = length;
        if (!stream.serializeByte(temp, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != length) return err.error("incorrect TCP MSS option length");
        }
        if (!stream.serializeUint32(TSval, err)) return err.propagate();
        if (!stream.serializeUint32(TSecr, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP TS Opt ]###\n");
        out = formatIndented(out, indent, "kind   = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length = {}\n", length);
        out = formatIndented(out, indent, "TSval  = {}\n", TSval);
        out = formatIndented(out, indent, "TSecr  = {}\n", TSecr);
        return out;
    }
};

/// \brief TCP header with options.
class TCP
{
public:
    enum class Flags : std::uint8_t
    {
        FIN = 1 << 0, // no more data from sender
        SYN = 1 << 1, // synchronize sequence numbers
        RST = 1 << 2, // reset the connection
        PSH = 1 << 3, // push
        ACK = 1 << 4, // ack field is significant
        URG = 1 << 5, // urgptr is significant
        ECE = 1 << 6, // ECN echo
        CWR = 1 << 7, // congestion window reduced
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    struct OptionMask
    {
        std::uint_fast8_t MSS      : 1;
        std::uint_fast8_t WS       : 1;
        std::uint_fast8_t SAckPerm : 1;
        std::uint_fast8_t SAck     : 1;
        std::uint_fast8_t TS       : 1;
    };

    static constexpr ScionProto PROTO = ScionProto::TCP;
    FlagSet flags;
    std::uint16_t sport = 0;
    std::uint16_t dport = 0;
    std::uint16_t window = 0;
    std::uint16_t urgptr = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint16_t chksum = 0;

    OptionMask optMask = {};
    struct Options {
        TcpMssOpt mss;   // valid if optMask.MSS == 1
        TcpWsOpt ws;     // valid if optMask.WS == 1
        TcpSAckOpt sack; // valid if optMask.SAck == 1
        TcpTsOpt ts;     // valid if optMask.TS == 1
    } options;

    std::uint32_t checksum() const
    {
        std::uint32_t sum = sport + dport;
        sum += (seq >> 16) + (seq & 0xffff);
        sum += (ack >> 16) + (ack & 0xffff);;
        sum += (std::uint32_t)((size() / 4) << 12) | (std::uint8_t)flags;
        sum += window + chksum + urgptr;
        sum += checksumOpts();
        return sum;
    }

    std::size_t size() const
    {
        return 20 + measureOpts();
    }

    /// \brief Compute this header's contribution to the flow label.
    std::uint32_t flowLabel() const
    {
        auto key = (std::uint32_t(PROTO) << 16)
        | (std::uint32_t(sport) << 8)
        | (std::uint32_t)(dport);
        std::uint32_t hash;
        scion::details::MurmurHash3_x86_32(&key, sizeof(key), 0, &hash);
        return hash;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint16(sport, err)) return err.propagate();
        if (!stream.serializeUint16(dport, err)) return err.propagate();
        if (!stream.serializeUint32(seq, err)) return err.propagate();
        if (!stream.serializeUint32(ack, err)) return err.propagate();
        std::uint32_t dataOffset = 0;
        if constexpr (Stream::IsWriting) dataOffset = (std::uint32_t)(size() / 4);
        if (!stream.serializeBits(dataOffset, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (dataOffset < 5) return err.error("invalid TCP header");
        }
        if (!stream.advanceBits(4, err)) return err.propagate();
        if (!stream.serializeByte(flags.ref(), err)) return err.propagate();
        if (!stream.serializeUint16(window, err)) return err.propagate();
        if (!stream.serializeUint16(chksum, err)) return err.propagate();
        if (!stream.serializeUint16(urgptr, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            optMask = {};
            if (dataOffset == 5)
                return true; // no options
            std::span<const std::byte> opts;
            if (!stream.lookahead(opts, 4 * (dataOffset - 5), err)) return err.propagate();
            ReadStream rs(opts);
            if (!parseOpts(rs, err)) return err.propagate();
            if (!stream.advanceBytes(opts.size(), err)) return err.propagate();
        } else {
            if (!emitOpts(stream, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP ]###\n");
        out = formatIndented(out, indent, "sport  = {}\n", sport);
        out = formatIndented(out, indent, "dport  = {}\n", dport);
        out = formatIndented(out, indent, "seq    = {}\n", seq);
        out = formatIndented(out, indent, "ack    = {}\n", ack);
        out = formatIndented(out, indent, "flags  = {:#02x}\n", (std::uint8_t)flags);
        out = formatIndented(out, indent, "window = {}\n", window);
        out = formatIndented(out, indent, "chksum = {}\n", chksum);
        out = formatIndented(out, indent, "urgptr = {}\n", urgptr);
        if (optMask.MSS) {
            out = formatIndented(out, indent, "mss    = {}\n", options.mss.mss);
        }
        if (optMask.SAckPerm) {
            out = formatIndented(out, indent, "sack   = permitted\n");
        }
        if (optMask.SAck) {
            auto n = std::min<std::size_t>(options.sack.blocks, options.sack.maxBlocks);
            for (std::size_t i = 0; i < n; ++i) {
                out = formatIndented(out, indent, "sack   = ({}, {})\n",
                    options.sack.left[i], options.sack.right[i]);
            }
        }
        if (optMask.TS) {
            out = formatIndented(out, indent, "TSval  = {}\n", options.ts.TSval);
            out = formatIndented(out, indent, "TSecr  = {}\n", options.ts.TSecr);
        }
        if (optMask.WS) {
            out = formatIndented(out, indent, "wshift = {}\n", options.ws.wndShift);
        }
        return out;
    }

private:
    template <typename ReadStream, typename Error>
    bool parseOpts(ReadStream& rs, Error& err)
    {
        while (rs) {
            std::span<const std::byte> next;
            if (!rs.lookahead(next, 1, err)) return err.propagate();
            switch ((TcpOptKind)next.front()) {
            case TcpOptKind::EndOfList:
                if (!rs.advanceBytes(1, err)) return err.propagate();
                return true;
            case TcpOptKind::NoOp:
                if (!rs.advanceBytes(1, err)) return err.propagate();
                break;
            case TcpOptKind::MSS:
                if (!options.mss.serialize(rs, err)) return err.propagate();
                optMask.MSS = 1;
                break;
            case TcpOptKind::WS:
                if (!options.ws.serialize(rs, err)) return err.propagate();
                optMask.WS = 1;
                break;
            case TcpOptKind::SAckPerm:
                {
                    TcpSAckPermOpt opt;
                    if (!opt.serialize(rs, err)) return err.propagate();
                    optMask.SAckPerm = 1;
                    break;
                }
            case TcpOptKind::SAck:
                if (!options.sack.serialize(rs, err)) return err.propagate();
                optMask.SAck = 1;
                break;
            case TcpOptKind::TS:
                if (!options.ts.serialize(rs, err)) return err.propagate();
                optMask.TS = 1;
                break;
            default:
                {
                    TcpUnknownOpt opt;
                    if (!opt.serialize(rs, err)) return err.propagate();
                    break;
                }
            }
        }
        return true;
    }

    template <typename WriteStream, typename Error>
    bool emitOpts(WriteStream& ws, Error& err)
    {
        std::size_t len = 0;
        if (optMask.MSS) {            // 4 bytes
            len += TcpMssOpt::length;
            if (!options.mss.serialize(ws, err)) return err.propagate();
        }
        if (optMask.SAckPerm) {       // 2 bytes
            len += TcpSAckPermOpt::length;
            if (!TcpSAckPermOpt().serialize(ws, err)) return err.propagate();
        }
        if (optMask.SAck) {           // 8 * n + 2 bytes + 2 bytes padding
            len += options.sack.size() + 2;
            if (!ws.serializeUint16(0x0101u, err)) return err.propagate();
            if (!options.sack.serialize(ws, err)) return err.propagate();
        }
        if (optMask.TS) {
            // Packets with a timestamp option followed by two bytes of padding
            // don't seem to work on Linux.
            if (flags & Flags::SYN) { // 10 bytes
                len += TcpTsOpt::length;
                if (!options.ts.serialize(ws, err)) return err.propagate();
            } else {                  // 10 bytes + 2 bytes padding
                len += TcpTsOpt::length + 2;
                if (!ws.serializeUint16(0x0101u, err)) return err.propagate();
                if (!options.ts.serialize(ws, err)) return err.propagate();
            }
        }
        if (optMask.WS) {             // 3 bytes + 1 byte padding
            len += TcpWsOpt::length + 1;
            if (!ws.serializeByte(0x01u, err)) return err.propagate();
            if (!options.ws.serialize(ws, err)) return err.propagate();
        }
        if (len & 0x2) {
            // write end of option list (0) options
            std::size_t padding = 4 - (len & 3);
            if (!ws.advanceBytes(padding, err)) return err.propagate();
        }
        return true;
    }

    // Returns the size of the TCP options as emitted by emitOpts() including
    // padding.
    std::size_t measureOpts() const
    {
        std::size_t len = 0;
        if (optMask.MSS) len += TcpMssOpt::length;
        if (optMask.SAckPerm) len += TcpSAckPermOpt::length;
        if (optMask.SAck) len += options.sack.size() + 2; // 2 bytes padding
        if (optMask.TS) {
            if (flags[Flags::SYN])
                len += TcpTsOpt::length; // no padding
            else
                len += TcpTsOpt::length + 2; // 2 bytes padding
        }
        if (optMask.WS) len += TcpWsOpt::length + 1; // 1 byte padding
        return (len + 3) & ~((std::size_t)3); // round up to a multiple of 4
    }

    std::uint32_t checksumOpts() const
    {
        std::uint32_t sum = 0;
        if (optMask.MSS) sum += options.mss.checksum();
        if (optMask.SAckPerm) sum += TcpSAckPermOpt().checksum();
        if (optMask.SAck) sum += options.sack.checksum();
        if (optMask.TS) sum += options.ts.checksum();
        if (optMask.WS) sum += options.ws.checksum();
        return sum;
    }
};

inline TCP::FlagSet operator|(TCP::Flags lhs, TCP::Flags rhs)
{
    return TCP::FlagSet(lhs) | rhs;
}

} // namespace hdr
} // namespace scion
