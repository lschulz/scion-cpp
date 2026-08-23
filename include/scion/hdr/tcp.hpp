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

#include "scion/addr/generic_ip.hpp"
#include "scion/details/flags.hpp"
#include "scion/hash.hpp"
#include "scion/hdr/details.hpp"
#include "scion/hdr/proto.hpp"

#include <algorithm>
#include <cstdint>
#include <format>


namespace scion {
namespace hdr {

enum class TcpOptKind : std::uint8_t
{
    EndOfList =  0, // end of option list (padding after the last option)
    NoOp      =  1, // no-operation (padding in between options)
    MSS       =  2, // maximum segment size
    WS        =  3, // window scale option
    SAckPerm  =  4, // selective acknowledgement permitted
    SAck      =  5, // selective acknowledgement
    TS        =  8, // timestamps
    MPTCP     = 30, // multipath
};

enum class TcpMpSubtype : std::uint8_t
{
    MP_CAPABLE   = 0, // Multipath Capable
    MP_JOIN      = 1, // Join Connection
    DSS          = 2, // Data Sequence Signal
    ADD_ADDR     = 3, // Add Address
    REMOVE_ADDR  = 4, // Remove Address
    MP_PRIO      = 5, // Change Subflow Priority
    MP_FAIL      = 6, // Fallback
    MP_FASTCLOSE = 7, // Fast Close
    MP_TCPRST    = 8  // Subflow Reset
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
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect TCP MSS option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
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

    /// \brief Compute checksum assuming option is preceded by a 0x01 no-op
    /// option aligned on a 2 byte boundary.
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
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect TCP WS option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
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
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect TCP SAckPerm option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
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
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto temp = (std::uint8_t)size();
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
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect TCP MSS option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
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

/// \brief TCP Multipath Capable Option (RFC 8684, Section 3.1)
class TcpMpCapableOpt
{
public:
    enum class Flags : std::uint8_t
    {
        ChksumReq   = 1 << 7, // checksum required
        Extension   = 1 << 6, // future extensions
        NoSubflows  = 1 << 5, // no additional subflows to this IP and port accepted
        D           = 1 << 4, // crypto negotiation
        E           = 1 << 3, // crypto negotiation
        F           = 1 << 2, // crypto negotiation
        G           = 1 << 1, // crypto negotiation
        HMAC_SHA256 = 1 << 0, // use HMAC-SHA256
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    struct FieldMask
    {
        std::uint8_t senderKey    : 1;
        std::uint8_t receiverKey  : 1;
        std::uint8_t dataLevelLen : 1;
        std::uint8_t chksum       : 1;
    };

    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_CAPABLE;
    FieldMask fieldMask = {};
    std::uint8_t version = 1;
    FlagSet flags;
    std::uint64_t senderKey = 0;
    std::uint64_t receiverKey = 0;
    std::uint16_t dataLevelLen = 0;
    std::uint16_t chksum = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | (uint32_t)size();
        sum += ((uint32_t)subtype << 12) | ((uint32_t)version << 8) | (uint32_t)flags;
        if (fieldMask.senderKey) {
            sum += details::checksumUint64(senderKey);
        }
        if (fieldMask.receiverKey) {
            sum += details::checksumUint64(receiverKey);
        }
        if (fieldMask.dataLevelLen) sum += dataLevelLen;
        if (fieldMask.chksum) sum += chksum;
        return sum;
    }

    std::size_t size() const
    {
        std::size_t length = 4;
        if (fieldMask.senderKey) length += 8;
        if (fieldMask.receiverKey) length += 8;
        if (fieldMask.dataLevelLen) length += 2;
        if (fieldMask.chksum) length += 2;
        return length;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto length = (std::uint8_t)size();
        if (!stream.serializeByte(length, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (length == 4) fieldMask = {0, 0, 0, 0};
            else if(length == 12) fieldMask = {1, 0, 0, 0};
            else if (length == 20) fieldMask = {1, 1, 0, 0};
            else if (length == 22) fieldMask = {1, 1, 1, 0};
            else if (length == 24) fieldMask = {1, 1, 1, 1};
            else return err.error("invalid MP_CAPABLE option length");
        }
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.serializeBits(version, 4, err)) return err.propagate();
        if (!stream.serializeByte(flags.ref(), err)) return err.propagate();
        if (fieldMask.senderKey) {
            if (!stream.serializeUint64(senderKey, err)) return err.propagate();
        }
        if (fieldMask.receiverKey) {
            if (!stream.serializeUint64(receiverKey, err)) return err.propagate();
        }
        if (fieldMask.dataLevelLen) {
            if (!stream.serializeUint16(dataLevelLen, err)) return err.propagate();
        }
        if (fieldMask.chksum) {
            if (!stream.serializeUint16(chksum, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_CAPABLE Opt ]###\n");
        out = formatIndented(out, indent, "kind         = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length       = {}\n", size());
        out = formatIndented(out, indent, "subtype      = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "version      = {}\n", version);
        out = formatIndented(out, indent, "flags        = {:#02x}\n", (std::uint8_t)flags);
        if (fieldMask.senderKey)
            out = formatIndented(out, indent, "senderKey    = {:#016x}\n", senderKey);
        if (fieldMask.receiverKey)
            out = formatIndented(out, indent, "receiverKey  = {:#016x}\n", receiverKey);
        if (fieldMask.dataLevelLen)
            out = formatIndented(out, indent, "dataLevelLen = {}\n", dataLevelLen);
        if (fieldMask.chksum)
            out = formatIndented(out, indent, "chksum       = {}\n", chksum);
        return out;
    }
};

inline TcpMpCapableOpt::FlagSet operator|(TcpMpCapableOpt::Flags lhs, TcpMpCapableOpt::Flags rhs)
{
    return TcpMpCapableOpt::FlagSet(lhs) | rhs;
}

/// \brief TCP Multipath Subflow Join Option (RFC 8684, Section 3.2)
class TcpMpJoinOpt
{
public:
    enum class Flags : std::uint8_t
    {
        Backup = 1 << 0, // is a backup path
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    // MP_JOIN on initial SYN
    struct Syn
    {
        FlagSet flags;
        std::uint8_t addressId = 0;
        std::uint32_t receiverToken = 0;
        std::uint32_t senderRand = 0;
    };

    // MP_JOIN on responding SYN/ACK
    struct SynAck
    {
        FlagSet flags;
        std::uint8_t addressId = 0;
        std::uint64_t senderMac = 0;
        std::uint32_t senderRand = 0;
    };

    // MP_JOIN on initiator's first ACK
    struct Ack
    {
        std::array<std::byte, 20> senderMac = {};
    };

    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_JOIN;
    std::uint8_t length = 12;
    // Option content varies during three-way handshake
    std::variant<Syn, SynAck, Ack> content;

    constexpr TcpMpJoinOpt() : content(Syn{}) {}

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | (uint32_t)size();
        sum += std::visit([](auto&& arg) -> std::uint32_t {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, Syn>) {
                return (((uint32_t)subtype << 12) | (((uint32_t)arg.flags << 8) | arg.addressId))
                    + (arg.receiverToken >> 16) + (arg.receiverToken & 0xffff)
                    + (arg.senderRand >> 16) + (arg.senderRand & 0xffff);
            }
            else if constexpr (std::is_same_v<T, SynAck>) {
                return (((uint32_t)subtype << 12) | (((uint32_t)arg.flags << 8) | arg.addressId))
                    + details::checksumUint64(arg.senderMac)
                    + (arg.senderRand >> 16) + (arg.senderRand & 0xffff);
            } else {
                return details::onesComplementChecksum(arg.senderMac, (uint32_t)subtype << 12);
            }
        }, content);
        return sum;
    }

    std::size_t size() const
    {
        if (content.index() == 0) return 12;
        if (content.index() == 1) return 16;
        else return 24;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto length = (std::uint8_t)size();
        if (!stream.serializeByte(length, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (length == 12) content = Syn{};
            else if(length == 16) content = SynAck{};
            else if (length == 24) content = Ack{};
            else return err.error("invalid MP_JOIN option length");
        }
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (content.index() == 0) {
            auto& syn = std::get<0>(content);
            if (!stream.serializeBits(syn.flags.ref(), 4, err)) return err.propagate();
            if (!stream.serializeByte(syn.addressId, err)) return err.propagate();
            if (!stream.serializeUint32(syn.receiverToken, err)) return err.propagate();
            if (!stream.serializeUint32(syn.senderRand, err)) return err.propagate();
        } else if (content.index() == 1) {
            auto& sa = std::get<1>(content);
            if (!stream.serializeBits(sa.flags.ref(), 4, err)) return err.propagate();
            if (!stream.serializeByte(sa.addressId, err)) return err.propagate();
            if (!stream.serializeUint64(sa.senderMac, err)) return err.propagate();
            if (!stream.serializeUint32(sa.senderRand, err)) return err.propagate();
        } else {
            auto& ack = std::get<2>(content);
            if (!stream.advanceBits(12, err)) return err.propagate();
            if (!stream.serializeBytes(ack.senderMac, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_JOIN Opt ]###\n");
        out = formatIndented(out, indent, "kind          = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length        = {}\n", size());
        out = formatIndented(out, indent, "subtype       = {}\n", (unsigned)subtype);
        if (content.index() == 0) {
            auto& syn = std::get<0>(content);
            out = formatIndented(out, indent, "flags         = {:#02x}\n", (std::uint8_t)syn.flags);
            out = formatIndented(out, indent, "addressId     = {}\n", syn.addressId);
            out = formatIndented(out, indent, "receiverToken = {}\n", syn.receiverToken);
            out = formatIndented(out, indent, "senderRand    = {}\n", syn.senderRand);
        } else if (content.index() == 1) {
            auto& sa = std::get<1>(content);
            out = formatIndented(out, indent, "flags         = {:#02x}\n", (std::uint8_t)sa.flags);
            out = formatIndented(out, indent, "addressId     = {}\n", sa.addressId);
            out = formatIndented(out, indent, "senderMac     = {}\n", sa.senderMac);
            out = formatIndented(out, indent, "senderRand    = {}\n", sa.senderRand);
        } else {
            auto& ack = std::get<2>(content);
            out = formatIndented(out, indent, "senderMac     = ");
            out = formatBytes(out, ack.senderMac);
            out = std::format_to(out, "\n");
        }
        return out;
    }
};

inline TcpMpJoinOpt::FlagSet operator|(TcpMpJoinOpt::Flags lhs, TcpMpJoinOpt::Flags rhs)
{
    return TcpMpJoinOpt::FlagSet(lhs) | rhs;
}

/// \brief TCP Multipath Data Sequence Signal Option (RFC 8684, Section 3.3)
class TcpMpDssOpt
{
public:
    enum class Flags : std::uint16_t
    {
        ACK  = 1 << 0, // Data Ack present
        ACK8 = 1 << 1, // Data ACK is 8 bytes
        DSN  = 1 << 2, // DSN, SSN, and data-level length present
        DSN8 = 1 << 3, // DSN is 8 bytes
        FIN  = 1 << 4, // Data FIN
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    union SequenceNumber
    {
        std::uint32_t u32;
        std::uint64_t u64 = 0;
    };

    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::DSS;
    FlagSet flags;
    SequenceNumber dataAck = {};
    SequenceNumber dsn = {};
    std::uint32_t subflowSeq = 0;
    std::uint16_t dataLevelLen = 0;
    std::optional<std::uint16_t> chksum;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | (uint32_t)size();
        sum += ((uint32_t)subtype << 12) | (uint32_t)flags;
        if (flags & Flags::ACK) {
            if (flags & Flags::ACK8) {
                sum += details::checksumUint64(dataAck.u64);
            } else {
                sum += (uint32_t)(((dataAck.u32 >> 16) & 0xffff) + (dataAck.u32 & 0xffff));
            }
        }
        if (flags & Flags::DSN) {
            if (flags & Flags::DSN8) {
                sum += details::checksumUint64(dsn.u64);
            } else {
                sum += (uint32_t)(((dsn.u32 >> 16) & 0xffff) + (dsn.u32 & 0xffff));
            }
            sum += (subflowSeq >> 16) + (subflowSeq & 0xffff);
            sum += dataLevelLen;
        }
        if (chksum.has_value()) sum += *chksum;
        return sum;
    }

    std::size_t size() const
    {
        std::size_t length = 4;
        if (flags & Flags::ACK) {
            length += 4;
            if (flags & Flags::ACK8) length += 4;
        }
        if (flags & Flags::DSN) {
            length += 10;
            if (flags & Flags::DSN8) length += 4;
        }
        if (chksum.has_value()) length += 2;
        return length;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto length = (std::uint8_t)size();
        if (!stream.serializeByte(length, err)) return err.propagate();
        std::uint16_t temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.serializeBits(flags.ref(), 12, err)) return err.propagate();
        if (flags & Flags::ACK) {
            if (flags & Flags::ACK8) {
                if (!stream.serializeUint64(dataAck.u64, err)) return err.propagate();
            } else {
                if (!stream.serializeUint32(dataAck.u32, err)) return err.propagate();
            }
        }
        if (flags & Flags::DSN) {
            if (flags & Flags::DSN8) {
                if (!stream.serializeUint64(dsn.u64, err)) return err.propagate();
            } else {
                if (!stream.serializeUint32(dsn.u32, err)) return err.propagate();
            }
            if (!stream.serializeUint32(subflowSeq, err)) return err.propagate();
            if (!stream.serializeUint16(dataLevelLen, err)) return err.propagate();
        }
        if constexpr (Stream::IsReading) {
            chksum = std::nullopt;
            if ((std::ptrdiff_t)length - (std::ptrdiff_t)size() >= 2) {
                chksum = 0;
                if (!stream.serializeUint16(*chksum, err)) return err.propagate();
            }
        } else {
            if (chksum.has_value()) {
                if (!stream.serializeUint16(*chksum, err)) return err.propagate();
            }
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_CAPABLE Opt ]###\n");
        out = formatIndented(out, indent, "kind         = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length       = {}\n", size());
        out = formatIndented(out, indent, "subtype      = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "flags        = {:#02x}\n", (std::uint8_t)flags);
        if (flags & Flags::ACK) {
            if (flags & Flags::ACK8) {
                out = formatIndented(out, indent, "dataAck      = {}\n", dataAck.u64);
            } else {
                out = formatIndented(out, indent, "dataAck      = {}\n", dataAck.u32);
            }
        }
        if (flags & Flags::DSN) {
            if (flags & Flags::DSN8) {
                out = formatIndented(out, indent, "dsn          = {}\n", dsn.u64);
            } else {
                out = formatIndented(out, indent, "dsn          = {}\n", dsn.u32);
            }
            out = formatIndented(out, indent, "subflowSeq   = {}\n", subflowSeq);
            out = formatIndented(out, indent, "dataLevelLen = {}\n", dataLevelLen);
        }
        if (chksum.has_value()) {
            out = formatIndented(out, indent, "chksum       = {}\n", *chksum);
        }
        return out;
    }
};

inline TcpMpDssOpt::FlagSet operator|(TcpMpDssOpt::Flags lhs, TcpMpDssOpt::Flags rhs)
{
    return TcpMpDssOpt::FlagSet(lhs) | rhs;
}

/// \brief TCP Multipath Add Address Option (RFC 8684, Section 3.4.1)
class TcpMpAddAddrOpt
{
public:
    enum class Flags : std::uint16_t
    {
        Echo = 1 << 0, // is echo for reliability
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::ADD_ADDR;
    FlagSet flags;
    std::uint8_t addressId = 0;
    scion::generic::IPAddress address;
    std::optional<std::uint16_t> port;
    std::uint64_t mac = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | (uint32_t)size();
        sum += ((uint32_t)subtype << 12) | ((uint32_t)flags << 8) | addressId;
        sum += address.checksum();
        if (port.has_value()) sum += *port;
        if (!flags[Flags::Echo]) {
            sum += details::checksumUint64(mac);
        }
        return sum;
    }

    std::size_t size() const
    {
        std::size_t length = 4 + address.size();
        if (port.has_value()) length += 2;
        if (!flags[Flags::Echo]) length += 8;
        return length;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto length = (std::uint8_t)size();
        if (!stream.serializeByte(length, err)) return err.propagate();
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.serializeBits(flags.ref(), 4, err)) return err.propagate();
        if (!stream.serializeByte(addressId, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            auto n = (int)length - 4;
            if (!flags[Flags::Echo]) n -= 8;
            if (n == 6 || n == 18) {
                port = 0;
                if (!stream.serializeUint16(*port, err)) return err.propagate();
            } else {
                port = std::nullopt;
            }
            bool is4 = n == 4 || n == 6;
            if (!address.serialize(stream, is4, err)) return err.propagate();
        } else {
            if (!address.serialize(stream, address.is4(), err)) return err.propagate();
            if (port.has_value()) {
                if (!stream.serializeUint16(*port, err)) return err.propagate();
            }
        }
        if (!flags[Flags::Echo]) {
            if (!stream.serializeUint64(mac, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP ADD_ADDR Opt ]###\n");
        out = formatIndented(out, indent, "kind      = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length    = {}\n", size());
        out = formatIndented(out, indent, "subtype   = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "flags     = {:#02x}\n", (std::uint8_t)flags);
        out = formatIndented(out, indent, "addressId = {}\n", addressId);
        out = formatIndented(out, indent, "address   = {}\n", address);
        if (port.has_value()) {
            out = formatIndented(out, indent, "port      = {}\n", *port);
        }
        if (!flags[Flags::Echo]) {
            out = formatIndented(out, indent, "mac       = {:#016x}\n", mac);
        }
        return out;
    }
};

inline TcpMpAddAddrOpt::FlagSet operator|(TcpMpAddAddrOpt::Flags lhs, TcpMpAddAddrOpt::Flags rhs)
{
    return TcpMpAddAddrOpt::FlagSet(lhs) | rhs;
}

/// \brief TCP Multipath Remove Address Option (RFC 8684, Section 3.4.2)
class TcpMpRemAddrOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::REMOVE_ADDR;
    static constexpr std::size_t minLength = 4;
    std::array<std::uint8_t, 8> addressIds = {};
    /// \brief Number of IDs in addressIds, at least 1.
    std::uint32_t count = 1;

public:
    /// \brief Returns the address IDs that this option removes.
    std::span<const std::uint8_t> getAddressIds() const
    {
        auto n = std::max<std::size_t>(1, std::min((std::size_t)count, addressIds.size()));
        return std::span<const std::uint8_t>(addressIds.data(), n);
    }

    /// \brief Compute checksum assuming option is padded to an even length
    /// with a 0x01 no-op option preceding the remove address option.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = 0;
        auto addr = getAddressIds();
        if (addr.size() % 2) {
            sum = ((uint32_t)kind << 8) | (uint32_t)size();
            sum += (uint32_t)subtype << 12;
            for (std::size_t i = 0; i < addr.size(); ++i) {
                sum += addr[i] << (8 * (i % 2 == 1));
            }
        } else {
            sum = (0x01 << 8) | (uint32_t)kind;
            sum += ((uint32_t)size() << 8) | ((uint32_t)subtype << 4);
            for (std::size_t i = 0; i < addr.size(); ++i) {
                sum += addr[i] << (8 * (i % 2 == 0));
            }
        }
        return sum;
    }

    std::size_t size() const
    {
        return 3 + std::max<std::size_t>(1, std::min((std::size_t)count, addressIds.size()));
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        auto length = (std::uint8_t)size();
        if (!stream.serializeByte(length, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (length < minLength) return err.error("invalid REMOVE_ADDR option length");
        }
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.advanceBits(4, err)) return err.propagate();
        std::uint32_t n = 1;
        if constexpr (Stream::IsReading) {
            n = (uint32_t)(length - minLength + 1);
            if (n > addressIds.size())
                return err.error("too many addresses in MPTCP REMOVE_ADDR option");
            count = n;
        } else {
            n = std::max<std::uint32_t>(1, std::min(count, (uint32_t)addressIds.size()));
        }
        for (std::uint32_t i = 0; i < n; ++i) {
            if (!stream.serializeByte(addressIds[i], err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP REMOVE_ADDR Opt ]###\n");
        out = formatIndented(out, indent, "kind         = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length       = {}\n", size());
        out = formatIndented(out, indent, "subtype      = {}\n", (unsigned)subtype);
        auto n = std::max<std::size_t>(1, std::min((std::size_t)count, addressIds.size()));
        for (std::size_t i = 0; i < n; ++i) {
            out = formatIndented(out, indent, "addressId[{}] = {}\n", i, addressIds[i]);
        }
        return out;
    }
};

/// \brief TCP Multipath Change Subflow Priority Option (RFC 8684, Section 3.3)
class TcpMpPrioOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_PRIO;
    static constexpr std::uint8_t length = 3;
    bool backup = false;

    /// \brief Compute checksum assuming option is preceded by a 0x01 no-op
    /// option aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = (0x01 << 8) | (uint32_t)kind;
        sum += ((uint32_t)length << 8) | ((uint32_t)subtype << 4) | (uint32_t)backup;
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect MP_PRIO option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        temp = backup;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        backup = (temp & 1);
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_PRIO Opt ]###\n");
        out = formatIndented(out, indent, "kind    = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length  = {}\n", size());
        out = formatIndented(out, indent, "subtype = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "backup  = {}\n", backup);
        return out;
    }
};

/// \brief TCP Multipath Fail Option (RFC 8684, Section 3.7)
class TcpMpFailOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_FAIL;
    static constexpr std::uint8_t length = 12;
    std::uint64_t dsn = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | length;
        sum += (uint32_t)subtype << 12;
        sum += details::checksumUint64(dsn);
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect MP_TCPRST option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.advanceBits(12, err)) return err.propagate();
        if (!stream.serializeUint64(dsn, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_FAIL Opt ]###\n");
        out = formatIndented(out, indent, "kind    = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length  = {}\n", size());
        out = formatIndented(out, indent, "subtype = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "dsn     = {}\n", dsn);
        return out;
    }
};

/// \brief TCP Multipath Fast Close Option (RFC 8684, Section 3.5)
class TcpMpCloseOpt
{
public:
    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_FASTCLOSE;
    static constexpr std::uint8_t length = 12;
    std::uint64_t receiverKey = 0;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | length;
        sum += (uint32_t)subtype << 12;
        sum += details::checksumUint64(receiverKey);
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect MP_FASTCLOSE option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.advanceBits(12, err)) return err.propagate();
        if (!stream.serializeUint64(receiverKey, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_FASTCLOSE Opt ]###\n");
        out = formatIndented(out, indent, "kind         = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length       = {}\n", size());
        out = formatIndented(out, indent, "subtype      = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "receiverKey  = {:#016x}\n", receiverKey);
        return out;
    }
};

/// \brief TCP Multipath Subflow Reset Option (RFC 8684, Section 3.6)
class TcpMpRstOpt
{
public:
    enum class Flags : std::uint8_t
    {
        Transient = 1 << 0, // transient error
    };
    using FlagSet = scion::details::FlagSet<Flags>;

    enum class Reason : std::uint8_t
    {
        Unspecified             = 0x00,
        MptcpSpecific           = 0x01,
        LackOfResources         = 0x02,
        Prohibited              = 0x03,
        TooMuchOutstandingData  = 0x04,
        UnacceptablePerformance = 0x05,
        MiddleboxInterference   = 0x06,
    };

    static constexpr TcpOptKind kind = TcpOptKind::MPTCP;
    static constexpr TcpMpSubtype subtype = TcpMpSubtype::MP_TCPRST;
    static constexpr std::uint8_t length = 4;
    FlagSet flags;
    Reason reason;

    /// \brief Compute checksum assuming option is aligned on a 2 byte boundary.
    std::uint32_t checksum() const
    {
        using std::uint32_t;
        uint32_t sum = ((uint32_t)kind << 8) | length;
        sum += ((uint32_t)subtype << 12) | ((uint32_t)flags << 8) | (uint32_t)reason;
        return sum;
    }

    std::size_t size() const { return length; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        static const char* msg1 = "incorrect TCP option kind";
        static const char* msg2 = "incorrect MP_TCPRST option length";
        if (!verifyByte(stream, (std::uint8_t)kind, msg1, err)) return err.propagate();
        if (!verifyByte(stream, length, msg2, err)) return err.propagate();
        auto temp = (std::uint8_t)subtype;
        if (!stream.serializeBits(temp, 4, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (temp != (std::uint8_t)subtype) return err.error("incorrect MPTCP subtype");
        }
        if (!stream.serializeBits(flags.ref(), 4, err)) return err.propagate();
        if (!stream.serializeByte((std::uint8_t&)reason, err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ TCP MP_TCPRST Opt ]###\n");
        out = formatIndented(out, indent, "kind    = {}\n", (unsigned)kind);
        out = formatIndented(out, indent, "length  = {}\n", size());
        out = formatIndented(out, indent, "subtype = {}\n", (unsigned)subtype);
        out = formatIndented(out, indent, "flags   = {:#02x}\n", (std::uint8_t)flags);
        out = formatIndented(out, indent, "reason  = {}\n", (unsigned)reason);
        return out;
    }
};

inline TcpMpRstOpt::FlagSet operator|(TcpMpRstOpt::Flags lhs, TcpMpRstOpt::Flags rhs)
{
    return TcpMpRstOpt::FlagSet(lhs) | rhs;
}

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
        std::uint32_t MSS       : 1;
        std::uint32_t WS        : 1;
        std::uint32_t SAckPerm  : 1;
        std::uint32_t SAck      : 1;
        std::uint32_t TS        : 1;
        std::uint32_t MpCapable : 1;
        std::uint32_t MpJoin    : 1;
        std::uint32_t MpDss     : 1;
        std::uint32_t MpAddAddr : 1;
        std::uint32_t MpRemAddr : 1;
        std::uint32_t MpPrio    : 1;
        std::uint32_t MpFail    : 1;
        std::uint32_t MpClose   : 1;
        std::uint32_t MpRst     : 1;
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
        TcpMssOpt mss;         // valid if optMask.MSS == 1
        TcpWsOpt ws;           // valid if optMask.WS == 1
        TcpSAckOpt sack;       // valid if optMask.SAck == 1
        TcpTsOpt ts;           // valid if optMask.TS == 1
        TcpMpCapableOpt mpCap; // valid if optMask.MpCapable == 1
        TcpMpJoinOpt mpJoin;   // valid if optMask.MpJoin == 1
        TcpMpDssOpt mpDss;     // valid if optMask.MpDss == 1
        TcpMpAddAddrOpt mpAdd; // valid if optMask.MpAddAddr == 1
        TcpMpRemAddrOpt mpRem; // valid if optMask.MpRemAddr == 1
        TcpMpPrioOpt mpPrio;   // valid if optMask.MpPrio == 1
        TcpMpFailOpt mpFail;   // valid if optMask.MpFail == 1
        TcpMpCloseOpt mpClose; // valid if optMask.MpClose == 1
        TcpMpRstOpt mpRst;     // valid if optMask.MpRst == 1
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
        auto key = (std::uint32_t(PROTO) << 16) | (sport ^ dport);
        std::uint32_t hash;
        scion::hash32(&key, sizeof(key), 0, &hash);
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
        if (optMask.MpCapable) {
            out = options.mpCap.print(out, indent);
        }
        if (optMask.MpJoin) {
            out = options.mpJoin.print(out, indent);
        }
        if (optMask.MpDss) {
            out = options.mpDss.print(out, indent);
        }
        if (optMask.MpAddAddr) {
            out = options.mpAdd.print(out, indent);
        }
        if (optMask.MpRemAddr) {
            out = options.mpRem.print(out, indent);
        }
        if (optMask.MpPrio) {
            out = options.mpPrio.print(out, indent);
        }
        if (optMask.MpFail) {
            out = options.mpFail.print(out, indent);
        }
        if (optMask.MpClose) {
            out = options.mpClose.print(out, indent);
        }
        if (optMask.MpRst) {
            out = options.mpRst.print(out, indent);
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
            case TcpOptKind::MPTCP:
            {
                if (!rs.lookahead(next, 3, err)) return err.propagate();
                switch ((TcpMpSubtype)(next.back() >> 4)) {
                case TcpMpSubtype::MP_CAPABLE:
                    if (!options.mpCap.serialize(rs, err)) return err.propagate();
                    optMask.MpCapable = 1;
                    break;
                case TcpMpSubtype::MP_JOIN:
                    if (!options.mpJoin.serialize(rs, err)) return err.propagate();
                    optMask.MpJoin = 1;
                    break;
                case TcpMpSubtype::DSS:
                    if (!options.mpDss.serialize(rs, err)) return err.propagate();
                    optMask.MpDss = 1;
                    break;
                case TcpMpSubtype::ADD_ADDR:
                    if (!options.mpAdd.serialize(rs, err)) return err.propagate();
                    optMask.MpAddAddr = 1;
                    break;
                case TcpMpSubtype::REMOVE_ADDR:
                    if (!options.mpRem.serialize(rs, err)) return err.propagate();
                    optMask.MpRemAddr = 1;
                    break;
                case TcpMpSubtype::MP_PRIO:
                    if (!options.mpPrio.serialize(rs, err)) return err.propagate();
                    optMask.MpPrio = 1;
                    break;
                case TcpMpSubtype::MP_FAIL:
                    if (!options.mpFail.serialize(rs, err)) return err.propagate();
                    optMask.MpFail = 1;
                    break;
                case TcpMpSubtype::MP_FASTCLOSE:
                    if (!options.mpClose.serialize(rs, err)) return err.propagate();
                    optMask.MpClose = 1;
                    break;
                case TcpMpSubtype::MP_TCPRST:
                    if (!options.mpRst.serialize(rs, err)) return err.propagate();
                    optMask.MpRst = 1;
                    break;
                default:
                    return err.error("unknown MPTCP option subtype");
                }
                break;
            }
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
            if (len % 4 == 2) {       // 10 bytes
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
        if (optMask.MpCapable) {
            if (!options.mpCap.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpJoin) {
            if (!options.mpJoin.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpDss) {
            if (!options.mpDss.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpAddAddr) {
            if (!options.mpAdd.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpRemAddr) {      // padded to even length
            if (options.mpRem.size() % 2) {
                if (!ws.serializeByte(0x01, err)) return err.propagate();
            }
            if (!options.mpRem.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpPrio) {         // 3 bytes + 1 byte padding
            if (!ws.serializeByte(0x01, err)) return err.propagate();
            if (!options.mpPrio.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpFail) {
            if (!options.mpFail.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpClose) {
            if (!options.mpClose.serialize(ws, err)) return err.propagate();
        }
        if (optMask.MpRst) {
            if (!options.mpRst.serialize(ws, err)) return err.propagate();
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
            if (len % 4 == 2)
                len += TcpTsOpt::length; // no padding
            else
                len += TcpTsOpt::length + 2; // 2 bytes padding
        }
        if (optMask.WS) len += TcpWsOpt::length + 1; // 1 byte padding
        if (optMask.MpCapable) len += options.mpCap.size();
        if (optMask.MpJoin) len += options.mpJoin.size();
        if (optMask.MpDss) len += options.mpDss.size();
        if (optMask.MpAddAddr) len += options.mpAdd.size();
        if (optMask.MpRemAddr) {
            auto size = options.mpRem.size();
            len += 2 * ((size + 1) / 2); // padded to an even number of bytes
        }
        if (optMask.MpPrio) len += options.mpPrio.size() + 1; // 1 byte padding
        if (optMask.MpFail) len += options.mpFail.size();
        if (optMask.MpClose) len += options.mpClose.size();
        if (optMask.MpRst) len += options.mpRst.size();
        return (len + 3) & ~((std::size_t)3); // round up to a multiple of 4
    }

    std::uint32_t checksumOpts() const
    {
        std::size_t len = 0;
        std::uint32_t sum = 0;
        if (optMask.MSS) {
            len += TcpMssOpt::length;
            sum += options.mss.checksum();
        }
        if (optMask.SAckPerm) {
            len += TcpSAckPermOpt::length;
            sum += TcpSAckPermOpt().checksum();
        }
        if (optMask.SAck) {
            len += options.sack.size() + 2; // 2 bytes padding
            sum += options.sack.checksum();
        }
        if (optMask.TS) {
            if (len % 4 == 2) {
                len += TcpTsOpt::length; // no padding
                sum += options.ts.checksum();
            } else {
                len += TcpTsOpt::length + 2; // 2 bytes padding
                sum += 0x0101 + options.ts.checksum();
            }
        }
        if (optMask.WS) {
            len += TcpWsOpt::length + 1; // 1 byte padding
            sum += options.ws.checksum();
        }
        if (optMask.MpCapable) {
            len += options.mpCap.size();
            sum += options.mpCap.checksum();
        }
        if (optMask.MpJoin) {
            len += options.mpJoin.size();
            sum += options.mpJoin.checksum();
        }
        if (optMask.MpDss) {
            len += options.mpDss.size();
            sum += options.mpDss.checksum();
        }
        if (optMask.MpAddAddr) {
            len += options.mpAdd.size();
            sum += options.mpAdd.checksum();
        }
        if (optMask.MpRemAddr) {
            len += 2 * ((options.mpRem.size() + 1) / 2); // padded to an even number of bytes
            sum += options.mpRem.checksum();
        }
        if (optMask.MpPrio) {
            len += options.mpPrio.size() + 1; // 1 byte padding
            sum += options.mpPrio.checksum();
        }
        if (optMask.MpFail) {
            len += options.mpFail.size();
            sum += options.mpFail.checksum();
        }
        if (optMask.MpClose) {
            len += options.mpClose.size();
            sum += options.mpClose.checksum();
        }
        if (optMask.MpRst) {
            len += options.mpRst.size();
            sum += options.mpRst.checksum();
        }
        // final padding uses zero bytes
        return sum;
    }
};

inline TCP::FlagSet operator|(TCP::Flags lhs, TCP::Flags rhs)
{
    return TCP::FlagSet(lhs) | rhs;
}

} // namespace hdr
} // namespace scion
