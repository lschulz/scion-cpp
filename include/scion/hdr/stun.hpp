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
#include "scion/bit_stream.hpp"
#include "scion/details/bit.hpp"
#include "scion/details/flags.hpp"
#include "scion/hdr/details.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>


namespace scion {
namespace hdr {

enum class StunMsgType : std::uint16_t
{
    BindingRequest  = 0x0001,
    BindingResponse = 0x0101,
};

enum class StunAttribType : std::uint16_t
{
    // comprehension optional
    Reserved         = 0x0000,
    MappedAddress    = 0x0001,
    Username         = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode        = 0x0009,
    Unknown          = 0x000a,
    Realm            = 0x0014,
    Nonce            = 0x0015,
    XorMappedAddress = 0x0020,
    // comprehension required
    Software         = 0x8022,
    AlternateServer  = 0x8023,
    Fingerprint      = 0x8028,
};

enum class StunAddrFamily : std::uint8_t
{
    IPv4 = 0x01,
    IPv6 = 0x02,
};

/// \brief Generic STUN Attribute.
class StunAttribute
{
public:
    static constexpr std::size_t minSize = 4;

    StunAttribType type = StunAttribType::Reserved;
    std::uint16_t length = 0;
    std::array<std::byte, 32> value = {};

    /// \brief Returns valid size of `value`.
    std::size_t getValueSize() const
    {
        return std::min((std::size_t)length, value.size());
    }

    /// \brief Set the attribute value size in bytes. The maximum supported size
    /// is 16 bytes.
    void setValueSize(std::size_t size)
    {
        assert(size <= value.size());
        length = (std::uint16_t)size;
    }

    /// \brief Get a view of the valid range of `value`.
    std::span<const std::byte> getValue() const
    {
        return std::span<const std::byte>(value.data(), getValueSize());
    }

    /// \brief Get a view of the valid range of `value`.
    std::span<std::byte> getValue()
    {
        return std::span<std::byte>(value.data(), getValueSize());
    }

    std::size_t size() const
    {
        return minSize + length;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto temp = (std::uint16_t)type;
        if (!stream.serializeUint16(temp, err)) return err.propagate();
        type = (StunAttribType)temp;
        if (!stream.serializeUint16(length, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (length > value.size()) return err.error("STUN attribute too large");
        }
        if (!stream.serializeBytes(getValue(), err)) return err.propagate();
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ STUN Generic TLV ]###\n");
        out = formatIndented(out, indent, "type   = {}\n", (std::uint16_t)type);
        out = formatIndented(out, indent, "length = {}\n", length);
        out = formatIndented(out, indent, "value  = ");
        out = formatBytes(out, getValue());
        return std::format_to(out, "\n");
    }
};

/// \brief STUN XOR-MAPPED-ADDRESS attribute.
class StunXorMappedAddress
{
public:
    static constexpr std::size_t minSize = 8;
    static constexpr StunAttribType type = StunAttribType::XorMappedAddress;

    generic::IPEndpoint address;

    std::size_t size() const
    {
        return minSize + address.host().size();
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, const std::array<std::byte, 12>& tx, Error& err);

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ STUN XOR-MAPPED-ADDRESS ]###\n");
        out = formatIndented(out, indent, "type    = {}\n", (std::uint16_t)type);
        out = formatIndented(out, indent, "length  = {}\n", size() - 4);
        out = formatIndented(out, indent, "port    = {}\n", address.port());
        out = formatIndented(out, indent, "address = {}\n", address.host());
        return out;
    }
};

/// \brief Simplified STUN message (RFC 5389).
class STUN
{
public:
    /// \brief Magic cookie in host byte order.
    static constexpr std::uint32_t magicCookie = 0x2112a442u;
    static constexpr std::size_t stunHeaderSize = 20;

    StunMsgType type = StunMsgType::BindingRequest;
    std::array<std::byte, 12> transaction;
    std::optional<StunXorMappedAddress> mapped;

    bool operator==(const STUN&) const = default;

    std::size_t size() const
    {
        auto size = stunHeaderSize;
        if (mapped) size += mapped->size();
        return size;
    }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        auto temp = (std::uint16_t)type;
        if (!stream.serializeUint16(temp, err)) return err.propagate();
        type = (StunMsgType)temp;
        auto length = (std::uint16_t)(size() - stunHeaderSize);
        if (!stream.serializeUint16(length, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
        }
        std::uint32_t cookie = magicCookie;
        if (!stream.serializeUint32(cookie, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            if (cookie != magicCookie) return err.error("magic cookie does not match");
        }
        if (!stream.serializeBytes(transaction, err)) return err.propagate();
        if constexpr (Stream::IsReading) {
            std::span<const std::byte> attribs;
            if (!stream.lookahead(attribs, length, err)) return err.propagate();
            ReadStream rs(attribs);
            if (!parseAttributes(rs, err)) return err.propagate();
        } else {
            if (!emitAttributes(stream, err)) return err.propagate();
        }
        return true;
    }

    auto print(auto out, int indent) const
    {
        using namespace details;
        out = std::format_to(out, "###[ STUN ]###\n");
        out = formatIndented(out, indent, "type        = {}\n", (std::uint16_t)type);
        out = formatIndented(out, indent, "transaction = ");
        out = formatBytes(out, transaction);
        out = std::format_to(out, "\n");
        if (mapped) {
            out = std::format_to(out, "xor mapped  = {}\n", mapped->address);
        }
        return out;
    }

private:
    template <typename ReadStream, typename Error>
    bool parseAttributes(ReadStream& rs, Error& err)
    {
        StunAttribute attrib;
        while (rs) {
            std::uint16_t type = 0;
            std::span<const std::byte> ptr;
            if (!rs.lookahead(ptr, 2, err)) return err.propagate();
            std::memcpy(&type, ptr.data(), 2);
            switch ((StunAttribType)scion::details::byteswapBE(type)) {
            case StunAttribType::XorMappedAddress:
                mapped = StunXorMappedAddress();
                if (!mapped->serialize(rs, transaction, err)) return err.propagate();
                break;
            default:
                if (!attrib.serialize(rs, err)) return err.propagate();
                if ((int)attrib.type < 0x8000 && attrib.type > StunAttribType::XorMappedAddress) {
                    // Attribute type between 0x000 and 0x7fff require comprehension in order to
                    // correctly interpret the message.
                    return err.error("STUN attribute not understood");
                }
                break;
            }
        }
        return true;
    }

    template <typename WriteStream, typename Error>
    bool emitAttributes(WriteStream& ws, Error& err)
    {
        if (mapped) {
            if (!mapped->serialize(ws, transaction, err)) return err.propagate();
        }
        return true;
    }
};

template <typename Stream, typename Error>
bool StunXorMappedAddress::serialize(
    Stream& stream, const std::array<std::byte, 12>& tx, Error& err)
{
    auto temp = (std::uint16_t)type;
    if (!stream.serializeUint16(temp, err)) return err.propagate();
    if constexpr (Stream::IsReading) {
        if (temp != (std::uint16_t)type)
            return err.error("incorrect attribute type");
    }
    auto length = (std::uint16_t)(size() - StunAttribute::minSize);
    if (!stream.serializeUint16(length, err)) return err.propagate();
    if (!stream.advanceBytes(1, err)) return err.propagate();
    auto family = address.host().is4() ? StunAddrFamily::IPv4 : StunAddrFamily::IPv6;
    if (!stream.serializeByte((std::uint8_t&)family, err)) return err.propagate();
    if constexpr (Stream::IsReading) {
        if (family == StunAddrFamily::IPv4) {
            if (length != 8) return err.error("STUN XOR-MAPPED_ADDRESS has invalid length");
        } else if (family == StunAddrFamily::IPv6) {
            if (length != 20) return err.error("STUN XOR-MAPPED_ADDRESS has invalid length");
        } else {
            return err.error("STUN XOR-MAPPED_ADDRESS unexpected address family");
        }
    }
    if constexpr (Stream::IsReading) {
        std::uint16_t port;
        if (!stream.serializeUint16(port, err)) return err.propagate();
        port ^= (std::uint16_t)(STUN::magicCookie >> 16);
        if (family == StunAddrFamily::IPv4) {
            std::uint32_t ip;
            if (!stream.serializeUint32(ip, err)) return err.propagate();
            ip ^= STUN::magicCookie;
            address = generic::IPEndpoint{generic::IPAddress::MakeIPv4(ip), port};
        } else {
            std::array<std::byte, 16> buf;
            if (!stream.serializeBytes(buf, err)) return err.propagate();
            auto [hi, lo] = generic::IPAddress::MakeIPv6(buf).getIPv6();
            std::uint32_t a = 0;
            std::uint64_t b = 0;
            std::memcpy(&a, tx.data(), 4);
            std::memcpy(&b, tx.data() + 4, 8);
            hi ^= (std::uint64_t{STUN::magicCookie} << 32) | scion::details::byteswapBE(a);
            lo ^= scion::details::byteswapBE(b);
            address = generic::IPEndpoint{generic::IPAddress::MakeIPv6(hi, lo), port};
        }
    } else {
        std::uint16_t port = address.port() ^ (std::uint16_t)(STUN::magicCookie >> 16);
        if (!stream.serializeUint16(port, err)) return err.propagate();
        if (address.host().is4()) {
            auto ip = address.host().getIPv4() ^ STUN::magicCookie;
            if (!stream.serializeUint32(ip, err)) return err.propagate();
        } else {
            auto [hi, lo] = address.host().getIPv6();
            std::uint32_t a = 0;
            std::uint64_t b = 0;
            std::memcpy(&a, tx.data(), 4);
            std::memcpy(&b, tx.data() + 4, 8);
            hi ^= (std::uint64_t{STUN::magicCookie} << 32) | scion::details::byteswapBE(a);
            lo ^= scion::details::byteswapBE(b);
            if (!generic::IPAddress::MakeIPv6(hi, lo).serialize(stream, false, err))
                return err.propagate();
        }
    }
    return true;
}

/// \brief Returns true if the packet in the given buffer contains the magic
/// cookie expected by STUN.
inline bool detectStun(std::span<const std::byte> buf)
{
    if (buf.size() < STUN::stunHeaderSize)
        return false;
    std::uint32_t signature;
    std::memcpy(&signature, buf.data() + 4, 4);
    return signature == scion::details::byteswapBE(STUN::magicCookie);
}

} // namespace hdr
} // namespace scion
