// Copyright (c) 2026 Lars-Christian Schulz
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

#include "scion/bit_stream.hpp"
#include "scion/crypto/aes.hpp"
#include "scion/details/debug.hpp"
#include "scion/extensions/idint.hpp"
#include "scion/hdr/idint.hpp"

#include <botan/system_rng.h>

#include <array>
#include <bit>
#include <cstring>

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;


static inline void verify(bool ok)
{
    assert(ok && "logic error in metadata encoder");
}

namespace scion {
namespace idint {

Nonce randomNonce()
{
    constexpr std::size_t size = std::tuple_size<Nonce>();
    return std::bit_cast<Nonce>(Botan::system_rng().random_array<size>());
}

void IntMetadata::encode(hdr::IdIntEntry& dst) const
{
    using namespace scion::hdr;

    dst.flags = {};
    if (m_flags.source) dst.flags |= IdIntEntry::Flags::Source;
    if (m_flags.ingress) dst.flags |= IdIntEntry::Flags::Ingress;
    if (m_flags.egress) dst.flags |= IdIntEntry::Flags::Egress;
    if (m_flags.aggregate) dst.flags |= IdIntEntry::Flags::Aggregate;

    dst.hop = m_hopIndex;
    dst.mask = m_bitmap;
    for (unsigned int i = 0; i < 4; ++i) {
        dst.ml[i] = m_size[i] / 2;
    }

    WriteStream ws(dst.metadata());
    if (dst.mask & InstrFlag::NodeID) {
        verify(ws.serializeUint32(m_nodeId, NullStreamError));
    }
    if (dst.mask & InstrFlag::NodeCnt) {
        verify(ws.serializeUint16(m_nodeCnt, NullStreamError));
    }
    if (dst.mask & InstrFlag::IgPort) {
        verify(ws.serializeUint16(m_ingressPort, NullStreamError));
    }
    if (dst.mask & InstrFlag::EgPort) {
        verify(ws.serializeUint16(m_egressPort, NullStreamError));
    }
    for (unsigned int i = 0; i < 4; ++i) {
        switch (m_size[i]) {
        case 0:
            break;
        case 2:
            verify(ws.serializeUint16(static_cast<uint16_t>(m_data[i]), NullStreamError));
            break;
        case 4:
            verify(ws.serializeUint32(static_cast<uint32_t>(m_data[i]), NullStreamError));
            break;
        case 6:
        {
            auto temp = scion::details::byteswapBE(static_cast<uint64_t>(m_data[i]));
            std::array<std::byte, 6> buf;
            // value in buf is big-endian at this point
            std::memcpy(buf.data(), reinterpret_cast<std::byte*>(&temp) + 2, buf.size());
            verify(ws.serializeBytes(buf, NullStreamError));
            break;
        }
        case 8:
            verify(ws.serializeUint64(static_cast<uint64_t>(m_data[i]), NullStreamError));
            break;
        default:
            assert(false && "invalid metadata size");
        }
    }

    // Pad metadata to a multiple of 4 + 2, so that combined with the rest of
    // the option we get a length that is a multiple of 4.
    auto padding = -(ws.getPos().first + 2u) & 0x03u;
    verify(ws.advanceBytes(padding, NullStreamError));
}

void IntMetadata::decode(const hdr::IdIntEntry& src, bool wasEncrypted)
{
    using namespace scion::hdr;

    m_flags.source = !!(src.flags & IdIntEntry::Flags::Source);
    m_flags.ingress = !!(src.flags & IdIntEntry::Flags::Ingress);
    m_flags.egress = !!(src.flags & IdIntEntry::Flags::Egress);
    m_flags.aggregate = !!(src.flags & IdIntEntry::Flags::Aggregate);
    m_flags.wasEncrypted = wasEncrypted;

    m_hopIndex = src.hop;
    m_bitmap = src.mask;
    for (unsigned int i = 0; i < 4; ++i) {
        m_size[i] = 2 * src.ml[i];
    }

    ReadStream rs(src.metadata());
    if (src.mask & InstrFlag::NodeID) {
        verify(rs.serializeUint32(m_nodeId, NullStreamError));
    }
    if (src.mask & InstrFlag::NodeCnt) {
        verify(rs.serializeUint16(m_nodeCnt, NullStreamError));
    }
    if (src.mask & InstrFlag::IgPort) {
        verify(rs.serializeUint16(m_ingressPort, NullStreamError));
    }
    if (src.mask & InstrFlag::EgPort) {
        verify(rs.serializeUint16(m_egressPort, NullStreamError));
    }
    for (unsigned int i = 0; i < 4; ++i) {
        switch (m_size[i]) {
        case 0:
            break;
        case 2:
        {
            uint16_t temp = 0;
            verify(rs.serializeUint16(temp, NullStreamError));
            m_data[i] = temp;
            break;
        }
        case 4:
        {
            uint32_t temp = 0;
            verify(rs.serializeUint32(temp, NullStreamError));
            m_data[i] = temp;
            break;
        }
        case 6:
        {
            uint64_t temp = 0;
            std::array<std::byte, 6> buf;
            verify(rs.serializeBytes(buf, NullStreamError));
            // value in buf is big-endian at this point
            std::memcpy(reinterpret_cast<std::byte*>(&temp) + 2, buf.data(), buf.size());
            m_data[i] = scion::details::byteswapBE(temp);
            break;
        }
        case 8:
        {
            uint64_t temp = 0;
            verify(rs.serializeUint64(temp, NullStreamError));
            m_data[i] = temp;
            break;
        }
        default:
            assert(false && "invalid metadata size");
        }
    }
}

namespace details {

static MAC calcSourceMAC(
    const hdr::IdIntEntry& e, const hdr::IdIntOpt& header, const drkey::Key& key);
static MAC calcMAC(const hdr::IdIntEntry& e, MAC prevMAC, const drkey::Key& key);

void authSourceEntry(hdr::IdIntEntry& e, const hdr::IdIntOpt& header, const drkey::Key& key)
{
    e.setMAC(calcSourceMAC(e, header, key));
}

void encryptSourceEntry(
    hdr::IdIntEntry& e,
    const hdr::IdIntOpt& header,
    const drkey::Key& key,
    const Nonce& nonce)
{
    e.flags |= hdr::IdIntEntry::Flags::Encrypted;
    e.nonce = nonce;
    e.setMAC(calcSourceMAC(e, header, key));
    auto err = crypto::aesCtrMode(key.key, e.nonce, e.metadataWithMAC());
    if (err) {
        assert(0 && "implementation error in crypto module");
        std::abort();
    }
}

MAC decryptAndMAC(
    hdr::IdIntEntry& e,
    const hdr::IdIntOpt& header,
    MAC& prevMAC,
    const drkey::Key& key)
{
    auto encMAC = e.mac(); // MAC chaning uses encrypted MACs
    if (e.flags & hdr::IdIntEntry::Flags::Encrypted) {
        auto err = crypto::aesCtrMode(key.key, e.nonce, e.metadataWithMAC());
        if (err) {
            assert(0 && "implementation error in crypto module");
            std::abort();
        }
    }
    MAC mac;
    if (e.flags & hdr::IdIntEntry::Flags::Source) {
        mac = calcSourceMAC(e, header, key);
    } else {
        mac = calcMAC(e, prevMAC, key);
    }
    // Clear encrypted flag after the MAC has been calculated
    e.flags |= hdr::IdIntEntry::Flags::Encrypted;
    prevMAC = encMAC;
    return mac;
}

static MAC calcSourceMAC(
    const hdr::IdIntEntry& e,
    const hdr::IdIntOpt& header,
    const drkey::Key& key)
{
    // Serialize main header and source stack entry
    std::array<std::byte, 128> buf;
    WriteStream ws(buf);
    SCION_STREAM_ERROR err;
    if (!const_cast<hdr::IdIntOpt&>(header).serialize(ws, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }
    if (!const_cast<hdr::IdIntEntry&>(e).serialize(ws, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }

    // Zero-out updatable fields
    buf[2] &= std::byte{0xfd}; // ignore telemetry stack space exhausted flag
    buf[5] = std::byte{0};
    buf[6] = std::byte{0};
    buf[7] = std::byte{0};

    std::span<std::byte> input;
    std::array<std::byte, 16> mac;
    if (!ws.lookback(input, WriteStream::npos, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }
    input = input.subspan(0, input.size()-4); // ignore the current MAC
    crypto::aesCbcMac(key.key, input, mac);

    return MAC{mac[0], mac[1], mac[2], mac[3]};
}

static MAC calcMAC(const hdr::IdIntEntry& e, MAC prevMAC, const drkey::Key& key)
{
    std::array<std::byte, 64> buf;

    // Serialize entry
    WriteStream ws(buf);
    SCION_STREAM_ERROR err;
    if (!const_cast<hdr::IdIntEntry&>(e).serialize(ws, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }

    // Overwrite MAC with the MAC of the previous hop
    auto pos = ws.getPos().first;
    if (!ws.seek(pos - 4, 0)) {
        return MAC{};
    }
    if (!ws.serializeBytes(prevMAC, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }

    std::span<std::byte> input;
    std::array<std::byte, 16> mac;
    if (!ws.lookback(input, WriteStream::npos, err)) {
        SCION_DEBUG_PRINT(err);
        return MAC{};
    }
    crypto::aesCbcMac(key.key, input, mac);
    return MAC{mac[0], mac[1], mac[2], mac[3]};
}

} // namespace details
} // namespace idint
} // namespace scion
