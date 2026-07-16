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

#include "scion/bit_stream.hpp"
#include "scion/drkey/drkey.hpp"
#include "scion/extensions/extension.hpp"
#include "scion/extensions/idint_instr.hpp"
#include "scion/hdr/idint.hpp"

#include <chrono>
#include <concepts>
#include <memory>
#include <utility>
#include <vector>


class PacketSocketFixture;

namespace scion {
namespace idint {

template <typename T>
concept MetadataValue =
    std::is_same_v<T, std::uint8_t>
    || std::is_same_v<T, std::uint16_t>
    || std::is_same_v<T, std::uint32_t>
    || std::is_same_v<T, std::uint64_t>;

namespace details {
void authSourceEntry(hdr::IdIntEntry&, const hdr::IdIntOpt&, const drkey::Key&);
void encryptSourceEntry(hdr::IdIntEntry&, const hdr::IdIntOpt&, const drkey::Key&, const Nonce&);
MAC decryptAndMAC(hdr::IdIntEntry&, const hdr::IdIntOpt&, MAC&, const drkey::Key&);
}

// How much an ID-INT timestamp is allowed to be in the past for the data to
// be considered valid. In nanoseconds.
constexpr auto MAX_AGE = 60'000'000'000ull;

/// Decoded telemetry data.
class IntMetadata
{
private:
    struct {
        std::uint8_t source    : 1;
        std::uint8_t ingress   : 1;
        std::uint8_t egress    : 1;
        std::uint8_t aggregate : 1;
    } m_flags = {};

    std::uint8_t m_hopIndex = 0;

    InstrBitmap m_bitmap;
    std::uint32_t m_nodeId = 0;
    std::uint16_t m_nodeCnt = 0;
    std::uint16_t m_ingressPort = 0;
    std::uint16_t m_egressPort = 0;

    std::array<std::uint8_t, 4> m_size = {};
    std::array<std::uint64_t, 4> m_data = {};

public:
    static constexpr IntMetadata MakeSource()
    {
        IntMetadata sourceMd{};
        sourceMd.m_flags.source = 1;
        return sourceMd;
    }

    /// \brief Encode to ID-INT stack option.
    void encode(hdr::IdIntEntry& dst) const;

    /// \brief Decode from ID-INT stack option.
    void decode(const hdr::IdIntEntry& src);

    bool isSource() const { return m_flags.source; }
    bool isIngress() const { return m_flags.ingress; }
    bool isEgress() const { return m_flags.egress; }
    bool isAggregate() const { return m_flags.aggregate; }

    std::uint8_t hopIndex() const { return m_hopIndex; }

    InstrBitmap bitmap() const { return m_bitmap; }
    std::uint32_t nodeId() const { return m_nodeId; }
    std::uint16_t nodeCount() const { return m_nodeCnt; }
    std::uint16_t ingressPort() const { return m_ingressPort; }
    std::uint16_t egressPort() const { return m_egressPort; }

    /// \brief Returns metadata value as type \tparam T.
    /// \param slot Must be < 4.
    template <MetadataValue T = std::uint64_t>
    T metadata(std::size_t slot) const
    {
        assert(slot < 4);
        if (slot >= 4) return 0;
        return static_cast<T>(m_data[slot]);
    }

    /// \brief Copy metadata value to `dst`.
    void metadata(std::size_t slot, std::uint64_t& dst) {
        assert(slot < 4);
        if (slot < 4) {
            dst = m_data[slot];
        } else {
            dst = 0;
        }
    }

    bool hasNodeId() const
    {
        return m_bitmap[InstrFlag::NodeID];
    }

    void setNodeId(std::uint32_t nid)
    {
        m_bitmap[InstrFlag::NodeID] = true;
        m_nodeId = nid;
    }
    void clearNodeId()
    {
        m_bitmap[InstrFlag::NodeID] = false;
    }

    bool hasNodeCount() const
    {
        return m_bitmap[InstrFlag::NodeCnt];
    }

    void setNodeCount(std::uint16_t count)
    {
        m_bitmap[InstrFlag::NodeCnt] = true;
        m_nodeCnt = count;
    }

    void clearNodeCount()
    {
        m_bitmap[InstrFlag::NodeCnt] = false;
    }

    bool hasIngressPort() const
    {
        return m_bitmap[InstrFlag::IgPort];
    }

    void setIngressPort(std::uint16_t port)
    {
        m_bitmap[InstrFlag::IgPort] = true;
        m_ingressPort = port;
    }

    void clearIngressPort()
    {
        m_bitmap[InstrFlag::IgPort] = false;
    }

    bool hasEgressPort() const
    {
        return m_bitmap[InstrFlag::EgPort];
    }

    void setEgressPort(std::uint16_t port)
    {
        m_bitmap[InstrFlag::EgPort] = true;
        m_egressPort = port;
    }

    void clearEgressPort()
    {
        m_bitmap[InstrFlag::EgPort] = false;
    }

    /// \brief Returns the size in bytes of the metadata value in any slot.
    /// Returns 0 if there is no value.
    std::size_t metadataSize(std::size_t slot) const
    {
        assert(slot < 4);
        if (slot >= 4) return 0;
        return m_size[slot];
    }

    /// \brief Set metadata in one of the four available slots.
    /// \param slot Must be < 4.
    /// \param instr Instruction the value belongs to. Determines the expected
    /// data size. See also MetadataSize().
    /// \param data Data to set. Must be a 2, 4, or 8 byte unsigned integer.
    template <MetadataValue T = std::uint64_t>
    void setMetadata(std::size_t slot, Instr instr, T data)
    {
        static_assert(sizeof(data) == 2 || sizeof(data) == 4 || sizeof(data) == 8);
        assert(slot < 4);
        if (slot < 4) {
            m_size[slot] = (std::uint8_t)MetadataSize(instr);
            m_data[slot] = static_cast<std::uint64_t>(data);
        }
    }

    /// \brief Set the given metadata slot to free again.
    /// \param slot Must be < 4.
    void clearMetadata(std::size_t slot)
    {
        assert(slot < 4);
        if (slot < 4) {
            m_size[slot] = 0;
        }
    }
};

/// Telemetry request that may be encoded to a packet header.
class IntRequest
{
public:
    struct {
        /// Strip ID-INT extension headers before delivering to end host.
        std::uint8_t infrastructure : 1;
        /// Discard packet at arrival in destination AS.
        std::uint8_t discard   : 1;
        /// Ask routers to encrypt telemetry data.
        std::uint8_t encrypt   : 1;
    } flags = {};

    /// How many hop fields to skip before the first non-source telemetry is
    /// recorded.
    std::uint8_t skipHops = 0;
    /// Bitmap-encoded telemetry instructions.
    InstrBitmap bitmap;
    /// Aggregation mode.
    AM agrMode = AM::Off;

    /// Size of the telemetry stack to allocate in bytes. Must be a multiple of
    /// 4 and provide sufficient space for at least the source entry.
    unsigned int maxStackLen = 0;

    /// Aggregation function for each instruction slot.
    std::array<AF, 4> agrFuncs = {};
    /// Instruction slots.
    std::array<Instr, 4> instructions = {};
    /// Verifier type.
    Verifier vtype = Verifier::Destination;
    /// Verifier address if vtype is third-party.
    ScIPAddress verifier;

    /// Request identifier consisting of a timestamp with nanosecond precision
    /// and an egress port identifier. The combination of timestamp and port
    /// must be unique for every request sent under the same key.
    struct {
        std::uint64_t timestamp : 48;
        std::uint16_t port      : 16;
    } identifier;

    /// Telemetry reported by the request originator.
    IntMetadata srcData = IntMetadata::MakeSource();
};

/// Decoded ID-INT telemetry.
template <typename Alloc = std::allocator<IntMetadata>>
class IntReport
{
public:
    explicit IntReport(Alloc alloc = Alloc())
        : data(alloc)
    {}

    using MetadataVec = std::vector<IntMetadata, Alloc>;

    /// Whether metadata was omitted because the maximum stack size was reached
    bool stackFull = false;
    /// Source timestamp and port
    struct {
        /// Lower 48 bits of the time since the Unix epoch in nanosecconds.
        std::uint64_t timestamp : 48;
        std::uint64_t port      : 16;
    } identifier;
    /// Requested aggregation mode
    AM agrMode = AM::Off;
    /// Aggregation function for each instruction slot
    std::array<AF, 4> agrFuncs = {};
    /// Instruction slots (type of requested metadata)
    std::array<Instr, 4> instructions;
    /// Telemetry data in path order (source to destination)
    MetadataVec data;
};

struct VerificationStatus
{
    std::error_code error; ///< Error code

    struct Location {
        bool isSource = false; ///< Error in source entry
        int hopIndex = 0;      ///< Hop field index the invalid stack entry is attached to.
        IsdAsn isdAsn;         ///< Origin AS and ISD.
    } location;                ///< First hop that failed verification if there was an error.

    MAC expectedMAC = {}; ///< Computed MAC. Zero if no MAC could be computed.
    MAC actualMAC = {};   ///< Decrypted MAC from the packet. Zero if no MAC could be computed.

    /// \brief Converts to true if there were no errors.
    operator bool() const {
        return !error;
    }
};

template <typename Alloc = std::allocator<hdr::IdIntEntry>>
class IdInt : public ext::Extension
{
private:
    using EntryVec = std::vector<hdr::IdIntEntry, Alloc>;

    hdr::IdIntOpt main;
    EntryVec entries;

    friend class ::PacketSocketFixture;

public:
    explicit IdInt(Alloc alloc = Alloc())
        : entries(alloc)
    {}

    const hdr::IdIntOpt& getRawMainHeader() const { return main; }
    const EntryVec& getRawEntries() const { return entries; }

    ext::Category category() const override { return ext::Category::HopByHop; }
    hdr::OptType type() const override { return hdr::IdIntOpt::type; }

    std::size_t size(std::size_t pos) const override
    {
        return padding(pos, 4, 2) + main.size() + 4 * (std::size_t)(main.stackLen);
    }

    bool parse(ReadStream& rs, SCION_STREAM_ERROR& err) override
    {
        return serialize(rs, 0, err);
    }

    bool write(WriteStream& ws, std::size_t pos, SCION_STREAM_ERROR& err) const override
    {
        return const_cast<IdInt*>(this)->serialize(ws, pos, err);
    }

    /// \param pos Byte offset from the beginning of the extensions headers
    /// for calculating necessary alignment padding.
    template <typename Stream, typename Error>
    bool serialize(Stream& stream, std::size_t pos, Error& err)
    {
        if constexpr (Stream::IsWriting) {
            if (!insertPadding(padding(pos, 4, 2), stream, err)) return err.propagate();
        } else {
            setInvalid();
        }
        if (!main.serialize(stream, err)) return err.propagate();
        if constexpr (Stream::IsWriting) {
            auto stackBegin = stream.getPtr();
            for (auto& entry : entries) {
                if (!entry.serialize(stream, err)) return err.propagate();
            }
            auto stackLen = stream.getPtr() - stackBegin;
            assert(stackLen % 4 == 0);
            int padding = 4 * (int)(main.stackLen) - (int)stackLen;
            if (padding < 0) {
                return err.error("ID-INT stack length fields does not match actual length");
            }
            if (!insertPadding((std::size_t)padding, stream, err)) {
                return err.propagate();
            }
        } else {
            // Parse 4*stackLen bytes of options forming the telemetry stack.
            // This parser allows padding options in between stack entries and
            // does not check correct alignment.
            std::span<const std::byte> stack;
            if (!stream.lookahead(stack, 4 * main.stackLen, err)) return err.propagate();
            if (!stream.advanceBytes(4 * main.stackLen, err)) return err.propagate();
            ReadStream rs(stack);
            entries.resize(0);
            while (rs) {
                std::span<const std::byte> nextType;
                if (!rs.lookahead(nextType, 1, err)) return err.propagate();
                if (hdr::OptType(nextType.front()) == hdr::OptType::IdIntEntry) {
                    entries.emplace_back();
                    if (!entries.back().serialize(rs, err)) return err.propagate();
                } else if (hdr::OptType(nextType.front()) == hdr::OptType::PadN) {
                    // discard padding
                    hdr::SciOpt padding;
                    if (!padding.serialize(rs, err)) return err.propagate();
                } else {
                    return err.error("unexpected extension type in ID-INT stack");
                }
            }
        }
        if constexpr (Stream::IsReading) setValid();
        return true;
    }

    auto print(auto out, int indent) const
    {
        out = main.print(out, indent);
        for (const auto& entry : entries)
            out = entry.print(out, indent + 2);
        return out;
    }

    /// \brief Prepare sending an ID-INT request packet.
    /// \param key DRKey HostHost key for MACing the source data.
    std::error_code encodeIntRequest(
        const IntRequest& req, const drkey::Key& key, const Nonce* nonce)
    {
        using namespace scion::hdr;
        using namespace scion::idint;
        using namespace std::chrono;

        main.flags = IdIntOpt::FlagSet{};
        if (req.flags.infrastructure) main.flags |= IdIntOpt::Flags::InfraMode;
        if (req.flags.discard) main.flags |= IdIntOpt::Flags::Discard;
        if (req.flags.encrypt) main.flags |= IdIntOpt::Flags::Encrypt;

        main.agrMode = req.agrMode;
        main.delayHops = req.skipHops;
        main.bitmap = req.bitmap;
        main.agrFuncs = req.agrFuncs;
        main.instr = req.instructions;

        main.sourceTS = req.identifier.timestamp;
        main.sourcePort = (std::uint16_t)req.identifier.port;

        if (std::to_underlying(req.vtype) > std::to_underlying(Verifier::MaxValue)) {
            return ErrorCode::InvalidArgument;
        }
        main.vtype = req.vtype;
        main.verifier = req.verifier;

        if (req.maxStackLen % 4 != 0 || req.maxStackLen > (4*255)) {
            return ErrorCode::InvalidArgument;
        }
        main.stackLen = (std::uint8_t)(req.maxStackLen / 4);
        main.tos = 0;
        main.dataLen = (std::uint8_t)(main.size() - 2);

        // Set up source stack entry
        entries.resize(1);
        auto& top = entries[0];
        req.srcData.encode(top);

        if (!req.flags.encrypt) {
            details::authSourceEntry(top, main, key);
        } else {
            if (!nonce) return ErrorCode::InvalidArgument;
            details::encryptSourceEntry(top, main, key, *nonce);
        }
        return ErrorCode::Ok;
    }

    /// \brief Recovers the original request from received ID-INT headers.
    /// \details The generated request does not contain the source metadata.
    /// Metadata must be decoded using decodeUnverified() or verifyAndDecrypt().
    std::error_code recoverRequest(IntRequest& req)
    {
        using namespace scion::hdr;

        req.flags = {};
        req.flags.infrastructure = main.flags[IdIntOpt::Flags::InfraMode];
        req.flags.discard = main.flags[IdIntOpt::Flags::Discard];
        req.flags.encrypt = main.flags[IdIntOpt::Flags::Encrypt];

        req.agrMode = main.agrMode;
        req.bitmap = main.bitmap;
        req.agrFuncs = main.agrFuncs;
        req.instructions = main.instr;

        req.vtype = main.vtype;
        req.verifier = main.verifier;

        req.srcData = IntMetadata::MakeSource();

        // Try to revover the original value of delay hops from the first hop
        // index in the telemetry stack.
        for (const auto& e : entries) {
            if (!e.flags[IdIntEntry::Flags::Source]) {
                req.skipHops = e.hop;
            }
        }
        return ErrorCode::Ok;
    }

    /// \brief Decode raw telemetry headers to an IntReport without verifying
    /// the MACs. Fails with ErrorCode::NoKey of the headers contain encrypted
    /// data.
    template <typename ReportAlloc>
    std::error_code decodeUnverified(IntReport<ReportAlloc>& report) const
    {
        using namespace scion::hdr;

        report.stackFull = main.flags & IdIntOpt::Flags::SizeExceeded;
        report.identifier.timestamp = main.sourceTS & ~(~0ull << 48);
        report.identifier.port = main.sourcePort;
        report.agrMode = main.agrMode;
        report.agrFuncs = main.agrFuncs;
        report.instructions = main.instr;

        report.data.clear();
        report.data.resize(entries.size());
        auto i = 0;
        for (const auto& e : entries) {
            if (e.flags & IdIntEntry::Flags::Encrypted) {
                return ErrorCode::NoKey;
            }
            report.data[i++].decode(e);
        }
        return ErrorCode::Ok;
    }

    /// \brief Verifies and decodes telemetry data.
    /// \param report Contains the decoded telemetry report upon successful return.
    /// \param now Current time for checking MAC validity.
    /// \param sourceKey MAC validation key for the source stack entry.
    /// \param hopToKey Function that provides the remaining MAC validation keys.
    /// Signature: `Maybe<drkey::Key> hopToKey(std::uint8_t hopIndex, const std::chrono::utc_clock& ts)`
    /// `hopIndex` is the index of the hop field an ID-INT key is required for.
    /// `ts` is the time at which the key must be valid.
    /// \returns Result of the verification. Possible error codes include:
    /// * ErrorCode::Expired If the data is too old relative to `now`.
    /// * ErrorCode::NoKey If a necessary symmetric key is missing.
    /// * ErrorCode::InvalidMAC If the data does not appear authentic.
    template <typename ReportAlloc, typename F>
    VerificationStatus verifyAndDecrypt(
        IntReport<ReportAlloc>& report,
        const std::chrono::utc_clock::time_point& now,
        const drkey::Key& sourceKey,
        F hopToKey)
    {
        using namespace std::chrono;
        using namespace scion::hdr;

        report.stackFull = main.flags & IdIntOpt::Flags::SizeExceeded;
        report.identifier.timestamp = main.sourceTS & ~(~0ull << 48);
        report.identifier.port = main.sourcePort;
        report.agrMode = main.agrMode;
        report.agrFuncs = main.agrFuncs;
        report.instructions = main.instr;

        // Get source timestamp accounting for the possibility of wraparound
        auto nanos = duration_cast<nanoseconds>(now.time_since_epoch()).count();
        auto elapsed = (nanos & 0xffff'ffff'ffff) - main.sourceTS;
        elapsed &= 0xffff'ffff'ffff;
        if (elapsed > MAX_AGE) {
            return VerificationStatus{ErrorCode::Expired, {}};
        }
        nanos = nanos - elapsed;
        auto sourceTime = utc_clock::time_point(utc_clock::duration(nanoseconds{nanos}));

        // Verify metadata
        MAC macChain;
        IsdAsn as;
        Maybe<drkey::Key> key;
        report.data.clear();
        report.data.resize(entries.size());
        int i = 0;
        for (auto& e : entries) {
            if (e.flags & IdIntEntry::Flags::Source) {
                as = IsdAsn();
                key = sourceKey;
            } else {
                std::tie(key, as) = hopToKey(e.hop, sourceTime);
                if (isError(key)) {
                    return VerificationStatus{key.error(), {
                        .isSource = e.flags[hdr::IdIntEntry::Flags::Source],
                        .hopIndex = e.hop,
                        .isdAsn = as}
                    };
                }
            }
            auto mac = details::decryptAndMAC(e, main, macChain, *key);
            if (!std::ranges::equal(mac, e.mac())) {
                return VerificationStatus{ErrorCode::InvalidMAC, {
                    .isSource = e.flags[IdIntEntry::Flags::Source],
                    .hopIndex = e.hop,
                    .isdAsn = as,
                }, mac, e.mac()};
            }
            report.data[i++].decode(e);
        }

        return VerificationStatus{ErrorCode::Ok, {}};
    }
};

} // namespace idint
} // namespace scion
