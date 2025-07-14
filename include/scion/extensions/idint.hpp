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
#include "scion/extensions/extension.hpp"
#include "scion/hdr/idint.hpp"

#include <memory>
#include <vector>


class HeaderCacheFixture;
class PacketSocketFixture;
class ScmpSocketFixture;
class UdpSocketFixture;
class AsioScmpSocketFixture;
class AsioUdpSocketFixture;


namespace scion {
namespace ext {

template <typename Alloc = std::allocator<std::byte>>
class IdInt : public Extension
{
private:
    using EntryVec = std::vector<hdr::IdIntEntry,
        typename std::allocator_traits<Alloc>::template rebind_alloc<hdr::IdIntEntry>>;

    hdr::IdIntOpt main;
    EntryVec entries;

    // TODO: Add proper interface for ID-INT clients
    friend class ::HeaderCacheFixture;
    friend class ::PacketSocketFixture;
    friend class ::ScmpSocketFixture;
    friend class ::UdpSocketFixture;
    friend class ::AsioScmpSocketFixture;
    friend class ::AsioUdpSocketFixture;

public:
    explicit IdInt(Alloc alloc = Alloc())
        : entries(alloc)
    {}

    Category category() const override { return Category::HopByHop; }
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
};

} // namespace ext
} // namespace scion
