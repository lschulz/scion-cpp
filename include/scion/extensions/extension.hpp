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
#include "scion/hdr/scion.hpp"

#include <cassert>
#include <concepts>
#include <cstdint>


namespace scion {
namespace ext {

enum class Category
{
    HopByHop,
    EndToEnd,
};

class Extension
{
public:
    virtual ~Extension() {};

    /// \brief Get the validity flag. An extension must be set valid in order
    /// for it to be emitted in the packet headers. The valid flag is also set
    /// when the extension is parsed from a received packet, where it indicates
    /// whether the extension was present or not.
    bool isValid() const { return validFlag; }

    /// \brief Mark the extension as invalid, i.e., ready to be included in
    /// emitted packets.
    void setValid() { validFlag = true; }

    /// \brief Mark the extension as invalid, i.e., not to be included in
    /// emitted packets.
    void setInvalid() { validFlag = false; }

    /// \brief Return whether this is a hop-by-hop or end-to-end extension.
    virtual Category category() const = 0;

    /// \brief Get the option type of this extension. If the extension uses
    /// multiple options the type of the first option.
    virtual hdr::OptType type() const = 0;

    /// \brief Returns the extension size on the wire in bytes.
    /// \param pos Byte offset from the beginning of the extensions headers
    /// for calculating necessary alignment padding.
    virtual std::size_t size(std::size_t pos) const = 0;

    virtual bool parse(ReadStream& rs, SCION_STREAM_ERROR& err) = 0;

    virtual bool write(WriteStream& ws, std::size_t pos, SCION_STREAM_ERROR& err) const = 0;

protected:
    /// \brief Calculate the amount of padding necessary to add to n to align
    /// with align*n+offset. `align` must be a power of two.
    static std::size_t padding(std::size_t n, std::size_t align, std::size_t offset)
    {
        assert((align & (align - 1)) == 0 && "align must be a power of two");
        return -(n + offset) & (align - 1);
    }

    /// \brief Write padding options to fill `n` bytes of space.
    template <typename Stream, typename Error>
    static bool insertPadding(std::size_t n, Stream& stream, Error& err)
    {
        static_assert(Stream::IsWriting);
        if (n == 0) return true;
        hdr::SciOpt padding;
        if (n == 1) {
            padding.type = hdr::OptType::Pad1;
            padding.dataLen = 1;
        } else {
            padding.type = hdr::OptType::PadN;
            padding.dataLen = (std::uint8_t)(n - 2);
        }
        return padding.serialize(stream, err);
    }

private:
    bool validFlag = true;
};

template <typename T>
concept extension_range = std::ranges::range<T>
    && std::same_as<std::ranges::range_value_t<T>, Extension*>;

constexpr auto NoExtensions = std::views::empty<ext::Extension*>;

/// \brief Compute the size of the given extensions on the wire including all
/// necessary padding.
/// \return Size of the HopByHop and EndToEnd extensions headers in bytes. A
/// size of 0 indicates no header is required.
template <extension_range ExtRange>
std::pair<std::size_t, std::size_t> computeExtSize(ExtRange&& extensions)
{
    using namespace std::ranges::views;
    std::size_t hbh = 0, e2e = 0;
    // Iterate over HBH extensions first, to ensure correct order. Order might
    // affect the required padding.
    auto isHbH = [](auto ext) {
        return ext->isValid() && ext->category() == ext::Category::HopByHop;
    };
    auto isE2E = [](auto ext) {
        return ext->isValid() && ext->category() == ext::Category::EndToEnd;
    };
    if (std::ranges::any_of(extensions, isHbH)) {
        hbh += hdr::HopByHopOpts::minSize;
        for (auto ext : extensions | filter(isHbH)) {
            hbh += ext->size(hbh);
        }
    }
    assert(hbh % 4 == 0);
    if (std::ranges::any_of(extensions, isE2E)) {
        e2e += hdr::EndToEndOpts::minSize;
        for (auto ext : extensions | filter(isE2E)) {
            e2e += ext->size(e2e);
        }
    }
    assert(e2e % 4 == 0);
    return std::make_pair(hbh, e2e);
}

/// \brief Parse extensions from TLV-encoded SCION options. Options not
/// recognized by any of the given extensions are silently ignored.
/// \param rs
///     Stream beginning just after the maIn option header, i.e., with the first
///     TLV-encoded option.
/// \param extensions
///     List of extension to parse when encountered.
template <ext::extension_range ExtRange, typename Error>
bool parseExtensions(ReadStream& rs, ExtRange&& extensions, Error& err)
{
    using namespace hdr;

    // mark all extensions as not present
    for (auto ext : extensions) ext->setInvalid();

    std::span<const std::byte> nextType;
    while (rs) {
        if (!rs.lookahead(nextType, 1, err)) return err.propagate();
        auto optType = OptType(nextType.front());
        bool extParsed = false;
        for (auto ext : extensions) {
            if (optType == ext->type()) {
                if (!ext->parse(rs, err)) return err.propagate();
                extParsed = true;
                break;
            }
        }
        if (!extParsed) {
            // Extract Pad1, PadN, and unknown options
            SciOpt opt;
            if (!opt.serialize(rs, err)) err.propagate();
        }
    }
    return true;
}

} // namespace ext
} // namespace scion
