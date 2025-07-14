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
#include "scion/error_codes.hpp"
#include "scion/murmur_hash3.h"

#include <cassert>
#include <cstdint>
#include <format>
#include <numeric>
#include <ranges>
#include <span>
#include <string_view>
#include <system_error>
#include <variant>


namespace scion {

/// \brief SCION 16-bit ISD number.
class Isd
{
private:
    std::uint_fast16_t m_isd = 0;

public:
    constexpr Isd() = default;

    explicit constexpr Isd(std::uint_fast16_t isd) : m_isd(isd) { assert(isd <= MAX_VALUE); }

    constexpr operator std::uint_fast16_t() const { return m_isd; }

    /// \brief Number of bits in ISD number.
    static constexpr std::size_t BITS = 16;

    /// \brief Maximum possible ISD number.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;

    /// \brief Check whether the ISD is unspecified (equal to zero).
    bool isUnspecified() const { return m_isd == 0; }

    auto operator<=>(const Isd&) const = default;

    /// \brief Parse a decimal ISD number.
    static Maybe<Isd> Parse(std::string_view text);

    friend std::ostream& operator<<(std::ostream &stream, Isd isd);
    friend struct std::formatter<scion::Isd>;
};

/// \brief SCION 48-bit AS number.
class Asn
{
private:
    std::uint64_t m_asn = 0;

public:
    constexpr Asn() = default;

    explicit constexpr Asn(std::uint64_t asn) : m_asn(asn) { assert(asn <= MAX_VALUE); }

    constexpr operator std::uint64_t() const { return m_asn; }

    /// \brief Number of bits in AS number.
    static constexpr std::size_t BITS = 48;

    /// \brief Maximum possible AS number.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;

    /// \brief Largest AS number that is considered compatible with BGP.
    static constexpr std::size_t MAX_BGP_VALUE = (1ull << 32) - 1;

    /// \brief Check whether the ASN is unspecified (equal to zero).
    bool isUnspecified() const { return m_asn == 0; }

    auto operator<=>(const Asn&) const = default;

    /// \brief Parse a BGP or SCION AS number.
    ///
    /// Valid formats are:
    /// * A decimal non-negative integer if <= MAX_BGP_VALUE.
    /// * Three groups of 1 to 4 hexadecimal digits (upper or lower case)
    ///   separated by colons.
    static Maybe<Asn> Parse(std::string_view text);

    friend std::ostream& operator<<(std::ostream &stream, Asn asn);
    friend struct std::formatter<scion::Asn>;
};

/// \brief Combined 64-bit SCION ISD-ASN.
class IsdAsn
{
private:
    std::uint64_t m_ia = 0;

public:
    constexpr IsdAsn() = default;

    explicit constexpr IsdAsn(std::uint64_t ia) : m_ia(ia) {}

    constexpr IsdAsn(Isd isd, Asn asn) : m_ia(((std::uint64_t)isd << Asn::BITS) | asn) {}

    /// \brief Number of bits in ISD-ASN pair.
    static constexpr std::size_t BITS = 48;

    /// \brief Maximum possible ISD-ASN value.
    static constexpr std::size_t MAX_VALUE = (1ull << BITS) - 1;

    constexpr operator std::uint64_t() const { return m_ia; }

    Isd isd() const { return Isd(m_ia >> Asn::BITS); }
    Asn asn() const { return Asn(m_ia & ((1ull << Asn::BITS) - 1)); }

    /// \brief Check whether ISD or ASN are unspecified (equal to zero).
    bool isUnspecified() const
    {
        return isd().isUnspecified() || asn().isUnspecified();
    }

    auto operator<=>(const IsdAsn&) const = default;

    /// \brief Returns true if this address is equal to `other` or if this
    /// address is an unspecified.
    bool matches(IsdAsn other) const
    {
        return isUnspecified() || *this == other;
    }

    /// \brief Parse a string og the format "<ISD>-<ASN>".
    static Maybe<IsdAsn> Parse(std::string_view text);

    std::uint32_t checksum() const
    {
        return (std::uint32_t)(m_ia & 0xffff'fffful) + (std::uint32_t)(m_ia >> 32);
    }

    std::size_t size() const { return 8; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint64(m_ia, err)) return err.propagate();
        return true;
    }

    friend std::ostream& operator<<(std::ostream &stream, IsdAsn ia);
    friend struct std::formatter<scion::IsdAsn>;
};

} // namespace scion

template <>
struct std::formatter<scion::Isd> : std::formatter<std::uint_fast16_t>
{
    auto format(const scion::Isd& isd, auto& ctx) const
    {
        return std::formatter<std::uint_fast16_t>::format(isd.m_isd, ctx);
    }
};

template <>
struct std::formatter<scion::Asn>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::Asn& asn, auto& ctx) const
    {
        constexpr auto GROUP_BITS = 16ull;
        constexpr auto GROUP_MAX_VALUE = (1ull << GROUP_BITS) - 1;
        if (asn.m_asn <= scion::Asn::MAX_BGP_VALUE) {
            return std::format_to(ctx.out(), "{}", asn.m_asn);
        } else {
            return std::format_to(ctx.out(), "{:x}:{:x}:{:x}",
                (asn.m_asn >> 2 * GROUP_BITS) & GROUP_MAX_VALUE,
                (asn.m_asn >> GROUP_BITS) & GROUP_MAX_VALUE,
                (asn.m_asn) & GROUP_MAX_VALUE);
        }
    }
};

template <>
struct std::formatter<scion::IsdAsn>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::IsdAsn& ia, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{}-{}", ia.isd(), ia.asn());
    }
};

template <>
struct std::hash<scion::Isd>
{
    std::size_t operator()(const scion::Isd& isd) const noexcept
    {
        std::uint64_t value = isd;
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&value, sizeof(value), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&value, sizeof(value), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

template <>
struct std::hash<scion::Asn>
{
    std::size_t operator()(const scion::Asn& asn) const noexcept
    {
        std::uint64_t value = asn;
        auto seed = scion::details::randomSeed();
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint32_t h = 0;
            scion::details::MurmurHash3_x86_32(&value, sizeof(value), seed, &h);
            return h;
        } else {
            std::uint64_t h[2] = {};
            scion::details::MurmurHash3_x64_128(&value, sizeof(value), seed, &h);
            return h[0] ^ h[1];
        }
    }
};

template <>
struct std::hash<scion::IsdAsn>
{
    std::size_t operator()(const scion::IsdAsn& isdAsn) const noexcept
    {
        if constexpr (sizeof(std::size_t) == 4) {
            std::uint64_t ia = isdAsn;
            std::uint32_t h = 0;
            auto seed = scion::details::randomSeed();
            scion::details::MurmurHash3_x86_32(&ia, sizeof(ia), seed, &h);
            return h;
        } else {
            // identify hash
            return (std::uint64_t)isdAsn;
        }
    }
};
