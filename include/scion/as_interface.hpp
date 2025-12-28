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

#include <cstdint>
#include <format>


namespace scion {

/// \brief 64-bit SCION AS interface ID.
/// \note The data plane encoding in SCION paths has only 16 bit.
class AsInterface
{
public:
    AsInterface() = default;
    explicit AsInterface(std::uint64_t id) : ifid(id) {}

    operator std::uint64_t() const { return ifid; }

    std::uint32_t checksum() const
    {
        return (std::uint32_t)((ifid & 0xffff) + ((ifid >> 16) & 0xffff)
            + ((ifid >> 32) & 0xffff) + ((ifid >> 48) & 0xffff));
    }

    std::size_t size() const { return 8; }

    template <typename Stream, typename Error>
    bool serialize(Stream& stream, Error& err)
    {
        if (!stream.serializeUint64(ifid, err)) return err.propagate();
        return true;
    }

private:
    std::uint64_t ifid = 0;
};

} // namespace scion

template <>
struct std::formatter<scion::AsInterface> : std::formatter<std::uint64_t>
{
    auto format(scion::AsInterface iface, auto& ctx) const
    {
        return std::formatter<std::uint64_t>::format((std::uint64_t)iface, ctx);
    }
};
