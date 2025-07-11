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

#include <cstdint>
#include <format>


namespace scion {

/// \brief 128-bit hash identifying a path.
class PathDigest
{
public:
    constexpr PathDigest() = default;
    constexpr PathDigest(std::uint64_t lo, std::uint64_t hi)
        : digest{lo, hi}
    {}

    auto operator<=>(const PathDigest&) const = default;

    const std::uint64_t* value() const { return digest; }

    friend struct std::formatter<scion::PathDigest>;
    friend std::ostream& operator<<(std::ostream& stream, const PathDigest& pd);

private:
    std::uint64_t digest[2] = {};
    friend std::hash<PathDigest>;
};

} // namespace scion

template <>
struct std::formatter<scion::PathDigest>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::PathDigest& pd, auto& ctx) const
    {
        return std::format_to(ctx.out(), "{:016x}:{:016x}", pd.digest[0], pd.digest[1]);
    }
};

template <>
struct std::hash<scion::PathDigest>
{
    std::size_t operator()(const scion::PathDigest& pd) const noexcept
    {
        if constexpr (sizeof(std::size_t) == 4) {
            return (std::uint32_t)pd.digest[0] ^ (std::uint32_t)(pd.digest[0] >> 32)
                ^ (std::uint32_t)pd.digest[1] ^ (std::uint32_t)(pd.digest[1] >> 32);
        } else {
            return pd.digest[0] ^ pd.digest[1];
        }
    }
};
