// Copyright (c) 2024-2026 Lars-Christian Schulz
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

#include "scion/hash.hpp"
#include "scion/detect_cpu.hpp"
#include "scion/details/murmur_hash3.h"

#include <atomic>
#include <cassert>
#include <limits>
#include <random>


namespace scion {
namespace details {

static std::atomic<std::uint32_t> g_initSeed = -1;

struct HashConfig
{
    std::uint32_t seed = 0;
    decltype(MurmurHash3_x86_32)* hash32 = &MurmurHash3_x86_32;
    decltype(MurmurHash3_x64_128)* hash128 = &MurmurHash3_x64_128;
};

void setRandomSeed32(std::uint32_t seed)
{
    g_initSeed.store(seed);
}

HashConfig initHash()
{
    HashConfig cfg;

    cfg.seed = g_initSeed.load();
    if (cfg.seed == (std::uint32_t)-1)
        cfg.seed = std::random_device{}();

    auto cpu = getCpuFeatures();
    if (cpu.arch == CpuArch::Unknown)
        cfg.hash128 = &MurmurHash3_x86_128;
    else
        cfg.hash128 = &MurmurHash3_x64_128;

    return cfg;
}

} // namespace details

static const details::HashConfig& getHashConfig()
{
    static details::HashConfig cfg  = details::initHash();
    return cfg;
}

std::uint32_t randomSeed32()
{
    return getHashConfig().seed;
}

void hash32(const void* input, std::size_t len, std::uint32_t seed, std::uint32_t* output)
{
    if (len > std::numeric_limits<int>::max()) {
        assert("Hash input too large");
        std::abort();
    }
    getHashConfig().hash32(input, (int)len, seed, output);
}

void hash128(const void* input, std::size_t len, std::uint32_t seed, std::uint64_t output[2])
{
    if (len > std::numeric_limits<int>::max()) {
        assert("Hash input too large");
        std::abort();
    }
    getHashConfig().hash128(input, (int)len, seed, output);
}

} // namespace scion
