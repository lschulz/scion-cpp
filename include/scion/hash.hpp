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

#pragma once

#include <cstdint>


namespace scion {
namespace details {
// Override the random seed. Must be called before any other function from this
// file is called. Setting seed to -1 causes a random seed to be chosen.
void setRandomSeed32(std::uint32_t seed);
}

/// \brief Hash seed drawn at process start. Remains constant for the duration
/// of the program.
std::uint32_t randomSeed32();

/// \brief Computes a 32-bit hash from an input of up to 2^31 - 1 bytes.
void hash32(const void* input, std::size_t len, std::uint32_t seed, std::uint32_t* output);

/// \brief Computes a 128-bit hash from an input of up to 2^31 - 1 bytes.
void hash128(const void* input, std::size_t len, std::uint32_t seed, std::uint64_t output[2]);

} // namespace scion
