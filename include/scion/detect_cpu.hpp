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

#include <cstdint>


namespace scion {

struct X86CpuFeatures
{
    std::uint64_t x64 : 1;
    std::uint32_t invariantTsc : 1;
    std::uint64_t sse : 1;
    std::uint64_t sse2 : 1;
    std::uint64_t sse3 : 1;
    std::uint64_t sse4_1 : 1;
    std::uint64_t sse4_2 : 1;
    std::uint64_t avx : 1;
    std::uint64_t avx2 : 1;
    std::uint64_t avx512f : 1;
    std::uint64_t aes : 1;
    std::uint64_t rdrand : 1;
    std::uint64_t rdseed : 1;
    std::uint64_t sha : 1;
};

union CpuFeatures
{
    X86CpuFeatures x86;
};

/// \brief Get supported CPU features. The result is cached.
CpuFeatures getCpuFeatures();

} // namespace scion
