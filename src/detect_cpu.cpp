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

#include "scion/detect_cpu.hpp"

#if defined(__MSC_VER) || defined(__INTEL_COMPILER)
#include <array>
#include <intrin.h>
#elif defined(__GNUC__)
#include <cpuid.h>
#endif


namespace scion {

#if defined(__MSC_VER) || defined(__INTEL_COMPILER)

static CpuFeatures detectCpuFeatures()
{
#if _M_X64 || __x86_64__
    CpuFeatures feat = {
        .arch = CpuArch::x86_64,
        .x86 = X86CpuFeatures{},
    };

    std::array<int, 4> cpuid = {};
    __cpuid(cpuid.data(), 0x80000000);
    int maxExt = cpuid[0] & ~0x80000000;
    if (maxExt >= 7) {
        __cpuid(cpuid.data(), 0x80000007);
        feat.x86.invariantTsc = !!((cpuid[3] >> 8) & 1);
    }

    __cpuid(cpuid.data(), 1);
    feat.x86.sse     = !!((cpuid[3] >> 25) & 1);
    feat.x86.sse2    = !!((cpuid[3] >> 26) & 1);
    feat.x86.sse3    = !!((cpuid[2] >> 0) & 1);
    feat.x86.sse4_1  = !!((cpuid[2] >> 19) & 1);
    feat.x86.sse4_2  = !!((cpuid[2] >> 20) & 1);
    feat.x86.avx     = !!((cpuid[2] >> 28) & 1);
    feat.x86.avx2    = !!((cpuid[1] >> 5) & 1);
    feat.x86.avx512f = !!((cpuid[1] >> 16) & 1);
    feat.x86.aes     = !!((cpuid[2] >> 25) & 1);
    feat.x86.rdrand  = !!((cpuid[2] >> 30) & 1);
    feat.x86.rdseed  = !!((cpuid[1] >> 18) & 1);
    feat.x86.sha     = !!((cpuid[1] >> 29) & 1);
#else
    CpuFeatures feat = {
        .arch = CpuArch::Unknown,
        .unknown = UnknownCpuFeatures{},
    };
#endif
    return feat;
}

#elif defined(__GNUC__)

static CpuFeatures detectCpuFeatures()
{
#if __X86__ || __x86_64__
    CpuFeatures feat = {
        .arch = CpuArch::x86_64,
        .x86 = X86CpuFeatures{},
    };

    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(0x80000007, &eax, &ebx, &ecx, &edx)) {
        feat.x86.invariantTsc = !!((edx >> 8) & 1);
    }
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        feat.x86.sse     = !!((edx >> 25) & 1);
        feat.x86.sse2    = !!((edx >> 26) & 1);
        feat.x86.sse3    = !!((ecx >> 0) & 1);
        feat.x86.sse4_1  = !!((ecx >> 19) & 1);
        feat.x86.sse4_2  = !!((ecx >> 20) & 1);
        feat.x86.avx     = !!((ecx >> 28) & 1);
        feat.x86.avx2    = !!((ebx >> 5) & 1);
        feat.x86.avx512f = !!((ebx >> 16) & 1);
        feat.x86.aes     = !!((ecx >> 25) & 1);
        feat.x86.rdrand  = !!((ecx >> 30) & 1);
        feat.x86.rdseed  = !!((ebx >> 18) & 1);
        feat.x86.sha     = !!((ebx >> 29) & 1);
    }
#else
    CpuFeatures feat = {
        .arch = CpuArch::Unknown,
        .unknown = UnknownCpuFeatures{},
    };
#endif
    return feat;
}

#endif

CpuFeatures getCpuFeatures()
{
    static const auto cpuFeatures = detectCpuFeatures();
    return cpuFeatures;
}

} // namespace scion
