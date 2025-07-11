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

#include "stdint.h"

extern inline uint64_t scion_htonll(uint64_t x)
{
#if __STDC_ENDIAN_NATIVE__ == __STDC_ENDIAN_LITTLE__
    return ((x & 0x00000000000000ffull) << 56)
        | ((x & 0x000000000000ff00ull) << 40)
        | ((x & 0x0000000000ff0000ull) << 24)
        | ((x & 0x00000000ff000000ull) << 8)
        | ((x & 0x000000ff00000000ull) >> 8)
        | ((x & 0x0000ff0000000000ull) >> 24)
        | ((x & 0x00ff000000000000ull) >> 40)
        | ((x & 0xff00000000000000ull) >> 56);
#else
    return x;
#endif
}
