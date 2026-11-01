// Copyright (c) 2022-2026 Lars-Christian Schulz
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

#include "scion/error_codes.hpp"

#include <emmintrin.h>
#include <immintrin.h>
#if defined(_MSC_VER) && !defined(__clang__)
#define __m128i_u __m128i
#endif

#include <cstdint>
#include <cstring>
#include <span>

using std::byte;
using std::uint8_t;
using std::uint32_t;
using std::size_t;

namespace scion {
namespace crypto {

////////////////////
// AVX2 and AESNI //
////////////////////

#define AESCTR_MAX_BYTES 64
#define KEY_SCHED_SIZE 10

#define AES_KEY_EXPANSION_ROUND(key, temp, rcon) \
    temp = _mm_aeskeygenassist_si128(key, rcon); \
    temp = _mm_shuffle_epi32(temp, 0xff); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, _mm_slli_si128(key, 0x04)); \
    key = _mm_xor_si128(key, temp)

static void keyExpansion_AESNI(__m128i key, __m128i keySchedule[KEY_SCHED_SIZE])
{
    __m128i temp;
    __m128i *dest = (__m128i*)keySchedule;
    AES_KEY_EXPANSION_ROUND(key, temp, 0x01);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x02);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x04);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x08);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x10);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x20);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x40);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x80);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x1b);
    _mm_store_si128(dest++, key);
    AES_KEY_EXPANSION_ROUND(key, temp, 0x36);
    _mm_store_si128(dest++, key);
}

static __m128i encryptBlock_AESNI(__m128i input, __m128i key, const __m128i keySchedule[KEY_SCHED_SIZE])
{
    // Initialization (round 0)
    __m128i state = input;
    state = _mm_xor_si128(state, key);

    // First 9 rounds
    for (size_t i = 0; i < 9; ++i)
        state = _mm_aesenc_si128(state, _mm_load_si128(keySchedule + i));

    // Last round
    state = _mm_aesenclast_si128(state, _mm_load_si128(&keySchedule[9]));

    return state;
}

// AES using AES-NI instructions.
std::error_code aesCtrModeAESNI(
    std::span<const byte, 16> key,
    std::span<const byte, 12> nonce,
    std::span<byte> data)
{
    alignas(32) uint8_t buffer[AESCTR_MAX_BYTES] = {};

    auto pData = reinterpret_cast<__m128i_u*>(data.data());
    const auto len = data.size();

    if (len > AESCTR_MAX_BYTES) return ErrorCode::InvalidArgument;
    std::memcpy(buffer, pData, len);

    __m128i m128key = _mm_loadu_si128(reinterpret_cast<const __m128i_u*>(key.data()));
    __m128i temp;

    // Compute keystream for 4 blocks in parallel
    // Initialization
    const __m128i inc = _mm_set_epi64x(1ll << 56, 0);
    alignas(16) uint8_t counter[16] = {};
    std::memcpy(counter, nonce.data(), nonce.size());
    __m128i state1 = _mm_load_si128(reinterpret_cast<const __m128i*>(counter));
    __m128i state2 = _mm_add_epi32(state1, inc);
    __m128i state3 = _mm_add_epi32(state2, inc);
    __m128i state4 = _mm_add_epi32(state3, inc);

    state1 = _mm_xor_si128(state1, m128key);
    state2 = _mm_xor_si128(state2, m128key);
    state3 = _mm_xor_si128(state3, m128key);
    state4 = _mm_xor_si128(state4, m128key);

    // First 9 rounds
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x01);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x02);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x04);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x08);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x10);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x20);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x40);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x80);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x1b);
    state1 = _mm_aesenc_si128(state1, m128key);
    state2 = _mm_aesenc_si128(state2, m128key);
    state3 = _mm_aesenc_si128(state3, m128key);
    state4 = _mm_aesenc_si128(state4, m128key);

    // Last round
    AES_KEY_EXPANSION_ROUND(m128key, temp, 0x36);
    state1 = _mm_aesenclast_si128(state1, m128key);
    state2 = _mm_aesenclast_si128(state2, m128key);
    state3 = _mm_aesenclast_si128(state3, m128key);
    state4 = _mm_aesenclast_si128(state4, m128key);

    // XOR keystream with input data
    state1 = _mm_xor_si128(state1, _mm_load_si128((const __m128i*)(buffer + 0)));
    state2 = _mm_xor_si128(state2, _mm_load_si128((const __m128i*)(buffer + 16)));
    state3 = _mm_xor_si128(state3, _mm_load_si128((const __m128i*)(buffer + 32)));
    state4 = _mm_xor_si128(state4, _mm_load_si128((const __m128i*)(buffer + 48)));

    // Store result
    _mm_store_si128((__m128i*)(buffer + 0), state1);
    _mm_store_si128((__m128i*)(buffer + 16), state2);
    _mm_store_si128((__m128i*)(buffer + 32), state3);
    _mm_store_si128((__m128i*)(buffer + 48), state4);
    std::memcpy(pData, buffer, len);

    return ErrorCode::Ok;
}

// AES-CMAC using AES-NI instructions.
void aesCbcMacAESNI(
    std::span<const byte, 16> key,
    std::span<const byte> input,
    std::span<byte, 16> mac)
{
    __m128i keySchedule[KEY_SCHED_SIZE];
    __m128i m128key = _mm_loadu_si128(reinterpret_cast<const __m128i_u*>(key.data()));
    keyExpansion_AESNI(m128key, keySchedule);

    auto pData = reinterpret_cast<const __m128i_u*>(input.data());
    const auto len = input.size();
    size_t blocks = len / 16;
    __m128i reg = _mm_setzero_si128();
    for (size_t i = 0; i < blocks; ++i) {
        reg = _mm_xor_si128(reg, _mm_loadu_si128(pData + i));
        reg = encryptBlock_AESNI(reg, m128key, keySchedule);
    }

    size_t rem = len % 16;
    if (rem > 0) {
        alignas(16) uint8_t buffer[16] = {};
        std::memcpy(buffer, reinterpret_cast<const byte*>(pData) + len - rem, rem);
        reg = _mm_xor_si128(reg, _mm_load_si128(reinterpret_cast<const __m128i*>(buffer)));
        reg = encryptBlock_AESNI(reg, m128key, keySchedule);
    }

    _mm_storeu_si128(reinterpret_cast<__m128i_u*>(mac.data()), reg);
}

} // namespace crypto
} // namespace scion
