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

#pragma once

#include <cstddef>
#include <span>
#include <system_error>


namespace scion {
namespace crypto {

/// \brief Calculates the AES-CBC MAC of the input.
/// \param key AES-128 key
/// \param input
void CBCMAC(
    std::span<const std::byte, 16> key,
    std::span<const std::byte> input,
    std::span<std::byte, 16> mac
);

/// \brief Encrypts or decrypts up to 64 bytes of data with AES-128 in counter
/// mode.
/// \param key Encryption key
/// \param nonce Unique nonce. Do not reuse the same nonce with the same key.
/// \param data Data is encrypted or decrypted in-place. Maximum length is
/// 64 bytes.
std::error_code AESCTR(
    std::span<const std::byte, 16> key,
    std::span<const std::byte, 12> nonce,
    std::span<std::byte> data
);

} // namespace crypto
} // namespace scion
