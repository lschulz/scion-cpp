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

#include "scion/crypto/aes.hpp"

#include "gtest/gtest.h"
#include "utilities.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <ranges>

using std::byte;
using std::uint8_t;
using std::size_t;


namespace scion {
namespace crypto {
std::error_code aesCtrModeTables(
    std::span<const byte, 16> key,
    std::span<const byte, 12> nonce,
    std::span<byte> data);

void aesCbcMacTables(
    std::span<const std::byte, 16> key,
    std::span<const std::byte> input,
    std::span<std::byte, 16> mac);

std::error_code aesCtrModeAESNI(
    std::span<const byte, 16> key,
    std::span<const byte, 12> nonce,
    std::span<byte> data);

void aesCbcMacAESNI(
    std::span<const std::byte, 16> key,
    std::span<const std::byte> input,
    std::span<std::byte, 16> mac);

std::error_code aesCtrModeBotan(
    std::span<const byte, 16> key,
    std::span<const byte, 12> nonce,
    std::span<byte> data);

void aesCbcMacBotan(
    std::span<const std::byte, 16> key,
    std::span<const std::byte> input,
    std::span<std::byte, 16> mac);
} // namespace crypto
} // namespace scion

using namespace scion::crypto;

struct AesTables {
    static constexpr decltype(aesCtrModeTables)* aesCtrMode = &aesCtrModeTables;
    static constexpr decltype(aesCbcMacTables)* aesCbcMac = &aesCbcMacTables;
};

struct AesNI {
    static constexpr decltype(aesCtrModeAESNI)* aesCtrMode = &aesCtrModeAESNI;
    static constexpr decltype(aesCbcMacAESNI)* aesCbcMac = &aesCbcMacAESNI;
};

struct AesBotan {
    static constexpr decltype(aesCtrModeBotan)* aesCtrMode = &aesCtrModeBotan;
    static constexpr decltype(aesCbcMacBotan)* aesCbcMac = &aesCbcMacBotan;
};

template <typename T>
class AesImplTest : public testing::Test
{};

using ImplTypes = testing::Types<AesTables, AesNI, AesBotan>;
TYPED_TEST_SUITE(AesImplTest, ImplTypes);

TYPED_TEST(AesImplTest, CbcMac)
{
    using namespace scion;
    using namespace scion::crypto;
    static const std::array<byte, 16> key = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b, 9_b, 10_b, 11_b, 12_b, 13_b, 14_b, 15_b, 16_b
    };
    static const std::array<byte, 16> expected = {
        0x7a_b, 0xd8_b, 0x71_b, 0xcb_b, 0x26_b, 0x2e_b, 0x72_b, 0x3e_b,
        0x31_b, 0x40_b, 0xaa_b, 0x4e_b, 0x03_b, 0x59_b, 0x65_b, 0xe1_b,
    };

    std::array<byte, 64> input;
    for (size_t i = 0; i < input.size(); ++i) {
        input[i] = byte{(uint8_t)(2*i-1)};
    }

    std::array<byte, 16> mac;
    TypeParam::aesCbcMac(key, input, mac);
    ASSERT_TRUE(std::ranges::equal(mac, expected)) << printBufferDiff(mac, expected);
}

TYPED_TEST(AesImplTest, Encryption)
{
    using namespace scion;
    using namespace scion::crypto;
    static const std::array<byte, 16> key = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b, 9_b, 10_b, 11_b, 12_b, 13_b, 14_b, 15_b, 16_b
    };
    static const std::array<byte, 12> nonce = {
        12_b, 11_b, 10_b, 9_b, 8_b, 7_b, 6_b, 5_b, 4_b, 3_b, 2_b, 1_b
    };
    static const std::array<byte, 64> expected = {
        0xf8_b, 0xc1_b, 0x36_b, 0x3c_b, 0x97_b, 0x18_b, 0x8b_b, 0xf8_b,
        0xef_b, 0xa7_b, 0x3a_b, 0xae_b, 0x26_b, 0x96_b, 0xb9_b, 0x36_b,
        0x8b_b, 0x8f_b, 0xf0_b, 0x9a_b, 0x00_b, 0x83_b, 0x00_b, 0x3d_b,
        0xcd_b, 0x70_b, 0xf4_b, 0x30_b, 0xa9_b, 0xd7_b, 0x1d_b, 0x8a_b,
        0x7a_b, 0x13_b, 0x41_b, 0x46_b, 0x25_b, 0xf9_b, 0x76_b, 0xee_b,
        0xd9_b, 0x8f_b, 0xc9_b, 0xcf_b, 0x97_b, 0x28_b, 0x28_b, 0xca_b,
        0x7a_b, 0xea_b, 0x7f_b, 0xb0_b, 0x00_b, 0x39_b, 0x24_b, 0x2b_b,
        0xd3_b, 0x86_b, 0x43_b, 0x44_b, 0x93_b, 0xc0_b, 0x99_b, 0x80_b,
    };

    std::array<byte, 64> data;
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = byte{(uint8_t)(2*i-1)};
    }

    ASSERT_FALSE(TypeParam::aesCtrMode(key, nonce, data));
    EXPECT_TRUE(std::ranges::equal(data, expected)) << printBufferDiff(data, expected);
}

TYPED_TEST(AesImplTest, TooManyBlocks)
{
    using namespace scion;
    using namespace scion::crypto;
    static const std::array<byte, 16> key = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b, 9_b, 10_b, 11_b, 12_b, 13_b, 14_b, 15_b, 16_b
    };
    static const std::array<byte, 12> nonce = {
        12_b, 11_b, 10_b, 9_b, 8_b, 7_b, 6_b, 5_b, 4_b, 3_b, 2_b, 1_b
    };

    std::vector<byte> data(80);
    auto err = TypeParam::aesCtrMode(key, nonce, data);
    EXPECT_EQ(err, ErrorCondition::InvalidArgument);
}

// Combare AES-CBC MAC implementations.
TEST(Aes, CompareCBCMAC)
{
    using namespace scion;
    using namespace scion::crypto;

    static const std::array<byte, 16> key = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b, 9_b, 10_b, 11_b, 12_b, 13_b, 14_b, 15_b, 16_b
    };

    std::array<byte, 64> data;
    std::minstd_rand rng(1);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = byte{(uint8_t)rng()};
    }

    std::array<byte, 16> botan, tables, aesni;
    for (size_t size = 0; size <= data.size(); ++size) {
        auto input = std::span<byte>(data.begin(), size);
        aesCbcMacBotan(key, input, botan);
        aesCbcMacTables(key, input, tables);
        aesCbcMacAESNI(key, input, aesni);
        ASSERT_TRUE(std::ranges::equal(botan, tables)) << printBufferDiff(botan, tables);
        ASSERT_TRUE(std::ranges::equal(botan, aesni)) << printBufferDiff(botan, aesni);
    }
}

// Compare AES-CTR implementations.
TEST(Aes, CompareAESCTR)
{
    using namespace scion;
    using namespace scion::crypto;

    static const std::array<byte, 16> key = {
        1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b, 9_b, 10_b, 11_b, 12_b, 13_b, 14_b, 15_b, 16_b
    };
    static const std::array<byte, 12> nonce = {
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b,
        0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b
    };

    std::array<byte, 64> data;
    std::minstd_rand rng(1);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = byte{(uint8_t)rng()};
    }

    std::array<byte, data.size()> botanIn, tablesIn, aesniIn;
    for (size_t size = 0; size <= data.size(); ++size) {
        std::copy_n(data.begin(), size, botanIn.begin());
        std::copy_n(data.begin(), size, tablesIn.begin());
        std::copy_n(data.begin(), size, aesniIn.begin());

        auto botan = std::span<byte>(botanIn.begin(), size);
        auto tables = std::span<byte>(tablesIn.begin(), size);
        auto aesni = std::span<byte>(aesniIn.begin(), size);

        ASSERT_FALSE(aesCtrModeBotan(key, nonce, botan));
        ASSERT_FALSE(aesCtrModeTables(key, nonce, tables));
        ASSERT_FALSE(aesCtrModeAESNI(key, nonce, aesni));
        ASSERT_TRUE(std::ranges::equal(botan, tables)) << printBufferDiff(botan, tables);
        ASSERT_TRUE(std::ranges::equal(botan, aesni)) << printBufferDiff(botan, aesni);
    }
}
