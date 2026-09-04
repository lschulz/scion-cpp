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

#include "scion/bit_stream.hpp"

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "utilities.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iostream>

using std::uint8_t;
using std::uint32_t;
using std::uint64_t;
using std::size_t;


template <typename T>
class TypedStreamTest : public testing::Test
{};

using StreamTypes = testing::Types<scion::ReadStream, scion::WriteStream>;
TYPED_TEST_SUITE(TypedStreamTest, StreamTypes);

TYPED_TEST(TypedStreamTest, Seek)
{
    using namespace scion;
    std::array<std::byte, 8> data = {};

    TypeParam stream(data);
    ASSERT_EQ(stream.remaining(), 8);

    ASSERT_TRUE(stream.seek(2, 7));
    ASSERT_EQ(stream.remaining(), 5);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)2, (size_t)7));

    ASSERT_FALSE(stream.seek(0, 9));
    ASSERT_EQ(stream.remaining(), 5);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)2, (size_t)7));

    ASSERT_FALSE(stream.seek(8, 1));
    ASSERT_EQ(stream.remaining(), 5);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)2, (size_t)7));

    ASSERT_FALSE(stream.seek(9, 0));
    ASSERT_EQ(stream.remaining(), 5);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)2, (size_t)7));

    ASSERT_TRUE(stream.seek(TypeParam::npos, 0));
    ASSERT_EQ(stream.remaining(), 0);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)8, (size_t)0));

    ASSERT_FALSE(stream.seek(TypeParam::npos, 4));
    ASSERT_EQ(stream.remaining(), 0);
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)8, (size_t)0));
}

TEST(Stream, Lookahead)
{
    using namespace scion;

    std::array<std::byte, 16> data;
    for (std::size_t i = 0; i < data.size(); ++i) data[i] = std::byte{uint8_t(i)};
    ReadStream read(data);

    std::span<const std::byte> lookahead;
    ASSERT_TRUE(read.advanceBytes(4, NullStreamError));
    ASSERT_TRUE(read.lookahead(lookahead, 4, NullStreamError));
    EXPECT_THAT(lookahead, testing::ElementsAre(0x04_b, 0x05_b, 0x06_b, 0x07_b));

    // error: out of bounds
    EXPECT_TRUE(read.lookahead(lookahead, 12, NullStreamError));
    EXPECT_FALSE(read.lookahead(lookahead, 13, NullStreamError));

    // error: not aligned
    ASSERT_TRUE(read.advanceBits(1, NullStreamError));
    EXPECT_FALSE(read.lookahead(lookahead, 4, NullStreamError));
}

TEST(Stream, Lookback)
{
    using namespace scion;

    std::array<std::byte, 16> data;
    WriteStream write(data);
    ASSERT_TRUE(write.serializeUint64(0x00010203'04050607ull, NullStreamError));

    std::span<std::byte> lookback;
    ASSERT_TRUE(write.lookback(lookback, 4, NullStreamError));
    EXPECT_THAT(lookback, testing::ElementsAre(0x04_b, 0x05_b, 0x06_b, 0x07_b));

    // error: out of bounds
    EXPECT_TRUE(write.lookback(lookback, 8, NullStreamError));
    EXPECT_FALSE(write.lookback(lookback, 9, NullStreamError));

    // error: not aligned
    ASSERT_TRUE(write.advanceBits(1, NullStreamError));
    EXPECT_FALSE(write.lookback(lookback, 4, NullStreamError));
}

TEST(Stream, UpdateChecksum)
{
    using namespace scion;

    std::array<std::byte, 8> data;
    WriteStream write(data);
    ASSERT_TRUE(write.serializeUint16(0xffff, NullStreamError));
    ASSERT_TRUE(write.serializeUint16(0xffff, NullStreamError));
    ASSERT_TRUE(write.serializeUint16(0xffff, NullStreamError));
    ASSERT_TRUE(write.serializeUint16(0xffff, NullStreamError));

    auto pos = write.getPos();
    ASSERT_TRUE(write.updateChksum(0xaaaa, 4, NullStreamError));
    EXPECT_EQ(write.getPos(), pos);

    ReadStream read(data);
    uint64_t value = 0;
    ASSERT_TRUE(read.serializeUint64(value, NullStreamError));
    EXPECT_EQ(value, 0xffff'aaaa'ffff'ffffull);

    // error: out of bounds
    EXPECT_TRUE(write.updateChksum(0xaaaa, 6, NullStreamError));
    EXPECT_FALSE(write.updateChksum(0xaaaa, 7, NullStreamError));

    // error: not aligned
    ASSERT_TRUE(write.seek(4, 4));
    EXPECT_FALSE(write.updateChksum(0xaaaa, 0, NullStreamError));
}

TEST(Stream, SerializeBits)
{
    using namespace scion;
    const std::uint64_t pattern = 0x0123'4567'89ab'cdef;

    std::array<std::byte, 8> data;
    std::fill(data.begin(), data.end(), 0xff_b);

    StreamError err;
    for (unsigned int offset = 0; offset < 8; ++offset) {
        for (unsigned bits = 0; bits < 58; ++bits) {
            WriteStream write(data);
            ASSERT_TRUE(write.advanceBits(offset, err));
            ASSERT_TRUE(write.serializeBits(pattern, bits, err))
                << "offset = " << offset << '\n'
                << "bits = " << bits << '\n'
                << "Error: " << err;
            ASSERT_TRUE(err.ok());

            ReadStream read(data);
            std::uint64_t value = 0;
            ASSERT_TRUE(read.seek(0, offset));
            ASSERT_TRUE(read.serializeBits(value, bits, err))
                << "offset = " << offset << '\n'
                << "bits = " << bits << '\n'
                << "Error: " << err;
            ASSERT_TRUE(err.ok());
            ASSERT_EQ(value, (pattern & ((1ull << bits) - 1ull)))
                << "offset = " << offset << '\n'
                << "bits = " << bits << '\n';
        }
    }
}

TYPED_TEST(TypedStreamTest, SerializeBitsInvalidArg)
{
    using namespace scion;
    std::array<std::byte, 4> data = {};
    {
        StreamError err;
        TypeParam stream(data);
        uint32_t value32 = 0;
        ASSERT_FALSE(stream.serializeBits(value32, 33, err));
        ASSERT_FALSE(err.ok());
    }
    {
        StreamError err;
        TypeParam stream(data);
        uint64_t value64 = 0;
        ASSERT_FALSE(stream.serializeBits(value64, 58, err));
        ASSERT_FALSE(err.ok());
    }
}

TYPED_TEST(TypedStreamTest, SerializeBitsOverflow)
{
    using namespace scion;
    uint32_t value = 0;
    std::array<std::byte, 4> data = {};

    for (unsigned int bits = 0; bits < 8; ++bits)
    {
        StreamError err;
        TypeParam stream(data);
        stream.seek(3, 0);
        ASSERT_TRUE(stream.serializeBits(value, bits, err));
        ASSERT_TRUE(err.ok());
    }
}

TYPED_TEST(TypedStreamTest, AdvanceBits)
{
    using namespace scion;

    StreamError err;
    for (unsigned int offset = 0; offset < 64; ++offset) {
        std::array<std::byte, 8> data = {
            0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b, 0xff_b
        };
        TypeParam stream(data);
        ASSERT_TRUE(stream.advanceBits(offset, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_EQ(stream.getPos(), std::make_pair((size_t)(offset / 8), (size_t)(offset % 8)));
        if constexpr (TypeParam::IsWriting) {
            ReadStream read(data);
            std::uint64_t value = 0;
            ASSERT_TRUE(read.serializeUint64(value, NullStreamError));
            ASSERT_EQ(value & ~(~0ull >> offset), 0)
                << "offset = " << offset;
        }
    }
}

TYPED_TEST(TypedStreamTest, AdvanceBytes)
{
    using namespace scion;
    std::array<std::byte, 8> data = {};

    for (unsigned int bitOffset = 0; bitOffset < 8; ++bitOffset) {
        for (unsigned int bytes = 0; bytes < 4; ++bytes) {
            StreamError err;
            TypeParam stream(data);
            ASSERT_TRUE(stream.seek(0, bitOffset));
            ASSERT_TRUE(stream.advanceBytes(bytes, err))
                << "bitOffset = " << bitOffset << '\n'
                << "bytes = " << bytes << '\n'
                << "Error: " << err;
            ASSERT_TRUE(err.ok());
            if (bitOffset > 0 && bytes > 0) {
                ASSERT_FALSE(stream.advanceBytes(8, err));
                ASSERT_FALSE(err.ok());
            }
        }
    }
}

TEST(Stream, SerializeByte)
{
    using namespace scion;
    const std::uint8_t pattern = 0xcc;

    std::array<std::byte, 8> data;
    std::fill(data.begin(), data.end(), 0xff_b);

    StreamError err;
    for (size_t offset = 0; offset < 8; ++offset) {
        WriteStream write(data);
        ASSERT_TRUE(write.advanceBits(offset, err));
        ASSERT_TRUE(write.serializeByte(pattern, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(write.getPos(), std::make_pair((size_t)1, offset));

        ReadStream read(data);
        std::uint8_t value = 0;
        ASSERT_TRUE(read.seek(0, offset));
        ASSERT_TRUE(read.serializeByte(value, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(value, pattern)
            << "offset = " << offset << '\n';
        ASSERT_EQ(read.getPos(), std::make_pair((size_t)1, offset));
    }
}

TEST(Stream, SerializeUint16)
{
    using namespace scion;
    const std::uint16_t pattern = 0xcdef;

    std::array<std::byte, 8> data;
    std::fill(data.begin(), data.end(), 0xff_b);

    StreamError err;
    for (size_t offset = 0; offset < 8; ++offset) {
        WriteStream write(data);
        ASSERT_TRUE(write.advanceBits(offset, err));
        ASSERT_TRUE(write.serializeUint16(pattern, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(write.getPos(), std::make_pair((size_t)2, offset));

        ReadStream read(data);
        std::uint16_t value = 0;
        ASSERT_TRUE(read.seek(0, offset));
        ASSERT_TRUE(read.serializeUint16(value, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(value, pattern)
            << "offset = " << offset << '\n';
        ASSERT_EQ(read.getPos(), std::make_pair((size_t)2, offset));
    }
}

TYPED_TEST(TypedStreamTest, SerializeUint16Overflow)
{
    using namespace scion;
    uint16_t pattern = 0x1234;
    std::array<std::byte, 5> data = {};

    StreamError err;
    TypeParam stream(data);

    ASSERT_TRUE(stream.serializeUint16(pattern, err));
    ASSERT_TRUE(stream.serializeUint16(pattern, err));
    ASSERT_FALSE(stream.serializeUint16(pattern, err));
    ASSERT_FALSE(err.ok());
}

TEST(Stream, SerializeUint32)
{
    using namespace scion;
    const std::uint32_t pattern = 0x1234'5678;

    std::array<std::byte, 8> data;
    std::fill(data.begin(), data.end(), 0xff_b);

    StreamError err;
    for (size_t offset = 0; offset < 8; ++offset) {
        WriteStream write(data);
        ASSERT_TRUE(write.advanceBits(offset, err));
        ASSERT_TRUE(write.serializeUint32(pattern, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(write.getPos(), std::make_pair((size_t)4, offset));

        ReadStream read(data);
        std::uint32_t value = 0;
        ASSERT_TRUE(read.seek(0, offset));
        ASSERT_TRUE(read.serializeUint32(value, err))
            << "offset = " << offset << '\n'
            << "Error: " << err;
        ASSERT_TRUE(err.ok());
        ASSERT_EQ(value, pattern)
            << "offset = " << offset << '\n';
        ASSERT_EQ(read.getPos(), std::make_pair((size_t)4, offset));
    }
}

TYPED_TEST(TypedStreamTest, SerializeUint32Overflow)
{
    using namespace scion;
    uint32_t pattern = 0x1234'5678;
    std::array<std::byte, 9> data = {};

    StreamError err;
    TypeParam stream(data);

    ASSERT_TRUE(stream.serializeUint32(pattern, err));
    ASSERT_TRUE(stream.serializeUint32(pattern, err));
    ASSERT_FALSE(stream.serializeUint32(pattern, err));
    ASSERT_FALSE(err.ok());
}

TEST(Stream, ReadBytes)
{
    using namespace scion;
    std::array<std::byte, 8> data = {1_b, 2_b, 3_b, 4_b, 5_b, 6_b, 7_b, 8_b};
    std::array<std::byte, 4> bytes = {};

    StreamError err;
    ReadStream stream(data);

    ASSERT_TRUE(stream.serializeBytes(bytes, err));
    ASSERT_TRUE(std::equal(data.begin(), data.begin() + 4, bytes.begin()));
    ASSERT_TRUE(stream.serializeBytes(bytes, err));
    ASSERT_TRUE(std::equal(data.begin() + 4, data.end(), bytes.begin()));

    ASSERT_FALSE(stream.serializeBytes(std::span(bytes.begin(), bytes.begin() + 1), err));
    ASSERT_FALSE(err.ok());
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)8, (size_t)0));
}

TEST(Stream, WriteBytes)
{
    using namespace scion;
    std::array<std::byte, 8> data = {};
    std::array<std::byte, 4> bytes = {1_b, 2_b, 3_b, 4_b};

    StreamError err;
    WriteStream stream(data);

    ASSERT_TRUE(stream.serializeBytes(bytes, err));
    ASSERT_TRUE(stream.serializeBytes(bytes, err));
    ASSERT_TRUE(std::equal(bytes.begin(), bytes.end(), data.begin()));
    ASSERT_TRUE(std::equal(bytes.begin(), bytes.end(), data.begin() + 4));

    ASSERT_FALSE(stream.serializeBytes(std::span(bytes.begin(), bytes.begin() + 1), err));
    ASSERT_FALSE(err.ok());
    ASSERT_EQ(stream.getPos(), std::make_pair((size_t)8, (size_t)0));
}

TYPED_TEST(TypedStreamTest, SerializeBytesBitOffset)
{
    using namespace scion;
    std::array<std::byte, 8> data = {};
    std::array<std::byte, 4> bytes = {1_b, 2_b, 3_b, 4_b};

    StreamError err;
    TypeParam stream(data);

    stream.seek(0, 1);
    ASSERT_FALSE(stream.serializeBytes(bytes, err));
    ASSERT_FALSE(err.ok());
}
