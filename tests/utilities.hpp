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

#include "scion/error_codes.hpp"

#include "gtest/gtest.h"

#include <algorithm>
#include <cstddef>
#include <format>
#include <source_location>
#include <span>
#include <string>
#include <system_error>
#include <vector>


template <typename T>
static constexpr testing::AssertionResult hasSucceeded(const scion::Maybe<T>& result)
{
    if (scion::isError(result))
        testing::AssertionFailure() << "operation was expected to succeed";
    else
        return testing::AssertionSuccess();
}

template <typename T>
static constexpr testing::AssertionResult hasFailed(const scion::Maybe<T>& result)
{
    if (scion::isError(result))
        return testing::AssertionSuccess();
    else
        return testing::AssertionFailure() << "operation was expected to fail";
}

template <typename T>
T& unwrap(
    scion::Maybe<T>& result,
    const std::source_location loc = std::source_location::current())
{
    if (!result) {
        throw std::system_error(result.error(), std::format(
            "unexpected error in {}:{}", loc.file_name(), loc.line()));
    } else {
        return *result;
    }
}

template <typename T>
T& unwrap(
    scion::Maybe<T>&& result,
    const std::source_location loc = std::source_location::current())
{
    if (!result) {
        throw std::system_error(result.error(), std::format(
            "unexpected error in {}:{}", loc.file_name(), loc.line()));
    } else {
        return *result;
    }
}

constexpr std::byte operator ""_b(unsigned long long i)
{
    return std::byte{static_cast<unsigned char>(i)};
}

// Set the base path for loadPackets() from the command line or an environment
// variable.
void setTestBasePath(int argc, char* argv[]);

// Load packets from a file formatted as `(<length><packet data>)+` where
// length is a 32 bit field (big endian) giving the size of the following
// packet data in bytes.
std::vector<std::vector<std::byte>> loadPackets(const char* path);

// Format a buffer side-by-side as hexadecimal values and decoded string.
template <std::output_iterator<char> OutIter>
OutIter formatBuffer(OutIter out, std::span<const std::byte> buffer)
{
    constexpr size_t ROW_LENGTH = 16;
    const auto len = buffer.size();

    for (unsigned long i = 0; i < len; i += ROW_LENGTH) {
        if (i != 0) out = std::format_to(out, "\n");
        out = std::format_to(out, "{:04x}  ", i);

        // Hexadecimal bytes
        unsigned long j = 0;
        for (j = 0; j < ROW_LENGTH && (i+j) < len; ++j) {
            if (j != 0) *(out++) = ' ';
            if (j == 8) *(out++) = ' ';
            out = std::format_to(out, "{:02x}", (unsigned char)buffer[i+j]);
        }

        // Fill remaining characters
        for (; j  < ROW_LENGTH; ++j) {
            if (j == 8) *(out++) = ' ';
            out = std::format_to(out, "   ");
        }
        *(out++) = ' ';

        // Decoded text
        for (j = 0; j < ROW_LENGTH && (i+j) < len; ++j) {
            auto c = (unsigned char)buffer[i+j];
            *(out++) = std::isprint(c) ? c: '.';
        }
    }
    return std::format_to(out, "\n");
}

// Format buffer like formatBuffer(). Bytes in `buffer` that differ from `ref`
// are printed in red.
template <std::output_iterator<char> OutIter>
OutIter formatBufferDiff(
    OutIter out, std::span<const std::byte> buffer, std::span<const std::byte> ref)
{
    constexpr size_t ROW_LENGTH = 16;
    const auto len = buffer.size();

    if (len != ref.size()) {
        return std::format_to(out,
            "\033[31mbuffers have different size ({} != {})\033[0m\n", len, ref.size());
    }

    for (unsigned long i = 0; i < len; i += ROW_LENGTH) {
        if (i != 0) out = std::format_to(out, "\n");
        out = std::format_to(out, "{:04x}  ", i);

        // Hexadecimal bytes
        unsigned long j = 0;
        for (j = 0; j < ROW_LENGTH && (i+j) < len; ++j) {
            if (j != 0) *(out++) = ' ';
            if (j == 8) *(out++) = ' ';
            auto b = buffer[i+j];
            if (b == ref[i+j])
                out = std::format_to(out, "{:02x}", (unsigned char)b);
            else
                out = std::format_to(out, "\033[31m{:02x}\033[0m", (unsigned char)b);
        }

        // Fill remaining characters
        for (; j  < ROW_LENGTH; ++j) {
            if (j == 8) *(out++) = ' ';
            out = std::format_to(out, "   ");
        }
        *(out++) = ' ';

        // Decoded text
        for (j = 0; j < ROW_LENGTH && (i+j) < len; ++j) {
            auto c = (unsigned char)buffer[i+j];
            if (c == (unsigned char)ref[i+j])
                *(out++) = std::isprint(c) ? c: '.';
            else
                out = std::format_to(out, "\033[31m{:c}\033[0m", std::isprint(c) ? c: '.');
        }
    }
    return std::format_to(out, "\n");
}

// Returns the result of printBuffer() as string.
inline std::string printBuffer(std::span<const std::byte> buffer)
{
    std::string str;
    str.reserve(1024);
    formatBuffer(std::back_insert_iterator(str), buffer);
    return str;
}

// Returns the result of formatBufferDiff() as string.
inline std::string printBufferDiff(std::span<const std::byte> buffer, std::span<const std::byte> ref)
{
    std::string str;
    str.reserve(2048);
    std::back_insert_iterator out(str);
    out = std::format_to(out, "Buffer:\n");
    out = formatBufferDiff(out, buffer, ref);
    out = std::format_to(out, "Reference:\n");
    out = formatBufferDiff(out, ref, buffer);
    return str;
}

// Returns the string representation of a header.
template <typename T>
std::string printHeader(const T& hdr, int indent = 0)
{
    std::string str;
    str.reserve(1024);
    hdr.print(std::back_insert_iterator(str), indent);
    return str;
}

inline auto truncate(const std::vector<std::byte>& packet, int length)
{
    if (length < 0) {
        length = (int)packet.size() + length;
    }
    return std::span<const std::byte>(packet.data(), std::min(length, (int)packet.size()));
}
