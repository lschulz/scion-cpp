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

#include <scion/path/path.hpp>

#include <cstdint>
#include <format>
#include <span>
#include <string>


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
            out = std::format_to(out, " ..");
        }
        *(out++) = ' ';

        // Decoded text
        for (j = 0; j < ROW_LENGTH && (i+j) < len; ++j) {
            auto c = (char)buffer[i+j];
            *(out++) = std::isprint(c) ? c: '.';
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

// Print a buffer as string with escape sequences for unprintable characters.
std::ostream& printEscapedString(std::ostream& stream, std::span<const std::byte> buffer);
