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

#include "format.hpp"


std::ostream& printEscapedString(std::ostream& stream, std::span<const std::byte> buffer)
{
    auto flags = stream.flags(std::ios::hex);
    auto fill = stream.fill('0');

    auto size = buffer.size();
    for (size_t i = 0; i < size; ++i) {
        char c = (unsigned char)buffer[i];
        if (std::isprint(c)) {
            stream << c;
        } else {
            if (c == '\0')
                stream << "\\0";
            else if (c == '\n')
                stream << "\\n";
            else
                stream << "\\x" << std::setw(2) << +static_cast<unsigned char>(c);
        }
    }

    stream.setf(flags);
    stream.fill(fill);
    return stream;
}
