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

#include "scion/addr/endpoint.hpp"

#include <charconv>


namespace scion {
namespace details {

/// \brief Split host and port in an address of the form `<host>:<port>` or
/// `[<host>]:<port>`, where `<host>` is a domain name, an IPv4, IPv6,
/// SCION-IPv4, or SCION-IPv6 address and `<port>` is a numerical TCP/UDP port.
/// The port may be omitted in the form `<host>` or `[<host>]`, in which case
/// the function returns zero for the port.
Maybe<std::pair<std::string_view, std::uint16_t>> splitHostPort(std::string_view text)
{
    std::string_view addr, port;
    std::size_t sep = text.npos;
    if (text.starts_with('[')) {
        sep = text.rfind("]");
        if (sep == text.npos) return Error(ErrorCode::SyntaxError);
        addr = text.substr(1, sep - 1);
        if ((sep + 1) < text.size()) {
            if (text[sep + 1] != ':') return Error(ErrorCode::SyntaxError);
            port = text.substr(sep + 2);
            if (port.empty()) return Error(ErrorCode::SyntaxError);
        }
    } else {
        sep = text.rfind(':');
        addr = text.substr(0, sep);
        if (sep != text.npos) {
            auto comma = addr.find(',');
            if (comma != addr.npos) {
                if (addr.substr(comma).contains(':')) {
                    // SCION-IPv6 without a port
                    addr = text.substr();
                } else {
                    // SCION-IPv4
                    port = text.substr(sep + 1);
                    if (port.empty()) return Error(ErrorCode::SyntaxError);
                }
            } else if (addr.contains(':')) {
                // IPv6 without port
                addr = text.substr();
            } else {
                // host name, IPv4 or IPv4 with port
                port = text.substr(sep + 1);
                if (port.empty()) return Error(ErrorCode::SyntaxError);
            }
        }
    }

    uint16_t portValue = 0;
    if (!port.empty()) {
        const auto begin = port.data();
        const auto end = begin + port.size();
        auto res = std::from_chars(begin, end, portValue, 10);
        if (res.ptr != end)
            return Error(ErrorCode::SyntaxError);
        else if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
            return Error(ErrorCode::SyntaxError);
    }

    return std::make_pair(addr, portValue);
}

} // namespace details
} // namespace scion
