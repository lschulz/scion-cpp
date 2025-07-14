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

#include "scion/addr/isd_asn.hpp"

#include <boost/algorithm/string.hpp>

#include <bit>
#include <charconv>
#include <ostream>


namespace scion {

/////////
// Isd //
/////////

Maybe<Isd> Isd::Parse(std::string_view text)
{
    Isd isd;
    const auto begin = text.data();
    const auto end = begin + text.size();
    auto res = std::from_chars(begin, end, isd.m_isd, 10);
    if (res.ptr != end)
        return Error(ErrorCode::SyntaxError);
    else if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
        return Error(std::make_error_code(res.ec));
    else if (isd.m_isd > Isd::MAX_VALUE)
        return Error(ErrorCode::SyntaxError);
    return isd;
}

std::ostream& operator<<(std::ostream &stream, Isd isd)
{
    stream << std::format("{}", isd);
    return stream;
}

/////////
// Asn //
/////////

Maybe<Asn> Asn::Parse(std::string_view text)
{
    static constexpr std::size_t MAX_GROUP_VALUE = (1ull << 16) - 1;
    std::uint64_t asn = 0;

    // BGP-style ASN
    const auto begin = text.data();
    const auto end = begin + text.size();
    auto res = std::from_chars(begin, end, asn, 10);
    if (res.ptr == end && !(int)res.ec && asn <= MAX_VALUE)
        return Asn(asn);

    // SCION-style ASN
    int i = 0;
    auto finder = boost::algorithm::first_finder(":");
    boost::algorithm::split_iterator<std::string_view::iterator> groupEnd;
    for (auto group = boost::algorithm::make_split_iterator(text, finder); group != groupEnd; ++group, ++i)
    {
        if (i > 2 || group->size() == 0) // too many groups or empty group
            return Error(ErrorCode::SyntaxError);

        std::uint64_t v = 0;
        const auto begin = &group->front();
        const auto end = begin + group->size();
        auto res = std::from_chars(begin, end, v, 16);
        if (res.ptr != end)
            return Error(ErrorCode::SyntaxError);
        else if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
            return Error(std::make_error_code(res.ec));
        else if (v > MAX_GROUP_VALUE)
            return Error(ErrorCode::SyntaxError);

        asn |= (v << (16 * (2 - i)));
    }
    if (i < 2) // too few groups
        return Error(ErrorCode::SyntaxError);

    return Asn(asn);
}

std::ostream& operator<<(std::ostream &stream, Asn asn)
{
    stream << std::format("{}", asn);
    return stream;
}

////////////
// IsdAsn //
////////////

Maybe<IsdAsn> IsdAsn::Parse(std::string_view text)
{
    std::uint64_t ia = 0;

    auto i = text.find('-');
    if (i == text.npos) return Error(ErrorCode::SyntaxError);

    auto isd = Isd::Parse(text.substr(0, i));
    if (isError(isd)) return propagateError(isd);
    ia |= ((std::uint64_t)get(isd) << Asn::BITS);

    auto asn = Asn::Parse(text.substr(i + 1));
    if (isError(asn)) return propagateError(asn);
    ia |= get(asn);

    return IsdAsn(ia);
}

std::ostream& operator<<(std::ostream &stream, IsdAsn ia)
{
    stream << std::format("{}", ia);
    return stream;
}

} // namespace scion
