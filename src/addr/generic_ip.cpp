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

#include "scion/addr/generic_ip.hpp"
#include "scion/details/bit.hpp"

#include <boost/algorithm/string.hpp>

#if _WIN32
#include <Winsock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>
#else
#include <net/if.h>
#endif

#include <list>
#include <mutex>
#include <ostream>

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;


namespace scion {

namespace details {
Maybe<std::pair<std::string_view, std::uint16_t>> splitHostPort(std::string_view text);
}

namespace generic {

///////////////
// IPAddress //
///////////////

const IPAddress::AddrInfo IPAddress::IPv4 = {
    IPAddress::AddrType::IPv4,
    ""
};

const IPAddress::AddrInfo IPAddress::IPv6NoZone = {
    IPAddress::AddrType::IPv6,
    ""
};

struct DynamicAddrInfo
    : public IPAddress::AddrInfo
    , public boost::intrusive_ref_counter<DynamicAddrInfo>
{
private:
    // global registry of IPv6 zone identifiers
    inline static std::list<DynamicAddrInfo*> registry;
    inline static std::mutex mutex;

    DynamicAddrInfo(IPAddress::AddrType type, std::string_view zone)
        : AddrInfo(type, zone)
    {
        registry.push_back(this);
    }

public:
    ~DynamicAddrInfo() override
    {
        std::lock_guard<std::mutex> lock(mutex);
        registry.remove(this);
    }

    static boost::intrusive_ptr<const IPAddress::AddrInfo> Make(std::string_view zone)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto i = std::find_if(registry.begin(), registry.end(), [&](const AddrInfo* info) {
            return info->zone == zone;
        });
        if (i != registry.end()) {
            return *i;
        } else {
            return new DynamicAddrInfo(IPAddress::AddrType::IPv6, zone);
        }
    }

    void addRef() const noexcept override { boost::sp_adl_block::intrusive_ptr_add_ref(this); }
    void release() const noexcept override { boost::sp_adl_block::intrusive_ptr_release(this); }
};

boost::intrusive_ptr<const IPAddress::AddrInfo>
IPAddress::makeIPv6Zone(std::string_view zone)
{
    if (zone.empty()) {
        return &IPAddress::IPv6NoZone;
    } else {
        return DynamicAddrInfo::Make(zone);
    }
}

unsigned int IPAddress::zoneId() const
{
    char name[IF_NAMESIZE] = {};
    auto zone = m_addrInfo->zone;
    if (zone.empty()) return 0;
    zone = zone.substr(0, std::min(zone.size(), (std::size_t)IF_NAMESIZE)-1);
    std::ranges::copy(zone, name);
    return if_nametoindex(name);
}

static Maybe<uint32_t> parseIPv4(std::string_view text) noexcept
{
    uint32_t addr = 0;
    int i = 0;
    auto finder = boost::algorithm::first_finder(".");
    boost::algorithm::split_iterator<std::string_view::iterator> end;
    for (auto group = boost::algorithm::make_split_iterator(text, finder); group != end; ++group, ++i)
    {
        if (i > 3 || group->size() == 0) // too many dots
            return Error(ErrorCode::SyntaxError);

        uint8_t byte = 0;
        const auto begin = &group->front();
        const auto end = begin + group->size();
        auto res = std::from_chars(begin, end, byte, 10);
        if (res.ptr != end)
            return Error(ErrorCode::SyntaxError);
        else if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
            return Error(ErrorCode::SyntaxError);

        addr |= byte << (8*(3-i));
    }
    if (i < 4) return Error(ErrorCode::SyntaxError); // too few dots
    return addr;
}

Maybe<IPAddress> IPAddress::Parse(std::string_view text, bool noZone) noexcept
{
    if (text.empty()) return Error(ErrorCode::SyntaxError);

    std::array<uint16_t, 8> addr = {};
    std::string_view zone;
    auto zoneSep = text.find('%');
    if (zoneSep != text.npos) {
        if (noZone) return Error(ErrorCode::RequiresZone);
        zone = text.substr(zoneSep + 1);
        if (zone.empty()) return Error(ErrorCode::SyntaxError);
        text = text.substr(0, zoneSep);
    }

    int i = 0;
    int collapsedGroup = -1;
    auto finder = boost::algorithm::first_finder(":");
    boost::algorithm::split_iterator<std::string_view::iterator> end;
    for (auto group = boost::algorithm::make_split_iterator(text, finder); group != end; ++group, ++i)
    {
        if (i > 7) // too many groups
            return Error(ErrorCode::SyntaxError);

        if (group->size() == 0) {
            if (collapsedGroup >= 0) {
                if (collapsedGroup == 0 && (i == 1 || i == 2)) {
                    // allow "::x" and "::"
                } else if (collapsedGroup == 1 && i == 2) {
                    // allow "x::"
                } else {
                    // more than one collapsed group
                    return Error(ErrorCode::SyntaxError);
                }
            }
            collapsedGroup = i;
            addr[i] = 0;
            continue;
        }

        if (group->size() > 4) {
            if (i == 0) {
                // Might be an IPv4 address
                if (!zone.empty()) // IPv4 can't have a zone identifier
                    return Error(ErrorCode::SyntaxError);
                auto ipv4 = parseIPv4(text);
                if (isError(ipv4)) return propagateError(ipv4);
                return MakeIPv4(get(ipv4));
            } else {
                // Might be an IPv6 with an embedded IPv4
                auto ipv4 = parseIPv4(std::string_view(group->begin(), group->end()));
                if (isError(ipv4)) return Error(ErrorCode::SyntaxError);
                addr[i++] = details::byteswapBE((uint16_t)((get(ipv4) >> 16) & 0xffff));
                addr[i++] = details::byteswapBE((uint16_t)((get(ipv4) & 0xffff)));
                if (group->end() != text.end()) // must be the last group
                    return Error(ErrorCode::SyntaxError);
                break;
            }
        }

        uint16_t field = 0;
        const auto begin = &group->front();
        const auto end = begin + group->size();
        auto res = std::from_chars(begin, end, field, 16);
        if (res.ptr != end)
            return Error(ErrorCode::SyntaxError);
        else if (res.ec == std::errc::invalid_argument || res.ec == std::errc::result_out_of_range)
            return Error(ErrorCode::SyntaxError);

        addr[i] = details::byteswapBE(field);
    }
    if (i < 8) {
        if (collapsedGroup >= 0) {
            // Calculate how many extra zero fields to insert. One or two zero
            // fields may already be in the array at this point. Here we just
            // insert the remaining ones.
            int expandZeros = 8 - i;
            int collapsedEnd = collapsedGroup + expandZeros;
            for (int j = 7; j > collapsedEnd; --j) {
                int k = j - expandZeros;
                assert(j >= 0 && j < (int)addr.size());
                assert(k >= 0 && k < (int)addr.size());
                addr[j] = addr[k];
            }
            for (int j = collapsedGroup + 1; j < collapsedGroup + expandZeros + 1; ++j) {
                assert(j >= 0 && j < (int)addr.size());
                addr[j] = 0;
            }
        } else {
            return Error(ErrorCode::SyntaxError);
        }
    }
    return MakeIPv6(std::as_bytes(std::span<const uint16_t, 8>(addr)), zone);
}

std::ostream& operator<<(std::ostream& stream, const IPAddress& addr)
{
    stream << std::format("{}", addr);
    return stream;
}

static std::format_context::iterator formatIPv4(std::format_context::iterator out, uint64_t lo)
{
    return std::format_to(out, "{}.{}.{}.{}",
        ((lo >> 24) & 0xff),
        ((lo >> 16) & 0xff),
        ((lo >> 8) & 0xff),
        (lo & 0xff));
}

static std::pair<int, int> findLongestZeroGroup(std::span<std::byte, 16> addr, int length)
{
    int longestBegin = 0;
    int longestEnd = 0;
    int longestGroup = 2; // ignore groups that span only one field
    int groupBegin = -1;
    for (int i = 0; i < length; i += 2) {
        if (addr[i] == std::byte{0} && addr[i + 1] == std::byte{0}) {
            if (groupBegin < 0) groupBegin = i;
        } else if (groupBegin >= 0) {
            if (i - groupBegin > longestGroup) {
                longestBegin = groupBegin;
                longestEnd = i;
                longestGroup = (i - groupBegin);
            }
            groupBegin = -1;
        }
    }
    if ((groupBegin >= 0) && (length - groupBegin > longestGroup)) {
        longestBegin = groupBegin;
        longestEnd = length;
    }
    return std::make_pair(longestBegin, longestEnd);
}

std::format_context::iterator IPAddress::formatTo(
    std::format_context::iterator out, bool longForm, bool upperCase) const
{
    if (is4()) {
        return formatIPv4(out, m_lo);
    }

    std::byte addr[16];
    toBytes16(addr);

    int length = 16;
    if (is4in6() || isScion4()) length = 12; // skip last four bytes

    int first = 0, last = 0;
    if (!longForm) std::tie(first, last) = findLongestZeroGroup(addr, length);
    for (int i = 0; i < first; i += 2) {
        if (i != 0) (out++) = ':';
        if (upperCase)
            out = std::format_to(out, "{:X}", (uint16_t(addr[i]) << 8) | uint16_t(addr[i+1]));
        else
            out = std::format_to(out, "{:x}", (uint16_t(addr[i]) << 8) | uint16_t(addr[i+1]));
    }
    if (last > first) (out++) = ':';
    for (int i = last; i < length; i += 2) {
        if (i != 0) (out++) = ':';
        if (upperCase)
            out = std::format_to(out, "{:X}", (uint16_t(addr[i]) << 8) | uint16_t(addr[i+1]));
        else
            out = std::format_to(out, "{:x}", (uint16_t(addr[i]) << 8) | uint16_t(addr[i+1]));
    }
    if (last == length) (out++) = ':';

    if (length == 12) {
        (out++) = ':';
        out = formatIPv4(out, m_lo);
    }

    if (!zone().empty()) {
        return std::format_to(out, "%{}", zone());
    }
    return out;
}

////////////////
// IPEndpoint //
////////////////

Maybe<IPEndpoint> IPEndpoint::Parse(std::string_view text, bool noZone) noexcept
{
    auto split = details::splitHostPort(text);
    if (isError(split)) return propagateError(split);
    auto [host, port] = *split;

    auto ip = IPAddress::Parse(host, noZone);
    if (isError(ip)) return propagateError(ip);

    return IPEndpoint(get(ip), port);
}

std::ostream& operator<<(std::ostream& stream, const IPEndpoint& ep)
{
    stream << std::format("{}", ep);
    return stream;
}

} // namespace generic
} // namespace scion
