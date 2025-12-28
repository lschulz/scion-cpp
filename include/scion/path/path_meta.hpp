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

#include "scion/addr/isd_asn.hpp"
#include "scion/details/protobuf_time.hpp"
#include "scion/path/attributes.hpp"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4267)
#endif
#include "scion/proto/daemon/v1/daemon.pb.h"
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <chrono>
#include <cstdint>
#include <iterator>
#include <memory>
#include <ranges>
#include <string>
#include <vector>


namespace scion {
namespace path_meta {

using Interface = std::uint64_t;
using Duration = std::chrono::nanoseconds;

enum class LinkType
{
    Unspecified = 0, ///< Link type not specified
    Direct,          ///< Direct physical connection
    MultiHop,        ///< Connected with local routing/switching
    OpenNet,         ///< Connection overlayed over the public Internet
    Internal = 255,  ///< AS internal link (SCION does not provide link type for internal links)
};

struct GeoCoordinates
{
    float latitude;
    float longitude;
    std::string address;

    bool operator==(const GeoCoordinates&) const = default;
};

struct Hop
{
    IsdAsn isdAsn;
    Interface ingress, egress;

    bool operator==(const Hop&) const = default;
};

struct HopMeta
{
    GeoCoordinates ingRouter, egrRouter;
    std::uint32_t internalHops;
    std::string notes;

    bool operator==(const HopMeta&) const = default;
};

struct LinkMeta
{
    LinkType type;
    Duration latency;
    std::uint64_t bandwidth;

    bool operator==(const LinkMeta&) const = default;
};

namespace details {
inline LinkType linkTypeFromProtobuf(int type)
{
    using namespace proto::daemon::v1;
    switch (type) {
    default:
    case LINK_TYPE_UNSPECIFIED:
        return LinkType::Unspecified;
    case LINK_TYPE_DIRECT:
        return LinkType::Direct;
    case LINK_TYPE_MULTI_HOP:
        return LinkType::MultiHop;
    case LINK_TYPE_OPEN_NET:
        return LinkType::OpenNet;
    }
}
} // namespace details

/// \brief Path Metadata: List of ISD-ASN and interface IDs belonging to each
/// SCION hop.
class Interfaces : public PathAttributeBase
{
public:
    std::vector<Hop> data;
    Interfaces() = default;
    explicit Interfaces(std::vector<Hop>&& data) : data(std::move(data)) {};
    void initialize(const proto::daemon::v1::Path& pb);
};

/// \brief Path Metadata: Geolocation information, number of internal hops, and
/// free-form notes for each SCION hop.
class HopMetadata : public PathAttributeBase
{
public:
    std::vector<HopMeta> data;
    HopMetadata() = default;
    explicit HopMetadata(std::vector<HopMeta>&& data) : data(std::move(data)) {};
    void initialize(const proto::daemon::v1::Path& pb);
};

/// \brief Path Metadata: Link type, base latency and link capacity.
class LinkMetadata : public PathAttributeBase
{
public:
    std::vector<LinkMeta> data;
    LinkMetadata() = default;
    explicit LinkMetadata(std::vector<LinkMeta>&& data) : data(std::move(data)) {};
    void initialize(const proto::daemon::v1::Path& pb);
};

} // namespace path_meta
} // namespace scion

template <>
struct std::formatter<scion::path_meta::Interfaces>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::path_meta::Interfaces& hops, auto& ctx) const
    {
        using namespace scion::path_meta;
        if (hops.data.empty()) std::format_to(ctx.out(), "empty");

        auto out = std::format_to(ctx.out(), "{} {}",
            hops.data.front().isdAsn, hops.data.front().egress);
        std::size_t n = hops.data.size() - 1;
        for (std::size_t i = 1; i < n; ++i) {
            out = std::format_to(ctx.out(), ">{} {} {}",
                hops.data[i].ingress, hops.data[i].isdAsn, hops.data[i].egress);
        }
        return std::format_to(ctx.out(), ">{} {}",
            hops.data.back().ingress, hops.data.back().isdAsn);
    }
};
