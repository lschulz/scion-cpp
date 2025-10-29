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

#include "scion/addr/generic_ip.hpp"
#include "scion/addr/isd_asn.hpp"
#include "scion/as_interface.hpp"
#include "scion/details/protobuf_time.hpp"
#include "scion/hdr/scion.hpp"
#include "scion/path/attributes.hpp"
#include "scion/path/digest.hpp"
#include "scion/path/path_meta.hpp"
#include "scion/path/raw_hop_range.hpp"
#include "scion/path/raw.hpp"

#include <boost/smart_ptr/intrusive_ptr.hpp>
#include <boost/smart_ptr/intrusive_ref_counter.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <list>
#include <vector>


namespace scion {
namespace details {
PathDigest computeDigest(IsdAsn src, std::span<std::pair<std::uint16_t, std::uint16_t>> path);
} // namespace details

/// \brief Generic path with underlay routing information and optional metadata.
class Path : public boost::intrusive_ref_counter<Path>
{
public:
    using Expiry = std::chrono::utc_clock::time_point;

private:
    struct Attribute
    {
        int key;
        std::unique_ptr<PathAttributeBase> data;
    };

    IsdAsn m_source, m_destination;
    hdr::PathType m_type = hdr::PathType::Empty;
    Expiry m_expires_by;
    std::uint16_t m_mtu = 0;
    std::uint32_t m_hopCount = 0;
    generic::IPEndpoint m_nextHop;
    std::vector<std::byte> m_path;
    std::list<Attribute> m_attrib;
    std::atomic<std::uint64_t> m_broken = 0;
    PathDigest m_digest;

public:
    Path() = default;
    Path(IsdAsn source, IsdAsn destination,
        hdr::PathType type,
        Expiry expiry,
        std::uint16_t mtu,
        const generic::IPEndpoint& nh,
        std::span<const std::byte> dpPath);

    bool operator==(const Path& other) const
    {
        return m_source == other.m_source && m_destination == other.m_destination
            && m_type == other.m_type && m_expires_by == other.m_expires_by
            && m_nextHop == other.m_nextHop
            && std::ranges::equal(m_path, other.m_path);
    }

    /// \brief Returns the first AS on the path (the source).
    IsdAsn firstAS() const { return m_source; }

    /// \brief Returns the last AS on the path (the destination).
    IsdAsn lastAS() const { return m_destination; }

    /// \brief Returns the path type.
    hdr::PathType type() const { return m_type; }

    /// \brief Returns the expiry time of the path.
    Expiry expiry() const { return m_expires_by; }

    /// \brief Return the path MTU provided by the control plane.
    std::uint16_t mtu() const { return m_mtu; }

    /// \brief Returns true is the path is an empty path for AS-internal
    /// communication.
    bool empty() const { return m_type == hdr::PathType::Empty; }

    /// \brief Returns the encoded path length in bytes.
    std::size_t size() const { return m_path.size(); }

    /// \brief Returns the timestamp of the last time this path was marked as
    /// broken. Returns zero if the path is considered working. A non-zero
    /// timestamp is the number of nanoseconds since the epoch of
    /// `std::chrono::steady_clock`.
    std::uint64_t broken() const { return m_broken.load(); }

    /// \brief Mark the path as working or as broken. This method can be called
    /// from multiple threads without synchronization.
    /// \param ts Pass zero to mark the path as working. Pass the time when the
    /// path was last discovered to be broken to mark the path as broken. The
    /// timestamp is interpreted as nanoseconds since the epoch of
    /// `std::chrono::steady_clock`.
    void setBroken(std::uint64_t ts) { m_broken.store(ts); }

    /// \brief Returns the length of the path in inter-AS hops (i.e., the number
    /// of visited ASes - 1). This value is derived from the raw data plane path
    /// and does not necessarily match the hop count given by metadata.
    std::uint32_t hopCount() const { return m_hopCount; }

    /// \copydoc RawPath::hops()
    auto hops() const
    {
        return RawHopRange<Path>(*this);
    }

    /// \brief Returns the path digest.
    PathDigest digest() const { return m_digest; }

    /// \brief Returns the underlay address of the next router.
    const generic::IPEndpoint& nextHop() const { return m_nextHop; }

    /// \brief Returns the underlay address of the next router or `dst` if the
    /// path is empty, as packets with empty paths are send to the underlay
    /// address of the recipent directly.
    const generic::IPEndpoint& nextHop(const generic::IPEndpoint& dst) const
    {
        if (m_type == hdr::PathType::Empty)
            return dst;
        else
            return m_nextHop;
    }

    /// \brief Returns the path encoded for use in the data plane.
    std::span<const std::byte> encoded() const { return m_path; }

    /// \brief Add a new attribute with the given key. If the attribute already
    /// exists, a pointer to the existing attribute is returned.
    /// Not thread-safe.
    /// \return A non-null pointer.
    template <typename T>
    T* addAttribute(int key)
    {
        auto ptr = getAttribute<T>(key);
        if (ptr) return ptr;
        auto& attrib = m_attrib.emplace_back(key, std::make_unique<T>());
        return dynamic_cast<T*>(attrib.data.get());
    }

    /// \brief Returns a pointer to the attribute with the given key or nullptr
    /// if no such attribute exists.
    template <typename T>
    T* getAttribute(int key)
    {
        auto i = std::ranges::find_if(m_attrib, [=] (const Attribute& a) {
            return a.key == key;
        });
        if (i == m_attrib.end()) return nullptr;
        return dynamic_cast<T*>(i->data.get());
    }

    /// \brief Returns a pointer to the attribute with the given key or nullptr
    /// if no such attribute exists.
    template <typename T>
    const T* getAttribute(int key) const
    {
        auto i = std::ranges::find_if(m_attrib, [=] (const Attribute& a) {
            return a.key == key;
        });
        if (i == m_attrib.end()) return nullptr;
        return dynamic_cast<const T*>(i->data.get());
    }

    /// \brief Remove a path attribute. Attempting to remove an attribute that
    /// does not exist has no effect. Not thread-safe.
    void removeAttribute(int key)
    {
        m_attrib.remove_if([=] (const Attribute& a) {
            return a.key == key;
        });
    }

    /// \brief Check in path metadata whether the path contains the given
    /// interface.
    bool containsInterface(IsdAsn isdAsn, AsInterface iface) const
    {
        auto hops = getAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
        if (!hops) return false;
        for (const auto& hop : hops->data) {
            if (hop.isdAsn == isdAsn && (hop.ingress == iface || hop.egress == iface)) {
                return true;
            }
        }
        return false;
    }

    /// \brief Check in path metadata whether the path contains the given hop.
    bool containsHop(IsdAsn isdAsn, AsInterface igr, AsInterface egr) const
    {
        auto hops = getAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES);
        if (!hops) return false;
        for (const auto& hop : hops->data) {
            if (hop.isdAsn == isdAsn && hop.ingress == igr && hop.egress == egr) {
                return true;
            }
        }
        return false;
    }

    friend std::ostream& operator<<(std::ostream& stream, const Path& path);
};

inline Path::Path(IsdAsn source, IsdAsn destination,
    hdr::PathType type,
    Expiry expiry,
    std::uint16_t mtu,
    const generic::IPEndpoint& nh,
    std::span<const std::byte> dpPath)
    : m_source(source), m_destination(destination)
    , m_type(type)
    , m_expires_by(expiry)
    , m_mtu(mtu)
    , m_nextHop(nh)
    , m_path(dpPath.begin(), dpPath.end())
{
    // Determine hop count by decoding the raw path
    m_hopCount = (std::uint32_t)std::ranges::distance(hops());

    // Compute the path digest
    std::array<std::pair<std::uint16_t, std::uint16_t>, 64> buffer;
    std::size_t i = 0;
    for (auto hop : hops()) {
        if (i >= buffer.size()) break;
        buffer[i++] = hop;
    }
    m_digest = details::computeDigest(m_source, buffer);
}

using PathPtr = boost::intrusive_ptr<Path>;

/// \brief Helper for creating a path on the heap.
inline PathPtr makePath(IsdAsn source, IsdAsn destination,
    hdr::PathType type,
    Path::Expiry expiry,
    std::uint16_t mtu,
    const generic::IPEndpoint& nh,
    std::span<const std::byte> dpPath)
{
    return PathPtr(new Path(source, destination, type, expiry, mtu, nh, dpPath));
}

/// \brief Make path from a raw path.
inline PathPtr makePath(const RawPath& rp, const generic::IPEndpoint& nh)
{
    return makePath(rp.firstAS(), rp.lastAS(), rp.type(), rp.expiry(), 0, nh, rp.encoded());
}

/// \brief Helper for creating an empty path on the heap.
inline PathPtr makeEmptyPath(IsdAsn isdAsn)
{
    return PathPtr(new Path(isdAsn, isdAsn, hdr::PathType::Empty,
        Path::Expiry::max(), 0, generic::IPEndpoint(), std::span<std::byte>()));
}

} // namespace scion

template <>
struct std::formatter<scion::Path>
{
    constexpr auto parse(auto& ctx)
    {
        return ctx.begin();
    }

    auto format(const scion::Path& path, auto& ctx) const
    {
        using namespace scion;
        if (path.empty()) return std::format_to(ctx.out(), "empty {}", path.firstAS());
        if (auto hops = path.getAttribute<path_meta::Interfaces>(PATH_ATTRIBUTE_INTERFACES); hops) {
            return std::format_to(ctx.out(), "{}", *hops);
        } else {
            auto out = std::format_to(ctx.out(), "{} ", path.firstAS());
            for (auto [egr, igr] : path.hops()) {
                out = std::format_to(out, "{}>{} ", egr, igr);
            }
            return std::format_to(out, "{}", path.lastAS());
        }
    }
};

template <>
struct std::hash<scion::Path>
{
    std::size_t operator()(const scion::Path& rp) const noexcept
    {
        return std::hash<scion::PathDigest>{}(rp.digest());
    }
};
