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

#include "scion/addr/address.hpp"
#include "scion/addr/isd_asn.hpp"
#include "scion/details/debug.hpp"
#include "scion/path/path.hpp"
#include "scion/scmp/handler.hpp"

#include <chrono>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>


namespace scion {

/// \brief PathMtuDiscoverer stores the Path MTUs (PMTU) for a set of
/// destinations and SCION paths in an LRU cache. It is intended to support
/// implementations of RFC1981-style Path MTU discovery for SCION. The Path MTUs
/// are initially taken from the control place supplied values. If an SCMP
/// message indicating a packet that a packet was too big is received, the Path
/// MTU is updated.
///
/// \details In order to use the class it must be registered as SCMP handler in
/// all sockets for which the Path MTU should be stored. Before sending a
/// packet, the latest known PMTU can be retrieved with getMtu(). In order to
/// calculate the maximum payload size, the size of the SCION header, path,
/// extension headers, and L4 headers must be subtracted from the PMTU.
///
/// Example:
///     UdpSocket s;
///     PathMtuDiscoverer pmtu;
///     s.setNextScmpHandler(&pmtu);
///     size_t mtu = pmtu.getMtu(dest, path);
///     size_t hdrSize = s.measure(path).value();
///     size_t maxPayloadSize = mtu > hdrSize ? mtu - hdrSize : 0;
///
/// Stream-oriented sockets keep track of the Path MTU internally and usually
/// don't need this class.
template <
    typename Timestamp = std::chrono::steady_clock::time_point,
    typename Alloc = std::allocator<std::byte>>
class PathMtuDiscoverer : public ScmpHandlerImpl
{
private:
    struct Destination
    {
        ScIPAddress address;
        PathDigest path;
        bool operator==(const Destination& other) const = default;
    };

    struct HashDest
    {
        std::size_t operator()(const Destination& dest) const noexcept
        {
            return std::hash<ScIPAddress>{}(dest.address) ^ std::hash<PathDigest>{}(dest.path);
        }
    };

    struct MtuRecord
    {
        Timestamp lastAccess;
        std::uint16_t mtu;
    };

    // The LRU cache implemented as a std::list that has the most recently
    // accessed elements at its back and the least recently accessed at the
    // front. A std::unordered_map provides fast access using the `Destination`
    // as key. The last access time is stored for use with clear().

    using ListAlloc = typename std::allocator_traits<Alloc>::template rebind_alloc<
        std::pair<const Destination, MtuRecord>>;
    using List = std::list<std::pair<const Destination, MtuRecord>, ListAlloc>;

    using IndexAlloc = typename std::allocator_traits<Alloc>::template rebind_alloc<
        std::pair<const Destination, typename List::iterator>>;
    using Index = std::unordered_map<
        Destination, typename List::iterator, HashDest, std::equal_to<Destination>, IndexAlloc>;

    mutable std::mutex m_mutex;
    std::uint16_t m_maximumMtu;
    std::size_t m_capacity;
    List m_mtu;
    Index m_index;

public:
    /// \param firstHopMtu Local AS internal MTU. Path MTUs can never be larger
    /// than this value. Usually this is to the MTU of the local AS obtained
    /// from the SCION daemon, or to the link MTU of the interface used to
    /// communicate with SCION border routers. If neither is known, a safe
    /// choice is the minimum MTU for the underlay protocol (576 bytes in IPv4,
    /// 1280 bytes in IPv6).
    /// \param capacity Capacity of the LRU cache.
    PathMtuDiscoverer(std::uint16_t firstHopMtu = 65500, std::size_t capacity = 32768)
        : m_maximumMtu(firstHopMtu), m_capacity(std::max<std::size_t>(1, capacity))
    {}

    /// \brief Set the MTU of the local AS. This MTU is used as the default
    /// starting value for MTU discovery.
    void setFirstHopMtu(std::uint16_t firstHopMtu)
    {
        std::lock_guard lock(m_mutex);
        m_maximumMtu = firstHopMtu;
    }

    /// \brief Returns the current size.
    std::size_t size() const
    {
        std::lock_guard lock(m_mutex);
        return m_mtu.size();
    }

    /// \brief Returns the maximum size.
    std::size_t capacity() const
    {
        std::lock_guard lock(m_mutex);
        return m_capacity;
    }

    /// \brief Change the LRU cache capacity. If the new capacity is smaller
    /// than the current size, the least recently accessed MTU records are
    /// removed.
    /// \return The number of removed records.
    std::size_t setCapacity(std::size_t capacity)
    {
        std::lock_guard lock(m_mutex);
        m_capacity = std::max<std::size_t>(1, capacity);
        if (m_capacity < m_mtu.size()) {
            auto remove = m_mtu.size() - m_capacity;
            auto iter = m_mtu.begin();
            for (auto i = remove; i--;) {
                m_index.erase(iter->first);
                iter++;
            }
            m_mtu.erase(m_mtu.begin(), iter);
            return remove;
        }
        return 0;
    }

    /// \brief Returns the Path MTU for the given destination host and SCION
    /// path.
    /// \param t A monotonically increasing timestamp that is stored as the last
    /// access time of the MTU record.
    template <typename Path>
    std::uint16_t getMtu(const generic::IPAddress& dest, const Path& path, Timestamp t = Timestamp())
    {
        std::lock_guard lock(m_mutex);
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        if (auto mtu = get(d, t); mtu.has_value()) {
            return *mtu;
        } else {
            insert(d, m_maximumMtu, t);
            return m_maximumMtu;
        }
    }

    /// \brief Returns the Path MTU for the given destination host and SCION
    /// path.
    /// \param t A monotonically increasing timestamp that is stored as the last
    /// access time of the MTU record.
    std::uint16_t getMtu(const generic::IPAddress& dest, const Path& path, Timestamp t = Timestamp())
    {
        std::lock_guard lock(m_mutex);
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        if (auto cachedMtu = get(d, t); cachedMtu.has_value()) {
            return *cachedMtu;
        } else {
            std::uint16_t mtu = path.mtu();
            if (mtu == 0) { // mtu is 0 if no path metadata is available
                mtu = m_maximumMtu;
            }
            insert(d, mtu, t);
            return mtu;
        }
    }

    /// \brief Update a known Path MTU with a new lower value.
    /// \return Returns true if the PMTU was successfully updated. False is
    /// returned if the new MTU value is greater than the last known value.
    template <typename Path>
    bool updateMtu(const generic::IPAddress& dest, const Path& path, std::uint16_t mtu)
    {
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        return updateMtu(d, mtu);
    }

    /// \brief Remove a Path MTU record.
    /// \return The number of removed records (0 or 1).
    template <typename Path>
    std::size_t forgetMtu(const generic::IPAddress& dest, const Path& path)
    {
        std::lock_guard lock(m_mutex);
        Destination d{ScIPAddress{path.lastAS(), dest}, path.digest()};
        return erase(d);
    }

    /// \brief Remove all records that have not been accessed since `cutoff`.
    /// \return The number of removed records.
    std::size_t clear(Timestamp cutoff)
    {
        std::lock_guard lock(m_mutex);
        std::size_t count = 0;
        auto iter = m_mtu.begin();
        auto end = m_mtu.end();
        for (; iter != end && iter->second.lastAccess < cutoff; ++iter, ++count)
            m_index.erase(iter->first);
        m_mtu.erase(m_mtu.begin(), iter);
        return count;
    }

    /// \brief Remove all MTU records.
    void clear()
    {
        std::lock_guard lock(m_mutex);
        m_mtu.clear();
        m_index.clear();
    }

    bool handleScmpCallback(
        const ScIPAddress& from,
        const RawPath& path,
        const hdr::ScmpMessage& msg,
        std::span<const std::byte> payload) override
    {
        if (auto v = std::get_if<hdr::ScmpPacketTooBig>(&msg)) {
            if (auto dest = parseScmpPacketQuote(payload); dest) {
                updateMtu(*dest, v->mtu);
            }
        } else if (auto v = std::get_if<hdr::ScmpParamProblem>(&msg)) {
            if (v->code == hdr::ScmpParamProblem::Code::InvalidSize) {
                if (auto dest = parseScmpPacketQuote(payload); dest) {
                    // The Go border router never responds with PacketTooBig,
                    // but consistently returns ParameterProblem errors when the
                    // MTU approaches 9000 bytes, 8000 seems like a safe choice
                    // in this case.
                    updateMtu(*dest, 8000);
                }
            }
        }
        return true; // give other handlers a chance to handle PacketTooBig as well
    }

private:
    // Get MTU record and update last access time if it exists.
    std::optional<std::uint16_t> get(const Destination& dest, Timestamp t)
    {
        if (auto iter = m_index.find(dest); iter != m_index.end()) {
            iter->second->second.lastAccess = t;
            m_mtu.splice(m_mtu.end(), m_mtu, iter->second);
            return iter->second->second.mtu;
        }
        return std::nullopt;
    }

    // Unconditionally insert a new MTU record.
    void insert(const Destination& dest, std::uint16_t mtu, Timestamp t)
    {
        if (m_mtu.size() >= m_capacity) {
            m_index.erase(m_mtu.front().first);
            m_mtu.pop_front();
        }
        m_mtu.emplace_back(std::piecewise_construct,
            std::forward_as_tuple(dest),
            std::forward_as_tuple(t, mtu));
        m_index[dest] = std::prev(m_mtu.end());
    }

    std::size_t erase(const Destination& dest)
    {
        if (auto iter = m_index.find(dest); iter != m_index.end()) {
            m_mtu.erase(iter->second);
            m_index.erase(iter);
            return 1;
        }
        return 0;
    }

    // Update or an existing MTU record without changing the lastAccess time.
    // The MTU is only updated if the new MTU is lower than the one stored.
    bool updateMtu(const Destination& dest, std::uint16_t mtu)
    {
        std::lock_guard lock(m_mutex);
        if (auto iter = m_index.find(dest); iter != m_index.end()) {
            if (iter->second->second.mtu >= mtu) {
                iter->second->second.mtu = mtu;
                return true;
            }
        }
        return false;
    }

    std::optional<Destination> parseScmpPacketQuote(std::span<const std::byte> pktQuote)
    {
        ReadStream rs(pktQuote);
        SCION_STREAM_ERROR err;
        hdr::SCION sci;
        if (!sci.serialize(rs, err)) {
            SCION_DEBUG_PRINT("Error parsing SCMP packet quote:\n" << err);
            return std::nullopt;
        }
        std::span<const std::byte> path;
        if (!rs.lookahead(path, sci.pathSize(), err)) {
            SCION_DEBUG_PRINT("Error parsing SCMP packet quote:\n" << err);
            return std::nullopt;
        }
        RawPath rp(sci.src.isdAsn(), sci.dst.isdAsn(), sci.ptype, path);
        return Destination{sci.dst, rp.digest()};
    }
};

} // namespace scion
